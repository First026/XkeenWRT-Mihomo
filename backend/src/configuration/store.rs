use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path},
};
use yaml_rust2::parser::{Event, Parser};

pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;
const MAX_PROFILES: usize = 128;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const FREE_RESERVE_BYTES: u64 = 32 * 1024 * 1024;
const HEADER: &str = "# xkeenwrt-revision: ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidId,
    InvalidYaml,
    TooLarge,
    NotFound,
    Conflict,
    Busy,
    LimitReached,
    InsufficientSpace,
    UnsafePath,
    Storage,
    CommitUncertain,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub revision: String,
    pub source: String,
}

/// The held directory descriptor anchors all operations even if the path is renamed.
pub struct ConfigStore {
    root: File,
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::flock(&self.0, FlockOperation::Unlock);
    }
}

fn private_regular(f: &File) -> Result<(), ConfigError> {
    let m = f.metadata().map_err(|_| ConfigError::Storage)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.permissions().mode() & 0o077 != 0
    {
        return Err(ConfigError::UnsafePath);
    }
    Ok(())
}
fn open_file(root: &File, name: &str, flags: OFlags, mode: Mode) -> Result<File, rustix::io::Errno> {
    fs::openat(
        root,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        mode,
    )
    .map(File::from)
}

// The event API avoids YamlLoader's recursive descent and alias expansion.
fn validate_yaml(source: &str) -> Result<(), ConfigError> {
    let mut parser = Parser::new(source.chars());
    let mut depth = 0usize;
    let mut documents = 0usize;
    let mut root_seen = false;
    loop {
        let (event, _) = parser.next_token().map_err(|_| ConfigError::InvalidYaml)?;
        match event {
            Event::StreamStart => (),
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(ConfigError::InvalidYaml);
                }
                root_seen = false;
            }
            Event::DocumentEnd => {
                if !root_seen || depth != 0 {
                    return Err(ConfigError::InvalidYaml);
                }
            }
            Event::StreamEnd => {
                return if documents == 1 && root_seen && depth == 0 {
                    Ok(())
                } else {
                    Err(ConfigError::InvalidYaml)
                };
            }
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                if !root_seen {
                    if !matches!(event, Event::MappingStart(..)) {
                        return Err(ConfigError::InvalidYaml);
                    }
                    root_seen = true;
                }
                depth += 1;
                if depth > 64 {
                    return Err(ConfigError::InvalidYaml);
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                depth = depth.checked_sub(1).ok_or(ConfigError::InvalidYaml)?;
            }
            Event::Scalar(..) | Event::Alias(..) => {
                if !root_seen {
                    return Err(ConfigError::InvalidYaml);
                }
            }
            Event::Nothing => return Err(ConfigError::InvalidYaml),
        }
    }
}

impl ConfigStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ConfigError::UnsafePath);
        }
        let parts: Vec<_> = root.components().collect();
        if parts.len() < 2 || parts.iter().skip(1).any(|p| !matches!(p, Component::Normal(_))) {
            return Err(ConfigError::UnsafePath);
        }
        let mut dir = File::from(
            fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
                .map_err(|_| ConfigError::Storage)?,
        );
        for (index, part) in parts.iter().enumerate().skip(1) {
            let Component::Normal(name) = part else {
                return Err(ConfigError::UnsafePath);
            };
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let fd = match fs::openat(&dir, *name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if index == parts.len() - 1 => {
                    fs::mkdirat(&dir, *name, Mode::from_bits_truncate(0o700)).map_err(|_| ConfigError::Storage)?;
                    fs::openat(&dir, *name, flags, Mode::empty()).map_err(|_| ConfigError::UnsafePath)?
                }
                Err(_) => return Err(ConfigError::UnsafePath),
            };
            let child = File::from(fd);
            if index == parts.len() - 1 {
                // Persist the store directory entry even when it already existed:
                // an earlier creator may have stopped before syncing its parent.
                dir.sync_all().map_err(|_| ConfigError::Storage)?;
            }
            dir = child;
        }
        let m = dir.metadata().map_err(|_| ConfigError::Storage)?;
        if m.permissions().mode() & 0o077 != 0 || m.uid() != unsafe { nix::libc::geteuid() } {
            return Err(ConfigError::UnsafePath);
        }
        Ok(Self { root: dir })
    }
    fn entries(&self) -> Result<Vec<String>, ConfigError> {
        let dir = Dir::read_from(&self.root).map_err(|_| ConfigError::Storage)?;
        dir.map(|entry| {
            let entry = entry.map_err(|_| ConfigError::Storage)?;
            entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .map_err(|_| ConfigError::UnsafePath)
        })
        .collect()
    }
    fn lock(&self) -> Result<Lock, ConfigError> {
        let f = open_file(
            &self.root,
            ".lock",
            OFlags::RDWR | OFlags::CREATE,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| ConfigError::UnsafePath)?;
        private_regular(&f)?;
        fs::flock(&f, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::AGAIN {
                ConfigError::Busy
            } else {
                ConfigError::Storage
            }
        })?;
        let lock = Lock(f);
        for name in self.entries()? {
            if let Some(id) = name.strip_prefix('.').and_then(|s| s.strip_suffix(".tmp"))
                && uuid::Uuid::parse_str(id).is_ok()
            {
                fs::unlinkat(&self.root, name.as_str(), AtFlags::empty()).map_err(|_| ConfigError::Storage)?;
            }
        }
        Ok(lock)
    }
    fn name(id: &str) -> Result<String, ConfigError> {
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return Err(ConfigError::InvalidId);
        }
        Ok(format!("{id}.yaml"))
    }
    fn profile_file(&self, id: &str) -> Result<File, ConfigError> {
        let name = Self::name(id)?;
        let f = open_file(&self.root, &name, OFlags::RDONLY, Mode::empty()).map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                ConfigError::NotFound
            } else {
                ConfigError::UnsafePath
            }
        })?;
        private_regular(&f)?;
        if f.metadata().map_err(|_| ConfigError::Storage)?.len() > (MAX_PROFILE_BYTES + 128) as u64 {
            return Err(ConfigError::UnsafePath);
        }
        Ok(f)
    }
    fn read_locked(&self, id: &str) -> Result<Profile, ConfigError> {
        let f = self.profile_file(id)?;
        let mut contents = String::new();
        f.take((MAX_PROFILE_BYTES + 129) as u64)
            .read_to_string(&mut contents)
            .map_err(|_| ConfigError::Storage)?;
        if contents.len() > MAX_PROFILE_BYTES + 128 {
            return Err(ConfigError::UnsafePath);
        }
        let (header, source) = contents.split_once('\n').ok_or(ConfigError::Storage)?;
        let revision = header.strip_prefix(HEADER).ok_or(ConfigError::Storage)?;
        if uuid::Uuid::parse_str(revision).is_err() {
            return Err(ConfigError::Storage);
        }
        Ok(Profile {
            id: id.into(),
            revision: revision.into(),
            source: source.into(),
        })
    }
    pub fn read(&self, id: &str) -> Result<Profile, ConfigError> {
        let _lock = self.lock()?;
        self.read_locked(id)
    }
    pub(crate) fn with_revision<T>(&self, id: &str, revision: &str, f: impl FnOnce() -> T) -> Result<T, ConfigError> {
        let _lock = self.lock()?;
        if self.read_locked(id)?.revision != revision {
            return Err(ConfigError::Conflict);
        }
        Ok(f())
    }
    fn list_locked(&self) -> Result<Vec<String>, ConfigError> {
        let mut ids = Vec::new();
        for name in self.entries()? {
            if let Some(id) = name.strip_suffix(".yaml") {
                Self::name(id)?;
                self.profile_file(id)?;
                ids.push(id.to_owned());
                if ids.len() > MAX_PROFILES {
                    return Err(ConfigError::LimitReached);
                }
            }
        }
        ids.sort();
        Ok(ids)
    }
    pub fn list(&self) -> Result<Vec<String>, ConfigError> {
        let _lock = self.lock()?;
        self.list_locked()
    }
    /// Read a consistent set of profiles for an application backup. The shared
    /// store lock prevents a writer from publishing a mixed revision set midway
    /// through the snapshot.
    pub fn snapshot_all(&self) -> Result<Vec<Profile>, ConfigError> {
        let _lock = self.lock()?;
        self.list_locked()?
            .into_iter()
            .map(|id| self.read_locked(&id))
            .collect()
    }
    pub fn validate_source(source: &str) -> Result<(), ConfigError> {
        validate_yaml(source)
    }
    /// `None` creates a new profile; a revision replaces exactly that version.
    pub fn save(&self, id: &str, source: &str, expected_revision: Option<&str>) -> Result<Profile, ConfigError> {
        let name = Self::name(id)?;
        if source.len() > MAX_PROFILE_BYTES {
            return Err(ConfigError::TooLarge);
        }
        validate_yaml(source)?;
        let _lock = self.lock()?;
        match self.read_locked(id) {
            Ok(existing) if expected_revision == Some(existing.revision.as_str()) => (),
            Ok(_) => return Err(ConfigError::Conflict),
            Err(ConfigError::NotFound) if expected_revision.is_none() => {
                if self.list_locked()?.len() >= MAX_PROFILES {
                    return Err(ConfigError::LimitReached);
                }
            }
            Err(ConfigError::NotFound) => return Err(ConfigError::Conflict),
            Err(e) => return Err(e),
        }
        // Budget the final set of profiles and the temporary file separately. The
        // reserve is checked under the store lock, but other applications may
        // still consume space after this advisory preflight.
        let ids = self.list_locked()?;
        let mut total = 0u64;
        for existing_id in ids {
            if existing_id != id {
                let size = self
                    .profile_file(&existing_id)?
                    .metadata()
                    .map_err(|_| ConfigError::Storage)?
                    .len();
                total = total.saturating_add(size);
            }
        }
        let staged_bytes = (source.len() as u64)
            .saturating_add(HEADER.len() as u64)
            .saturating_add(37);
        if total.saturating_add(staged_bytes) > MAX_TOTAL_BYTES {
            return Err(ConfigError::LimitReached);
        }
        let space = fs::fstatvfs(&self.root).map_err(|_| ConfigError::Storage)?;
        let block_size = space.f_frsize;
        let allocated = staged_bytes
            .saturating_add(block_size.saturating_sub(1))
            .checked_div(block_size)
            .map(|blocks| blocks.saturating_mul(block_size))
            .unwrap_or(u64::MAX);
        if block_size == 0 || space.f_bavail.saturating_mul(block_size) < FREE_RESERVE_BYTES.saturating_add(allocated) {
            return Err(ConfigError::InsufficientSpace);
        }
        let revision = uuid::Uuid::new_v4().to_string();
        let tmp = format!(".{}.tmp", uuid::Uuid::new_v4());
        let result = (|| {
            let mut file = open_file(
                &self.root,
                &tmp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| ConfigError::Storage)?;
            write!(file, "{HEADER}{revision}\n{source}").map_err(|_| ConfigError::Storage)?;
            file.sync_all().map_err(|_| ConfigError::Storage)?;
            fs::renameat(&self.root, tmp.as_str(), &self.root, name.as_str()).map_err(|_| ConfigError::Storage)?;
            self.root.sync_all().map_err(|_| ConfigError::CommitUncertain)?;
            Ok(Profile {
                id: id.into(),
                revision,
                source: source.into(),
            })
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.root, tmp.as_str(), AtFlags::empty());
        }
        result
    }
    pub fn delete(&self, id: &str, expected_revision: &str) -> Result<(), ConfigError> {
        let name = Self::name(id)?;
        let _lock = self.lock()?;
        if id == "config" || self.list_locked()?.len() <= 1 {
            return Err(ConfigError::InvalidId);
        }
        let profile = self.read_locked(id)?;
        if profile.revision != expected_revision {
            return Err(ConfigError::Conflict);
        }
        fs::unlinkat(&self.root, name.as_str(), AtFlags::empty()).map_err(|_| ConfigError::Storage)?;
        self.root.sync_all().map_err(|_| ConfigError::CommitUncertain)
    }
    pub fn rename(&self, id: &str, new_id: &str, expected_revision: &str) -> Result<Profile, ConfigError> {
        let old_name = Self::name(id)?;
        let new_name = Self::name(new_id)?;
        let _lock = self.lock()?;
        if id == "config" || new_id == "config" {
            return Err(ConfigError::InvalidId);
        }
        let profile = self.read_locked(id)?;
        if profile.revision != expected_revision {
            return Err(ConfigError::Conflict);
        }
        if id == new_id {
            return Ok(profile);
        }
        match open_file(&self.root, &new_name, OFlags::RDONLY, Mode::empty()) {
            Ok(_) => return Err(ConfigError::Conflict),
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err(ConfigError::UnsafePath),
        }
        fs::renameat(&self.root, old_name.as_str(), &self.root, new_name.as_str()).map_err(|_| ConfigError::Storage)?;
        self.root.sync_all().map_err(|_| ConfigError::CommitUncertain)?;
        self.read_locked(new_id)
    }
}
