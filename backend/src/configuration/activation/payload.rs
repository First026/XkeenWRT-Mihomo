//! Immutable, content-addressed manual bundles. All writers hold mutation.lock.
//! Only typed relative file names are resolved; a display never calls this module's IO paths.
use super::{ActivationError, Saved, SavedAsset};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

type Result<T> = std::result::Result<T, ActivationError>;
const BUNDLE_LIMIT: u64 = 10 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRef {
    pub file: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PayloadRef {
    pub digest: String,
    pub files: Vec<FileRef>,
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
fn digest_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_asset(s: &str) -> bool {
    ["providers/proxies/", "providers/rules/"].iter().any(|prefix| {
        s.strip_prefix(prefix)
            .and_then(|x| x.strip_suffix(".yaml"))
            .is_some_and(|x| {
                x.parse::<usize>()
                    .is_ok_and(|n| n < profile_policy::MAX_PROVIDER_FILES && n.to_string() == x)
            })
    })
}
impl PayloadRef {
    pub fn valid(&self) -> bool {
        if !digest_ok(&self.digest)
            || self.files.is_empty()
            || self.files.len() > profile_policy::MAX_PROVIDER_FILES + 1
        {
            return false;
        }
        let mut paths = BTreeSet::new();
        let mut bytes = 0u64;
        for (i, f) in self.files.iter().enumerate() {
            if !digest_ok(&f.sha256)
                || f.bytes > BUNDLE_LIMIT
                || !paths.insert(&f.path)
                || if i == 0 {
                    f.path != "config.yaml" || f.file != "config.yaml"
                } else {
                    !valid_asset(&f.path) || f.file != format!("asset-{:03}", i - 1)
                }
            {
                return false;
            }
            bytes = bytes.saturating_add(f.bytes);
        }
        bytes <= BUNDLE_LIMIT && serde_json::to_vec(&self.files).is_ok_and(|b| hash(&b) == self.digest)
    }
}
fn directory(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ActivationError::Storage)?;
    let m = file.metadata().map_err(|_| ActivationError::Storage)?;
    if !m.is_dir() || m.uid() != unsafe { nix::libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(ActivationError::Storage);
    }
    Ok(file)
}
fn ensure_dir(path: &Path) -> Result<File> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            File::open(path.parent().ok_or(ActivationError::Storage)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| ActivationError::Storage)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(ActivationError::Storage),
    }
    directory(path)
}
fn read_file(path: &Path, expected: &FileRef) -> Result<Vec<u8>> {
    let f = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ActivationError::Storage)?;
    let m = f.metadata().map_err(|_| ActivationError::Storage)?;
    if !m.is_file()
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() != expected.bytes
    {
        return Err(ActivationError::Storage);
    }
    let mut bytes = Vec::new();
    f.take(expected.bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActivationError::Storage)?;
    if bytes.len() as u64 != expected.bytes || hash(&bytes) != expected.sha256 {
        return Err(ActivationError::Storage);
    }
    Ok(bytes)
}
fn names(path: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(path).map_err(|_| ActivationError::Storage)? {
        if names.len() > profile_policy::MAX_PROVIDER_FILES + 1 {
            return Err(ActivationError::Storage);
        }
        let name = entry
            .map_err(|_| ActivationError::Storage)?
            .file_name()
            .into_string()
            .map_err(|_| ActivationError::Storage)?;
        names.insert(name);
    }
    Ok(names)
}
pub(super) fn read(root: &Path, reference: &PayloadRef) -> Result<(String, Vec<SavedAsset>)> {
    if !reference.valid() {
        return Err(ActivationError::Storage);
    }
    let _root = directory(root)?;
    let parent = root.join("payloads");
    let _parent = directory(&parent)?;
    let object = parent.join(&reference.digest);
    let _object = directory(&object)?;
    if names(&object)? != reference.files.iter().map(|f| f.file.clone()).collect() {
        return Err(ActivationError::Storage);
    }
    let config = String::from_utf8(read_file(&object.join("config.yaml"), &reference.files[0])?)
        .map_err(|_| ActivationError::Storage)?;
    let mut assets = Vec::new();
    for f in reference.files.iter().skip(1) {
        assets.push(SavedAsset {
            path: f.path.clone(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(read_file(&object.join(&f.file), f)?),
        });
    }
    Ok((config, assets))
}
pub(super) fn compact(root: &Path, saved: &Saved) -> Result<Saved> {
    let assets = saved.bundle()?; // Exact admission before a payload becomes authoritative.
    let mut blobs = vec![(
        "config.yaml".to_owned(),
        "config.yaml".to_owned(),
        saved.config.as_bytes().to_vec(),
    )];
    let mut ordered: Vec<_> = assets.iter().collect();
    ordered.sort_by_key(|a| &a.path);
    for (i, a) in ordered.into_iter().enumerate() {
        blobs.push((format!("asset-{i:03}"), a.path.clone(), a.content.clone()));
    }
    let files: Vec<_> = blobs
        .iter()
        .map(|(file, path, bytes)| FileRef {
            file: file.clone(),
            path: path.clone(),
            sha256: hash(bytes),
            bytes: bytes.len() as u64,
        })
        .collect();
    let reference = PayloadRef {
        digest: hash(&serde_json::to_vec(&files).map_err(|_| ActivationError::Storage)?),
        files,
    };
    if !reference.valid() {
        return Err(ActivationError::Storage);
    }
    let _root = directory(root)?;
    let parent = root.join("payloads");
    let parent_fd = ensure_dir(&parent)?;
    let target = parent.join(&reference.digest);
    if std::fs::symlink_metadata(&target).is_ok() {
        read(root, &reference)?;
    } else {
        let size = blobs.iter().map(|b| b.2.len() as u64).sum::<u64>();
        let used = xkeenwrt_recovery::resources::history_size(root).map_err(|_| ActivationError::Storage)?;
        let space = rustix::fs::fstatvfs(&_root).map_err(|_| ActivationError::Storage)?;
        if used.saturating_add(size) > 64 * 1024 * 1024
            || space.f_bavail.saturating_mul(space.f_frsize) < 8 * 1024 * 1024 + size
        {
            return Err(ActivationError::Storage);
        }
        let stage_name = format!(".stage-{}", uuid::Uuid::new_v4());
        let stage = parent.join(&stage_name);
        let stage_fd = ensure_dir(&stage)?;
        let result = (|| {
            for (file, _, bytes) in &blobs {
                let mut f = File::options()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                    .open(stage.join(file))
                    .map_err(|_| ActivationError::Storage)?;
                f.write_all(bytes)
                    .and_then(|()| f.sync_all())
                    .map_err(|_| ActivationError::Storage)?;
            }
            stage_fd.sync_all().map_err(|_| ActivationError::Storage)?;
            rustix::fs::renameat_with(
                &parent_fd,
                stage_name.as_str(),
                &parent_fd,
                reference.digest.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| ActivationError::Storage)?;
            parent_fd.sync_all().map_err(|_| ActivationError::Storage)
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&stage);
        }
        result?;
    }
    let mut result = saved.clone();
    result.config.clear();
    result.assets.clear();
    result.provider_metadata = Some(crate::mihomo::providers::metadata::applied(&saved.config, &assets));
    result.payload = Some(reference);
    Ok(result)
}

fn validate_core_snapshot(path: &Path, depth: usize, count: &mut usize) -> Result<()> {
    let _dir = directory(path)?;
    if depth > 4 {
        return Err(ActivationError::Storage);
    }
    if depth == 0
        && !path
            .join("config.yaml")
            .try_exists()
            .map_err(|_| ActivationError::Storage)?
    {
        return Err(ActivationError::Storage);
    }
    for entry in std::fs::read_dir(path).map_err(|_| ActivationError::Storage)? {
        *count += 1;
        if *count > 64 {
            return Err(ActivationError::Storage);
        }
        let entry = entry.map_err(|_| ActivationError::Storage)?;
        let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
        let m = std::fs::symlink_metadata(entry.path()).map_err(|_| ActivationError::Storage)?;
        if m.file_type().is_symlink() || m.uid() != unsafe { nix::libc::geteuid() } {
            return Err(ActivationError::Storage);
        }
        if m.is_dir() {
            let allowed = match depth {
                0 => name == "assets",
                1 => name == "providers",
                2 => ["proxies", "rules"].contains(&name.as_str()),
                _ => false,
            };
            if !allowed {
                return Err(ActivationError::Storage);
            }
            validate_core_snapshot(&entry.path(), depth + 1, count)?;
        } else {
            let allowed = if depth == 0 {
                name == "config.yaml"
            } else {
                depth == 3
                    && name.strip_suffix(".yaml").is_some_and(|s| {
                        s.parse::<usize>()
                            .is_ok_and(|n| n < profile_policy::MAX_PROVIDER_FILES && n.to_string() == s)
                    })
            };
            if !allowed || !m.is_file() || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > BUNDLE_LIMIT {
                return Err(ActivationError::Storage);
            }
        }
    }
    Ok(())
}
/// Complete lease graph, or no deletion. Core snapshots are separate objects.
/// Existing lifecycle/rollback leases pin every payload until their handoff ends.
pub(super) fn gc(root: &Path) -> Result<()> {
    let _root = directory(root)?;
    for name in [
        "removal.json",
        "lifecycle.json",
        "rescue-replacement.json",
        "inputs-transition.json",
        "upgrade-receipt.json",
    ] {
        match std::fs::symlink_metadata(root.join(name)) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(ActivationError::Storage),
        }
    }
    let journal = super::journal_metadata(root)?;
    if journal.version != 2 {
        return Ok(());
    }
    let mut leased = BTreeSet::new();
    let mut add = |saved: &Saved| -> Result<()> {
        if let Some(r) = &saved.payload {
            if !r.valid() {
                return Err(ActivationError::Storage);
            }
            leased.insert(r.digest.clone());
        } else {
            saved.bundle()?;
        }
        Ok(())
    };
    for s in [&journal.current, &journal.pending].into_iter().flatten() {
        add(s)?;
    }
    let history = root.join("history");
    match std::fs::symlink_metadata(&history) {
        Ok(_) => {
            let _history = directory(&history)?;
            for (i, entry) in std::fs::read_dir(&history)
                .map_err(|_| ActivationError::Storage)?
                .enumerate()
            {
                if i >= 128 {
                    return Err(ActivationError::Storage);
                }
                let entry = entry.map_err(|_| ActivationError::Storage)?;
                let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
                if let Some(id) = name.strip_suffix(".json") {
                    if !uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id) {
                        return Err(ActivationError::Storage);
                    }
                    let bytes = super::read_private(&entry.path(), super::JOURNAL_LIMIT)?;
                    let saved: Saved = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Storage)?;
                    add(&saved)?;
                } else if uuid::Uuid::parse_str(&name).is_ok_and(|u| u.to_string() == name) {
                    validate_core_snapshot(&entry.path(), 0, &mut 0)?;
                } else {
                    // Unknown or interrupted core snapshot staging prevents orphan cleanup.
                    return Ok(());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(ActivationError::Storage),
    }
    let parent = root.join("payloads");
    if !parent.try_exists().map_err(|_| ActivationError::Storage)? {
        return Ok(());
    }
    let parent_fd = directory(&parent)?;
    let entries: Vec<_> = std::fs::read_dir(&parent)
        .map_err(|_| ActivationError::Storage)?
        .collect::<std::io::Result<_>>()
        .map_err(|_| ActivationError::Storage)?;
    if entries.len() > 128 {
        return Err(ActivationError::Storage);
    }
    // Validate every candidate before deleting any. Unknown names are never ours to delete.
    let mut unreferenced = Vec::new();
    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
        if leased.contains(&name) {
            continue;
        }
        if !digest_ok(&name)
            && !name
                .strip_prefix(".stage-")
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s))
        {
            return Err(ActivationError::Storage);
        }
        let _object = directory(&entry.path())?;
        for file in names(&entry.path())? {
            if file != "config.yaml"
                && !file.strip_prefix("asset-").is_some_and(|s| {
                    s.len() == 3 && s.parse::<usize>().is_ok_and(|n| n < profile_policy::MAX_PROVIDER_FILES)
                })
            {
                return Err(ActivationError::Storage);
            }
            // nofollow, bounds and ownership even for an orphan with no manifest lease.
            let p = entry.path().join(file);
            let m = std::fs::symlink_metadata(&p).map_err(|_| ActivationError::Storage)?;
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.uid() != unsafe { nix::libc::geteuid() }
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len() > BUNDLE_LIMIT
            {
                return Err(ActivationError::Storage);
            }
        }
        unreferenced.push(entry.path());
    }
    for path in unreferenced {
        std::fs::remove_dir_all(path).map_err(|_| ActivationError::Storage)?;
    }
    parent_fd.sync_all().map_err(|_| ActivationError::Storage)
}
