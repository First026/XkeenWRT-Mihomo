//! Closed AArch64 Mihomo release catalogue and process identity checks shared by
//! the installer, validator sandbox, and independent recovery binary.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

pub const ROOT: &str = "/usr/libexec/xkeenwrt/cores";
pub const ACTIVE_MARKER: &str = "/etc/xkeenwrt/mihomo-active";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: &'static str,
    pub url: &'static str,
    pub archive_size: u64,
    pub archive_sha256: &'static str,
    pub elf_size: u64,
    pub elf_sha256: &'static str,
    pub published: &'static str,
}

pub const RELEASES: [Release; 2] = [
    Release {
        version: "1.19.33",
        url: "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-arm64-v1.19.33.gz",
        archive_size: 20_824_326,
        archive_sha256: "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187",
        elf_size: 57_475_198,
        elf_sha256: "8c73570d9a5f388bc2f58eee0b347ccfab84fb3cf1a0f8f2cf5eac7005fbcdc0",
        published: "2026-10-21",
    },
    Release {
        version: "1.19.34",
        url: "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-arm64-v1.19.34.gz",
        archive_size: 20_684_679,
        archive_sha256: "daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f",
        elf_size: 57_344_126,
        elf_sha256: "022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441",
        published: "2026-11-11",
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    uid: u32,
    mode: u32,
    nlink: u64,
}
impl FileIdentity {
    fn read(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
        })
    }
}
struct CacheEntry {
    version: &'static str,
    file: File,
    identity: FileIdentity,
}
static VERIFIED_RELEASES: OnceLock<Mutex<Vec<CacheEntry>>> = OnceLock::new();

pub fn release(version: &str) -> Option<&'static Release> {
    RELEASES.iter().find(|release| release.version == version)
}

pub fn version_path(release: &Release) -> PathBuf {
    Path::new(ROOT).join(release.version).join("mihomo")
}

fn verify_directory(path: &Path, expected_mode: Option<u32>) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != 0
        || m.mode() & 0o7022 != 0
        || expected_mode.is_some_and(|mode| m.mode() & 0o7777 != mode)
    {
        return Err(io::Error::other("unsafe Mihomo release directory"));
    }
    Ok(())
}

fn open_release(release: &Release) -> io::Result<File> {
    if !cfg!(target_arch = "aarch64") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Mihomo catalogue is AArch64 only",
        ));
    }
    let root = Path::new(ROOT);
    for path in ["/usr", "/usr/libexec", "/usr/libexec/xkeenwrt"] {
        verify_directory(Path::new(path), None)?;
    }
    verify_directory(root, Some(0o755))?;
    verify_directory(&root.join(release.version), Some(0o755))?;
    let path = version_path(release);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let metadata = file.metadata()?;
    let at_path = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || at_path.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o755
        || metadata.len() != release.elf_size
        || at_path.dev() != metadata.dev()
        || at_path.ino() != metadata.ino()
    {
        return Err(io::Error::other("unsafe Mihomo release file"));
    }
    let identity = FileIdentity::read(&file)?;
    let cache = VERIFIED_RELEASES.get_or_init(|| Mutex::new(Vec::new()));
    let mut verified = cache
        .lock()
        .map_err(|_| io::Error::other("Mihomo identity cache poisoned"))?;
    if verified.iter().any(|entry| {
        entry.version == release.version
            && entry.identity == identity
            && FileIdentity::read(&entry.file).ok().as_ref() == Some(&identity)
    }) {
        file.seek(SeekFrom::Start(0))?;
        return Ok(file);
    }
    verify_elf(&mut file, release.elf_size)?;
    let digest = hash_file(&mut file)?;
    let after = FileIdentity::read(&file)?;
    let named_after = fs::symlink_metadata(&path)?;
    if digest != release.elf_sha256
        || after != identity
        || named_after.file_type().is_symlink()
        || named_after.dev() != identity.dev
        || named_after.ino() != identity.ino
    {
        return Err(io::Error::other("Mihomo release hash mismatch"));
    }
    let pinned = file.try_clone()?;
    verified.retain(|entry| entry.version != release.version);
    verified.push(CacheEntry {
        version: release.version,
        file: pinned,
        identity,
    });
    if verified.len() > RELEASES.len() {
        verified.remove(0);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn verify_marker_directory() -> io::Result<()> {
    verify_directory(Path::new("/etc"), None)?;
    match fs::symlink_metadata("/etc/xkeenwrt") {
        Ok(_) => verify_directory(Path::new("/etc/xkeenwrt"), Some(0o700)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn verify_elf(file: &mut File, expected_size: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || u16::from_le_bytes([header[18], header[19]]) != 183
    {
        return Err(io::Error::other("Mihomo ELF ABI mismatch"));
    }
    let phoff = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| io::Error::other("invalid ELF header"))?,
    );
    let phentsize = u16::from_le_bytes([header[54], header[55]]) as u64;
    let phnum = u16::from_le_bytes([header[56], header[57]]) as u64;
    if phentsize < 56
        || phnum > 256
        || phoff.saturating_add(phentsize.saturating_mul(phnum)) > expected_size
    {
        return Err(io::Error::other("invalid Mihomo ELF program headers"));
    }
    for index in 0..phnum {
        file.seek(SeekFrom::Start(phoff + index * phentsize))?;
        let mut kind = [0u8; 4];
        file.read_exact(&mut kind)?;
        if matches!(u32::from_le_bytes(kind), 2 | 3) {
            return Err(io::Error::other("Mihomo must be a static executable"));
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn hash_file(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn active_release() -> io::Result<Option<&'static Release>> {
    verify_marker_directory()?;
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(ACTIVE_MARKER)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o600 || m.len() > 32
    {
        return Err(io::Error::other("unsafe active Mihomo marker"));
    }
    let mut version = String::new();
    file.read_to_string(&mut version)?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(io::Error::other("invalid active Mihomo marker"));
    }
    release(&version)
        .map(Some)
        .ok_or_else(|| io::Error::other("active Mihomo version is outside the catalogue"))
}

pub fn open_release_version(version: &str) -> io::Result<(File, &'static Release)> {
    let release = release(version)
        .ok_or_else(|| io::Error::other("Mihomo version is outside the catalogue"))?;
    open_release(release).map(|file| (file, release))
}

/// Returns the catalogue entry only when `path` is one of the two exact
/// versioned executable names. Legacy flat paths and arbitrary suffixes are
/// deliberately not accepted.
pub fn release_for_exe_path(path: &Path) -> Option<&'static Release> {
    RELEASES
        .iter()
        .find(|release| path == version_path(release))
}

pub fn open_active_core() -> io::Result<Option<(File, &'static Release)>> {
    let Some(release) = active_release()? else {
        return Ok(None);
    };
    open_release(release).map(|file| Some((file, release)))
}

pub fn installed_core_valid() -> bool {
    match open_active_core() {
        Ok(Some(_)) | Ok(None) => true,
        Err(_) => false,
    }
}

/// Health must match the installed selection, not just any supported release.
pub fn active_api_version_matches(version: &str) -> bool {
    active_release()
        .ok()
        .flatten()
        .is_some_and(|release| version.strip_prefix('v') == Some(release.version))
}

pub fn verify_process_exe(pid: u32) -> io::Result<(File, &'static Release)> {
    let (active, release) =
        open_active_core()?.ok_or_else(|| io::Error::other("Mihomo is not installed"))?;
    let expected_path = version_path(release);
    let proc_path = format!("/proc/{pid}/exe");
    if fs::read_link(&proc_path)? != expected_path {
        return Err(io::Error::other("Mihomo process path mismatch"));
    }
    let process = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&proc_path)?;
    let a = active.metadata()?;
    let b = process.metadata()?;
    if !b.is_file()
        || b.uid() != 0
        || b.nlink() != 1
        || b.mode() & 0o7777 != 0o755
        || a.dev() != b.dev()
        || a.ino() != b.ino()
        || a.len() != b.len()
    {
        return Err(io::Error::other("Mihomo process identity mismatch"));
    }
    Ok((process, release))
}

pub fn open_active_core_for_validator() -> io::Result<File> {
    open_active_core()?
        .map(|(file, _)| file)
        .ok_or_else(|| io::Error::other("Mihomo is not installed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_catalogue_paths_are_trusted() {
        assert_eq!(
            release_for_exe_path(Path::new("/usr/libexec/xkeenwrt/cores/1.19.33/mihomo"))
                .map(|r| r.version),
            Some("1.19.33")
        );
        assert_eq!(
            release_for_exe_path(Path::new("/usr/libexec/xkeenwrt/cores/1.19.34/mihomo"))
                .map(|r| r.version),
            Some("1.19.34")
        );
        for path in [
            "/usr/libexec/xkeenwrt/mihomo",
            "/usr/libexec/xkeenwrt/cores/1.19.35/mihomo",
            "/usr/libexec/xkeenwrt/cores/1.19.34/mihomo (deleted)",
            "/tmp/mihomo",
        ] {
            assert!(release_for_exe_path(Path::new(path)).is_none(), "{path}");
        }
    }
}
