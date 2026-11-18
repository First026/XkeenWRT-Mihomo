//! Mihomo's lazy bbolt cache is mutable runtime state, never a profile asset.
use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Core launch starts with a cache-free home and umask 077. Admit only the
/// resulting bounded private regular file during live proofs and cleanup.
pub fn present(root: &Path) -> io::Result<bool> {
    check(root, false)
}
/// Only disposal of a proven retired home recognizes caches from older cores
/// that used umask 022. Live proofs remain 0600-only.
pub fn removable(root: &Path) -> io::Result<bool> {
    check(root, true)
}
fn check(root: &Path, retired: bool) -> io::Result<bool> {
    let parent = std::fs::symlink_metadata(root)?;
    if !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.uid() != 0
        || parent.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other("unsafe core cache parent"));
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join("cache.db"))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || !(m.mode() & 0o7777 == 0o600 || (retired && m.mode() & 0o7777 == 0o644))
        || m.nlink() != 1
        || m.len() > 16 * 1024 * 1024
    {
        return Err(io::Error::other("unsafe mutable core cache"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    #[test]
    fn cache_can_change_but_links_public_modes_and_oversized_files_are_rejected() {
        let root = std::env::temp_dir().join(format!(
            "xkeen-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!present(&root).unwrap());
        let cache = root.join("cache.db");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&cache)
            .unwrap();
        assert!(present(&root).unwrap());
        file.set_len(16384).unwrap();
        assert!(present(&root).unwrap());
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(present(&root).is_err());
        assert!(removable(&root).unwrap());
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&cache, root.join("linked")).unwrap();
        assert!(present(&root).is_err());
        std::fs::remove_file(root.join("linked")).unwrap();
        file.set_len(16 * 1024 * 1024 + 1).unwrap();
        assert!(present(&root).is_err());
        drop(file);
        std::fs::remove_file(&cache).unwrap();
        symlink("elsewhere", &cache).unwrap();
        assert!(present(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
