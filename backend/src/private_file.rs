//! Durable, no-replace publication for private local secrets.
use rustix::fs::{Mode, OFlags, RenameFlags, openat, renameat_with};
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};
use uuid::Uuid;

/// Publishes complete bytes as a 0600 single-link file. A pre-existing target is
/// never replaced; an interrupted staging file cannot become the target.
pub fn publish_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("missing parent"))?;
    let name = path.file_name().ok_or_else(|| io::Error::other("missing file name"))?;
    let dir = File::open(parent)?;
    let stage = format!(".xkeenwrt-secret-{}", Uuid::new_v4().simple());
    let result = (|| {
        let fd = openat(
            &dir,
            stage.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        renameat_with(&dir, stage.as_str(), &dir, name, RenameFlags::NOREPLACE)?;
        dir.sync_all()
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&dir, stage.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}

/// Preserve an existing private token exactly, or atomically create one.
pub fn load_or_create_bootstrap(path: &Path) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            publish_private(path, token.as_bytes())?;
            return Ok(token);
        }
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { nix::libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() != 64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid bootstrap token file",
        ));
    }
    let mut token = String::new();
    file.read_to_string(&mut token)?;
    if !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bootstrap token file",
        ));
    }
    Ok(token)
}
