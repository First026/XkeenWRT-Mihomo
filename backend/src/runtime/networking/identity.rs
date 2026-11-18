//! Durable owner and monotonic generation. Caller holds the shared mutation lock.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    pub owner_id: String,
    pub generation: u64,
}
fn private_read(path: &Path, limit: u64) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid network identity file",
        ));
    }
    let mut value = String::new();
    file.take(limit + 1).read_to_string(&mut value)?;
    if value.len() as u64 > limit {
        return Err(io::Error::other("identity too large"));
    }
    Ok(value)
}
fn atomic_counter(dir: &Path, generation: u64) -> io::Result<()> {
    let temp = dir.join(format!(".network-generation-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        writeln!(f, "{generation}")?;
        f.sync_all()?;
        fs::rename(&temp, dir.join("network-generation"))?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
/// Reserve the next generation after the runtime bootstrap has created identity files.
pub fn reserve(dir: &Path) -> io::Result<Identity> {
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe identity directory",
        ));
    }
    let owner_path = dir.join("owner-id");
    let counter_path = dir.join("network-generation");
    let exists = |path: &Path| match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    };
    if !exists(&owner_path)? || !exists(&counter_path)? {
        return Err(io::Error::other("network identity is not initialized"));
    }
    let journal_exists = exists(&dir.join("recovery.json"))?;
    let owner = private_read(&owner_path, 36)?;
    let parsed = uuid::Uuid::parse_str(&owner).map_err(io::Error::other)?;
    if parsed.to_string() != owner {
        return Err(io::Error::other("noncanonical owner"));
    }
    let raw = private_read(&counter_path, 21)?;
    let number = raw
        .strip_suffix('\n')
        .ok_or_else(|| io::Error::other("invalid generation"))?;
    if number.is_empty() || (number.len() > 1 && number.starts_with('0')) || !number.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(io::Error::other("invalid generation"));
    }
    let previous: u64 = number.parse().map_err(io::Error::other)?;
    if journal_exists {
        let journal = xkeenwrt_recovery::read_journal(dir)?;
        if journal.current.owner_id != owner
            || journal.decision(&journal.boot_id, journal.created_boottime_ms, false)
                != xkeenwrt_recovery::Decision::Settled
            || journal.generation > previous
            || journal.state == xkeenwrt_recovery::State::Pending
            || journal.state == xkeenwrt_recovery::State::Revoked
        {
            return Err(io::Error::other("unsettled network generation"));
        }
    }
    let generation = previous
        .checked_add(1)
        .ok_or_else(|| io::Error::other("generation exhausted"))?;
    atomic_counter(dir, generation)?;
    Ok(Identity {
        owner_id: owner,
        generation,
    })
}

/// Consume the fresh-install marker only after durable pending and immediately
/// before the first network mutation. Absence never recreates the marker.
pub fn consume_never_enabled(dir: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe identity directory",
        ));
    }
    let path = dir.join("network-never-enabled");
    if private_read(&path, 64)? != "xkeenwrt-no-network-v1\n" {
        return Err(io::Error::other("invalid never-enabled marker"));
    }
    fs::remove_file(path)?;
    File::open(dir)?.sync_all()
}

/// Check the fresh-install marker without creating or changing it.
pub fn never_enabled_present(dir: &Path) -> io::Result<bool> {
    let path = dir.join("network-never-enabled");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
        Ok(_) => {
            if private_read(&path, 64)? != "xkeenwrt-no-network-v1\n" {
                return Err(io::Error::other("invalid never-enabled marker"));
            }
            Ok(true)
        }
    }
}
