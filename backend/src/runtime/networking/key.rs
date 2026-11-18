//! Separate persistent key for deriving retryable confirmation tokens.
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Caller holds mutation.lock. `allow_create` is true only when no network
/// journal exists; a missing key with a pending/active journal must not rotate.
pub fn load(dir: &Path, allow_create: bool) -> io::Result<[u8; 32]> {
    let path = dir.join("confirmation-key");
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(&path)
    };
    let mut file = match open() {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound && allow_create => {
            use ring::rand::SecureRandom;
            let mut random = [0u8; 32];
            ring::rand::SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| io::Error::other("random source unavailable"))?;
            crate::private_file::publish_private(&path, &random)?;
            open()?
        }
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid confirmation key",
        ));
    }
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
