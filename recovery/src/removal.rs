//! Persistent removal request shared with the independently installed rescue service.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
pub use xkeenwrt_recovery::LifecycleState as RemovalState;
use xkeenwrt_recovery::{LifecycleKind, LifecycleRequest as Removal};
fn path() -> &'static Path {
    Path::new("/etc/xkeenwrt/removal.json")
}
pub fn load() -> io::Result<Option<Removal>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path())
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 4096
    {
        return Err(io::Error::other("unsafe removal journal"));
    }
    let mut bytes = Vec::new();
    f.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("removal journal too large"));
    }
    let value: Removal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if value
        .request_id
        .as_deref()
        .is_some_and(|id| xkeenwrt_recovery::supervisor_cgroup_path(&value.owner_id, id).is_err())
    {
        return Err(io::Error::other("invalid lifecycle request id"));
    }
    if value.version != 1
        || xkeenwrt_recovery::supervisor_cgroup_path(
            &value.owner_id,
            "00000000-0000-4000-8000-000000000000",
        )
        .is_err()
    {
        return Err(io::Error::other("invalid removal journal"));
    }
    Ok(Some(value))
}
pub fn store(value: &Removal) -> io::Result<()> {
    let temp = format!("/etc/xkeenwrt/.removal-{}", std::process::id());
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        serde_json::to_writer(&mut f, value).map_err(io::Error::other)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&temp, path())?;
        fs::File::open("/etc/xkeenwrt")?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn ensure_requested(owner_id: &str, kind: LifecycleKind) -> io::Result<Removal> {
    if let Some(existing) = load()? {
        if existing.owner_id != owner_id || existing.kind != kind {
            return Err(io::Error::other("removal owner mismatch"));
        }
        return Ok(existing);
    }
    let value = Removal {
        version: 1,
        owner_id: owner_id.to_owned(),
        request_id: Some(crate::core::fresh_nonce()?),
        kind,
        state: RemovalState::Requested,
    };
    let temp = format!("/etc/xkeenwrt/.removal-request-{}", std::process::id());
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        serde_json::to_writer(&mut f, &value).map_err(io::Error::other)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        if !xkeenwrt_recovery::publish_noreplace(Path::new(&temp), path())? {
            fs::remove_file(&temp)?;
        }
        fs::File::open("/etc/xkeenwrt")?.sync_all()?;
        let actual = load()?.ok_or_else(|| io::Error::other("removal request missing"))?;
        if actual.owner_id != owner_id || actual.kind != kind {
            return Err(io::Error::other("removal owner mismatch"));
        }
        Ok(actual)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
