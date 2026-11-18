//! Generation fence and cgroup quiescence. Paths are derived from the journal.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use xkeenwrt_recovery::{Journal, operation_cgroup_path, runtime_incarnation_path};
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Fence {
    version: u32,
    tx_id: String,
    generation: u64,
    boot_id: String,
}
fn expected(j: &Journal) -> Fence {
    Fence {
        version: 1,
        tx_id: j.tx_id.clone(),
        generation: j.generation,
        boot_id: j.boot_id.clone(),
    }
}
fn path(j: &Journal) -> PathBuf {
    PathBuf::from(format!("/var/run/xkeenwrt/revoked-{}", j.generation))
}
pub fn publish(j: &Journal) -> io::Result<()> {
    let path = path(j);
    if present(j)? {
        return Ok(());
    }
    let temp = PathBuf::from(format!(
        "/var/run/xkeenwrt/.fence-{}-{}",
        j.generation,
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        serde_json::to_writer(&mut file, &expected(j)).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        if !xkeenwrt_recovery::publish_noreplace(&temp, &path)? {
            fs::remove_file(&temp)?;
        }
        fs::File::open("/var/run/xkeenwrt")?.sync_all()?;
        if !present(j)? {
            return Err(io::Error::other("fence missing after publish"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn present(j: &Journal) -> io::Result<bool> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path(j))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 1024
    {
        return Err(io::Error::other("unsafe fence"));
    }
    let mut bytes = Vec::new();
    f.take(1025).read_to_end(&mut bytes)?;
    let actual: Fence = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if actual != expected(j) {
        return Err(io::Error::other("fence identity mismatch"));
    }
    Ok(true)
}
fn checked_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe cgroup directory"));
    }
    Ok(())
}
pub fn checked_path(j: &Journal, boot: &str) -> io::Result<Option<PathBuf>> {
    use std::ffi::CString;
    let root = Path::new("/sys/fs/cgroup");
    let cpath = CString::new(root.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(cpath.as_ptr(), &mut stat) } != 0 || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    let path = runtime_incarnation_path(&j.runtime_identity())?;
    if !path.exists() && boot != j.boot_id {
        return Ok(None);
    }
    for dir in [
        root.to_path_buf(),
        root.join("xkeenwrt"),
        root.join("xkeenwrt/incarnations"),
        path.clone(),
    ] {
        checked_dir(&dir)?;
    }
    Ok(Some(path))
}
pub fn check_ready(j: &Journal) -> io::Result<()> {
    let Some(parent) = checked_path(j, &j.boot_id)? else {
        return Err(io::Error::other("missing runtime cgroup"));
    };
    checked_dir(&parent.join("ops"))?;
    let path = operation_cgroup_path(
        &j.runtime_identity(),
        &j.current.owner_id,
        j.generation,
        &j.tx_id,
    )?;
    checked_dir(&path)?;
    let _ = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("cgroup.procs"))?;
    let _ = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("cgroup.kill"))?;
    let mut events = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("cgroup.events"))?
        .take(4096)
        .read_to_string(&mut events)?;
    if !events.lines().any(|line| line == "populated 0") {
        return Err(io::Error::other("operation cgroup not empty before READY"));
    }
    Ok(())
}
pub fn quiesce(j: &Journal, boot: &str) -> io::Result<()> {
    quiesce_identity(&j.runtime_identity(), boot)
}
pub fn quiesce_identity(
    identity: &xkeenwrt_recovery::RuntimeIncarnationIdentity,
    boot: &str,
) -> io::Result<()> {
    let root = Path::new("/sys/fs/cgroup");
    let path = runtime_incarnation_path(identity)?;
    if !path.exists() && identity.boot_id != boot {
        return Ok(());
    }
    for dir in [
        root.to_path_buf(),
        root.join("xkeenwrt"),
        root.join("xkeenwrt/incarnations"),
        path.clone(),
    ] {
        checked_dir(&dir)?;
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    use std::os::fd::AsRawFd;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    crate::supervisor::quiesce_pinned(&dir)
}
/// Fixed group for procd-spawned core-run wrappers; no path is accepted from a journal.
pub fn ensure_core_group() -> io::Result<PathBuf> {
    use std::ffi::CString;
    let root = Path::new("/sys/fs/cgroup");
    let croot = CString::new(root.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(croot.as_ptr(), &mut stat) } != 0 || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    checked_dir(root)?;
    let parent = root.join("xkeenwrt");
    let core = parent.join("core");
    for dir in [&parent, &core] {
        crate::supervisor::ensure_private_group(dir, true)?;
    }
    Ok(core)
}
pub fn quiesce_core() -> io::Result<()> {
    let path = ensure_core_group()?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    crate::supervisor::quiesce_pinned(&dir)
}

/// Apply fixed core limits only after the old core has been stopped and the
/// operation grant revoked. Read back every kernfs value before launch.
pub fn configure_core_limits() -> io::Result<()> {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    let path = ensure_core_group()?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("invalid core cgroup"));
    }
    fn file(dir: &std::fs::File, name: &std::ffi::CStr, flags: i32) -> io::Result<std::fs::File> {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
    }
    let mut events = String::new();
    file(&dir, c"cgroup.events", libc::O_RDONLY)?
        .take(4096)
        .read_to_string(&mut events)?;
    if !events.lines().any(|line| line == "populated 0") {
        return Err(io::Error::other("core cgroup not empty"));
    }
    for (name, value) in xkeenwrt_recovery::CORE_CGROUP_LIMITS {
        let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
        file(&dir, &name, libc::O_WRONLY)?.write_all(value.as_bytes())?;
        let mut actual = String::new();
        file(&dir, &name, libc::O_RDONLY)?
            .take(128)
            .read_to_string(&mut actual)?;
        if actual.trim() != value {
            return Err(io::Error::other("core cgroup limit mismatch"));
        }
    }
    Ok(())
}
