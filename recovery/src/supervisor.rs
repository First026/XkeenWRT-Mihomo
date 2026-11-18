//! Single supervisor ownership and pre-lock orphan-child quiescence.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};
use xkeenwrt_recovery::{MutationLock, SupervisorIdentity as Identity, supervisor_cgroup_path};
const IDENTITY: &str = "/var/run/xkeenwrt/supervisor.json";
fn read_identity() -> io::Result<Option<Identity>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(IDENTITY)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 4096
    {
        return Err(io::Error::other("unsafe supervisor identity"));
    }
    let mut data = Vec::new();
    f.take(4097).read_to_end(&mut data)?;
    if data.len() > 4096 {
        return Err(io::Error::other("supervisor identity too large"));
    }
    let id: Identity = serde_json::from_slice(&data).map_err(io::Error::other)?;
    if !id.valid() || supervisor_cgroup_path(&id.owner_id, &id.nonce).is_err() {
        return Err(io::Error::other("invalid supervisor identity"));
    }
    Ok(Some(id))
}
fn open_group(path: &Path) -> io::Result<Option<File>> {
    let dir = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = dir.metadata()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
        || unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("unsafe recovery cgroup"));
    }
    Ok(Some(dir))
}
fn at(dir: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn quiesce_pinned(dir: &File) -> io::Result<()> {
    let mut kill = at(dir, c"cgroup.kill", libc::O_WRONLY | libc::O_NONBLOCK)?;
    kill.write_all(b"1\n")?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let mut events = String::new();
        at(dir, c"cgroup.events", libc::O_RDONLY | libc::O_NONBLOCK)?
            .take(4096)
            .read_to_string(&mut events)?;
        if events.lines().any(|v| v == "populated 0") {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "old supervisor cgroup populated",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn private_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe recovery cgroup parent"));
    }
    Ok(())
}
pub(crate) fn ensure_private_group(path: &Path, existing_ok: bool) -> io::Result<()> {
    let created = match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(e) if existing_ok && e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e),
    };
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let m = dir.metadata()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if !m.is_dir()
        || m.uid() != 0
        || unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("unsafe recovery cgroup"));
    }
    if created && unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if dir.metadata()?.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe recovery cgroup mode"));
    }
    Ok(())
}
/// Create a private one-shot command group for an authenticated recovery CLI
/// operation that runs outside the long-lived supervisor service.
pub(crate) fn command_group(owner: &str) -> io::Result<File> {
    let root = Path::new("/sys/fs/cgroup");
    private_dir(root)?;
    let root_fd = File::open(root)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root_fd.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    ensure_private_group(&root.join("xkeenwrt"), true)?;
    ensure_private_group(&root.join("xkeenwrt/recovery"), true)?;
    let path = xkeenwrt_recovery::supervisor_cgroup_path(owner, &crate::core::fresh_nonce()?)?;
    ensure_private_group(&path, false)?;
    open_group(&path)?.ok_or_else(|| io::Error::other("missing command cgroup"))
}
fn store_identity(id: &Identity) -> io::Result<()> {
    let temp = format!("/var/run/xkeenwrt/.supervisor-{}", id.nonce);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        serde_json::to_writer(&mut f, id).map_err(io::Error::other)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&temp, IDENTITY)?;
        File::open("/var/run/xkeenwrt")?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn running_rescue_digest() -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let dir = Path::new("/etc/xkeenwrt/rescue");
    let dm = fs::symlink_metadata(dir)?;
    if !dm.is_dir() || dm.uid() != 0 || dm.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe rescue directory"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("xkeenwrt-recovery"))?;
    let meta = file.metadata()?;
    let running = fs::metadata("/proc/self/exe")?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
        || meta.nlink() != 1
        || meta.len() == 0
        || meta.len() > 64 * 1024 * 1024
        || meta.dev() != running.dev()
        || meta.ino() != running.ino()
    {
        return Err(io::Error::other("supervisor is not persistent rescue"));
    }
    let mut sha = Sha256::new();
    let mut bytes = [0u8; 16384];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        sha.update(&bytes[..n]);
    }
    Ok(sha.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
pub fn acquire(owner: &str, boot: &str) -> io::Result<(MutationLock, File, Identity)> {
    let root = Path::new("/sys/fs/cgroup");
    private_dir(root)?;
    let root_fd = File::open(root)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root_fd.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    // The old group is pinned before lock acquisition and keyed by a unique nonce.
    // A concurrent new supervisor can never reuse that pinned group.
    if let Some(old) = read_identity()? {
        if old.owner_id != owner {
            return Err(io::Error::other("supervisor owner mismatch"));
        }
        if old.boot_id == boot {
            let group = open_group(&supervisor_cgroup_path(&old.owner_id, &old.nonce)?)?;
            if read_identity()?.as_ref() != Some(&old) {
                return Err(io::Error::other("supervisor identity changed"));
            }
            if crate::process_identity(old.pid)?
                .is_some_and(|(state, start)| state != "Z" && start == old.starttime)
            {
                return Err(io::Error::other("supervisor already running"));
            }
            if let Some(group) = group {
                quiesce_pinned(&group)?;
            }
        }
    }
    let lock = MutationLock::acquire(Path::new("/var/run/xkeenwrt/recovery.lock"), Duration::ZERO)?;
    ensure_private_group(&root.join("xkeenwrt"), true)?;
    ensure_private_group(&root.join("xkeenwrt/recovery"), true)?;
    let nonce = crate::core::fresh_nonce()?;
    let path = supervisor_cgroup_path(owner, &nonce)?;
    ensure_private_group(&path, false)?;
    let group =
        open_group(&path)?.ok_or_else(|| io::Error::other("missing new supervisor group"))?;
    let pid = std::process::id();
    let (_, starttime) = crate::process_identity(pid)?
        .ok_or_else(|| io::Error::other("missing supervisor process"))?;
    let id = Identity {
        version: 1,
        exe_sha256: running_rescue_digest()?,
        owner_id: owner.to_owned(),
        nonce,
        pid,
        starttime,
        boot_id: boot.to_owned(),
    };
    store_identity(&id)?;
    Ok((lock, group, id))
}

/// A successful leaf process is insufficient if descendants still exist.
pub fn ensure_quiescent(dir: &File) -> io::Result<()> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let mut events = String::new();
        at(dir, c"cgroup.events", libc::O_RDONLY | libc::O_NONBLOCK)?
            .take(4096)
            .read_to_string(&mut events)?;
        if events.lines().any(|v| v == "populated 0") {
            return Ok(());
        }
        if Instant::now() >= until {
            quiesce_pinned(dir)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "recovery child descendants persisted",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Called under this process's supervisor lock only after its child group is empty.
pub fn retire_current() -> io::Result<()> {
    let id = read_identity()?.ok_or_else(|| io::Error::other("missing supervisor identity"))?;
    let current = crate::process_identity(std::process::id())?
        .ok_or_else(|| io::Error::other("missing current process"))?;
    if id.pid != std::process::id() || id.starttime != current.1 {
        return Err(io::Error::other("supervisor identity changed"));
    }
    fs::remove_file(IDENTITY)?;
    File::open("/var/run/xkeenwrt")?.sync_all()
}
