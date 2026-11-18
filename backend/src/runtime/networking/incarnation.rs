//! Recover stale runtime children before reacquiring the lifetime runtime lock.
//! No child process may be spawned until this object has been constructed.
use crate::runtime::{ipc::RuntimeLock, networking::helper};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};
use xkeenwrt_recovery::{RuntimeIncarnationIdentity, runtime_incarnation_path};

const RUN: &str = "/var/run/xkeenwrt";
const CG: &str = "/sys/fs/cgroup";
const CGROUP2: u64 = 0x6367_7270;

pub struct RuntimeIncarnation {
    _runtime_lock: RuntimeLock,
    dir: File,
    identity: RuntimeIncarnationIdentity,
}
impl RuntimeIncarnation {
    pub fn dir(&self) -> &File {
        &self.dir
    }
    pub fn identity(&self) -> &RuntimeIncarnationIdentity {
        &self.identity
    }
    /// Requires the private run directory already created by runtime bootstrap.
    pub fn acquire() -> io::Result<Self> {
        checked_dir(Path::new(RUN))?;
        if fs::symlink_metadata(RUN)?.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime directory must be private",
            ));
        }
        let _bootstrap = RuntimeLock::acquire(&Path::new(RUN).join("runtime-bootstrap.lock"))?;
        let boot = current_boot()?;
        check_cgroup_root()?;
        if let Some(previous) = read_identity()? {
            if previous.boot_id == boot && process_still_matches(&previous)? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "previous runtime is still alive",
                ));
            }
            quiesce(&previous)?;
        }
        let runtime_lock = RuntimeLock::acquire(&Path::new(RUN).join("runtime.lock"))?;
        let (pid, starttime) = helper::current_runtime_identity()?;
        let identity = RuntimeIncarnationIdentity {
            version: 1,
            boot_id: boot,
            pid,
            starttime,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let root = Path::new(CG);
        ensure_dir(&root.join("xkeenwrt"))?;
        ensure_dir(&root.join("xkeenwrt/incarnations"))?;
        let path = runtime_incarnation_path(&identity)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        privatize_new_dir(&path)?;
        checked_owned_dir(&path)?;
        ensure_dir(&path.join("ops"))?;
        let dir = File::open(&path)?;
        verify_cgroup_fd(&dir)?;
        publish_identity(&identity)?;
        Ok(Self {
            _runtime_lock: runtime_lock,
            dir,
            identity,
        })
    }
}
fn checked_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe runtime directory",
        ));
    }
    Ok(())
}
fn checked_owned_dir(path: &Path) -> io::Result<()> {
    checked_dir(path)?;
    if fs::symlink_metadata(path)?.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe owned cgroup directory",
        ));
    }
    Ok(())
}
/// Only for a directory just created by this process. The opened inode is
/// verified before chmod and compared with the path again afterward.
pub(crate) fn privatize_new_dir(path: &Path) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(path)?;
    verify_cgroup_fd(&f)?;
    let before = f.metadata()?;
    if unsafe { nix::libc::fchmod(f.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let after = f.metadata()?;
    let by_path = fs::symlink_metadata(path)?;
    if !by_path.is_dir()
        || by_path.file_type().is_symlink()
        || by_path.dev() != before.dev()
        || by_path.ino() != before.ino()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != 0
        || after.mode() & 0o777 != 0o700
    {
        return Err(io::Error::other("created cgroup identity changed"));
    }
    Ok(())
}
fn ensure_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => privatize_new_dir(path)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    checked_owned_dir(path)
}

fn verify_cgroup_fd(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    let mut fs: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !m.is_dir()
        || m.uid() != 0
        || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0
        || fs.f_type as u64 != CGROUP2
    {
        return Err(io::Error::other("invalid cgroup directory"));
    }
    Ok(())
}
fn check_cgroup_root() -> io::Result<()> {
    checked_dir(Path::new(CG))?;
    verify_cgroup_fd(&File::open(CG)?)
}
fn current_boot() -> io::Result<String> {
    let mut s = String::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(128)
        .read_to_string(&mut s)?;
    let s = s.trim();
    let id = uuid::Uuid::parse_str(s).map_err(io::Error::other)?;
    if id.to_string() != s {
        return Err(io::Error::other("invalid boot id"));
    }
    Ok(s.to_owned())
}
fn read_identity() -> io::Result<Option<RuntimeIncarnationIdentity>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(Path::new(RUN).join("incarnation.json"))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 4096 {
        return Err(io::Error::other("unsafe runtime identity"));
    }
    let mut data = Vec::new();
    file.take(4097).read_to_end(&mut data)?;
    if data.len() > 4096 {
        return Err(io::Error::other("oversized runtime identity"));
    }
    let identity: RuntimeIncarnationIdentity = serde_json::from_slice(&data).map_err(io::Error::other)?;
    let _ = runtime_incarnation_path(&identity)?;
    Ok(Some(identity))
}
fn process_still_matches(identity: &RuntimeIncarnationIdentity) -> io::Result<bool> {
    let f = match File::open(format!("/proc/{}/stat", identity.pid)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut stat = String::new();
    f.take(4097).read_to_string(&mut stat)?;
    let (pid, start) = helper::runtime_identity_from_stat(&stat)?;
    if pid != identity.pid {
        return Err(io::Error::other("ambiguous process identity"));
    }
    if start != identity.starttime {
        return Ok(false);
    }
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid process stat"))?;
    let state = stat[end + 1..]
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("missing process state"))?;
    Ok(!["Z", "X", "x"].contains(&state))
}
fn quiesce(identity: &RuntimeIncarnationIdentity) -> io::Result<()> {
    let path = runtime_incarnation_path(identity)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => (),
    }
    checked_dir(Path::new(CG))?;
    for p in [
        Path::new(CG).join("xkeenwrt"),
        Path::new(CG).join("xkeenwrt/incarnations"),
        path.clone(),
    ] {
        checked_owned_dir(&p)?;
    }
    verify_cgroup_fd(&File::open(&path)?)?;
    let mut kill = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path.join("cgroup.kill"))?;
    kill.write_all(b"1\n")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut events = String::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(path.join("cgroup.events"))?
            .take(4097)
            .read_to_string(&mut events)?;
        if events.len() > 4096 {
            return Err(io::Error::other("oversized cgroup events"));
        }
        let populated: Vec<_> = events.lines().filter(|line| line.starts_with("populated ")).collect();
        if populated == ["populated 0"] {
            return Ok(());
        }
        if populated != ["populated 1"] {
            return Err(io::Error::other("invalid cgroup population"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "stale cgroup still populated"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn publish_identity(identity: &RuntimeIncarnationIdentity) -> io::Result<()> {
    let dir = Path::new(RUN);
    let temp = dir.join(format!(".incarnation-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        serde_json::to_writer(&mut f, identity).map_err(io::Error::other)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&temp, dir.join("incarnation.json"))?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
