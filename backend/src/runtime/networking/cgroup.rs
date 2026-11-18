//! Creation of private per-transaction cgroup-v2 scopes.
//! Called only on the isolated OpenWrt target before publishing pending.
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

fn checked_dir(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe cgroup directory",
        ));
    }
    Ok(())
}
fn open_procs(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path.join("cgroup.procs"))?;
    let metadata = file.metadata()?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_file()
        || metadata.uid() != 0
        || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid cgroup.procs"));
    }
    Ok(file)
}

/// Create the fresh operation scope underneath the verified runtime incarnation.
pub fn create(
    identity: &xkeenwrt_recovery::RuntimeIncarnationIdentity, owner: &str, generation: u64, tx: &str,
) -> io::Result<File> {
    let operation = xkeenwrt_recovery::operation_cgroup_path(identity, owner, generation, tx)?;
    let incarnation = xkeenwrt_recovery::runtime_incarnation_path(identity)?;
    let root = Path::new("/sys/fs/cgroup");
    checked_dir(root)?;
    for path in [
        root.join("xkeenwrt"),
        root.join("xkeenwrt/incarnations"),
        incarnation.clone(),
        incarnation.join("ops"),
    ] {
        checked_dir(&path)?;
        if fs::symlink_metadata(&path)?.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owned cgroup directory",
            ));
        }
    }
    let root_fd = File::open(root)?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstatfs(root_fd.as_raw_fd(), &mut stat) } != 0 || stat.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    fs::DirBuilder::new().mode(0o700).create(&operation)?;
    super::incarnation::privatize_new_dir(&operation)?;
    checked_dir(&operation)?;
    if fs::symlink_metadata(&operation)?.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe operation cgroup directory",
        ));
    }
    let _operation_procs = open_procs(&operation)?;
    let operation_dir = File::open(&operation)?;
    let metadata = operation_dir.metadata()?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_dir()
        || metadata.uid() != 0
        || unsafe { nix::libc::fstatfs(operation_dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(io::Error::other("invalid operation cgroup directory"));
    }
    Ok(operation_dir)
}

/// Reattach to the exact operation scope that owns a still-pending journal.
/// No directory is created and the durable transaction identity selects the path.
pub fn open(
    identity: &xkeenwrt_recovery::RuntimeIncarnationIdentity, owner: &str, generation: u64, tx: &str,
) -> io::Result<File> {
    let operation = xkeenwrt_recovery::operation_cgroup_path(identity, owner, generation, tx)?;
    let incarnation = xkeenwrt_recovery::runtime_incarnation_path(identity)?;
    let root = Path::new("/sys/fs/cgroup");
    let root_fd = File::open(root)?;
    let mut root_stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstatfs(root_fd.as_raw_fd(), &mut root_stat) } != 0
        || root_stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    for path in [
        root.join("xkeenwrt"),
        root.join("xkeenwrt/incarnations"),
        incarnation.clone(),
        incarnation.join("ops"),
        operation.clone(),
    ] {
        checked_dir(&path)?;
        if fs::symlink_metadata(&path)?.mode() & 0o777 != 0o700 {
            return Err(io::Error::other("unsafe owned cgroup directory"));
        }
    }
    let _procs = open_procs(&operation)?;
    let directory = File::open(&operation)?;
    let metadata = directory.metadata()?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_dir()
        || metadata.uid() != 0
        || unsafe { nix::libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(io::Error::other("invalid operation cgroup directory"));
    }
    Ok(directory)
}

/// A missing old operation scope is safe only because cgroup v2 cannot remove
/// a populated group; otherwise require a verified, empty scope.
pub fn old_operation_empty(journal: &xkeenwrt_recovery::Journal) -> io::Result<bool> {
    use std::io::Read;
    let incarnation = journal.runtime_identity();
    let path = xkeenwrt_recovery::operation_cgroup_path(
        &incarnation,
        &journal.current.owner_id,
        journal.generation,
        &journal.tx_id,
    )?;
    let root = Path::new("/sys/fs/cgroup");
    checked_dir(root)?;
    let root_fd = File::open(root)?;
    let mut root_stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstatfs(root_fd.as_raw_fd(), &mut root_stat) } != 0
        || root_stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(io::Error::other("cgroup v2 unavailable"));
    }
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
        Ok(_) => (),
    }
    let inc = xkeenwrt_recovery::runtime_incarnation_path(&incarnation)?;
    for dir in [
        root.join("xkeenwrt"),
        root.join("xkeenwrt/incarnations"),
        inc.clone(),
        inc.join("ops"),
        path.clone(),
    ] {
        checked_dir(&dir)?;
        if fs::symlink_metadata(&dir)?.mode() & 0o777 != 0o700 {
            return Err(io::Error::other("unsafe old cgroup"));
        }
    }
    let dir = File::open(&path)?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0 || stat.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other("invalid old cgroup"));
    }
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
    let populated: Vec<_> = events.lines().filter(|l| l.starts_with("populated ")).collect();
    match populated.as_slice() {
        ["populated 0"] => Ok(true),
        ["populated 1"] => Ok(false),
        _ => Err(io::Error::other("invalid cgroup events")),
    }
}
