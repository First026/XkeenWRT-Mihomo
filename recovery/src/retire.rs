//! Explicit clean-install path after the older persistent helper finalized Remove.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use xkeenwrt_recovery::MutationLock;
fn invalid() -> io::Error {
    io::Error::other("finalized Remove clean-install proof unavailable")
}
fn absent(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}
fn deployment_absent() -> io::Result<()> {
    for path in [
        "/etc/init.d/xkeenwrt-ui",
        "/etc/init.d/xkeenwrt-runtime",
        "/etc/init.d/xkeenwrt-core",
        "/etc/init.d/xkeenwrt-recovery",
        "/etc/init.d/xkeenwrt-rescue",
        "/etc/rc.d/S09xkeenwrt-rescue",
        "/etc/rc.d/K91xkeenwrt-rescue",
        "/usr/libexec/xkeenwrt/xkeenwrt-ui",
        "/usr/libexec/xkeenwrt/xkeenwrt-recovery",
        "/usr/share/xkeenwrt/ui-manifest.json",
        "/usr/share/xkeenwrt/core-manifest.json",
    ] {
        if !absent(Path::new(path))? {
            return Err(invalid());
        }
    }
    if !crate::commands::project_services_absent()? {
        return Err(invalid());
    }
    Ok(())
}
fn private_dir(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    Ok(f)
}
fn all_children_stopped() -> io::Result<()> {
    let path = Path::new("/sys/fs/cgroup/xkeenwrt");
    let dir = private_dir(path)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(invalid());
    }
    let mut events = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("cgroup.events"))?
        .take(4097)
        .read_to_string(&mut events)?;
    if events.len() > 4096
        || events
            .lines()
            .filter(|l| l.starts_with("populated "))
            .collect::<Vec<_>>()
            != ["populated 0"]
    {
        return Err(invalid());
    }
    Ok(())
}
fn retired_path(path: &Path, request: &str) -> io::Result<PathBuf> {
    Ok(path.with_file_name(format!(
        "{}-retired-{request}",
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(invalid)?
    )))
}
fn marker(owner: &str, request: &str) -> Vec<u8> {
    format!("xkeenwrt-retired-v1\nowner={owner}\nrequest={request}\n").into_bytes()
}
fn verify_marker(dir: &Path, expected: &[u8]) -> io::Result<()> {
    let _ = private_dir(dir)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("retired-installation"))?;
    let m = f.metadata()?;
    let mut bytes = Vec::new();
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() != expected.len() as u64
    {
        return Err(invalid());
    }
    f.take(expected.len() as u64 + 1).read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(invalid());
    }
    Ok(())
}
fn archive_volatile(path: &Path, owner: &str, request: &str) -> io::Result<()> {
    let target = retired_path(path, request)?;
    let expected = marker(owner, request);
    if absent(path)? {
        return if absent(&target)? {
            Ok(())
        } else {
            verify_marker(&target, &expected)
        };
    }
    if !absent(&target)? {
        return Err(invalid());
    }
    let dir = private_dir(path)?;
    let marker_path = path.join("retired-installation");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&marker_path)
    {
        Ok(mut f) => {
            f.write_all(&expected)?;
            f.sync_all()?;
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => verify_marker(path, &expected)?,
        Err(e) => return Err(e),
    }
    dir.sync_all()?;
    if !xkeenwrt_recovery::publish_noreplace(path, &target)? {
        return Err(invalid());
    }
    File::open(path.parent().ok_or_else(invalid)?)?.sync_all()
}
pub(crate) fn run(request: &str) -> io::Result<()> {
    if let Some(target) =
        xkeenwrt_recovery::retirement::completed_archive(Path::new(crate::DIR), request)?
    {
        println!(
            "Already archived removed installation: {}",
            target.display()
        );
        return Ok(());
    }
    crate::persistent_guard()?;
    let owner = crate::read_owner()?;
    xkeenwrt_recovery::verify_remove_after_integrity_check(Path::new(crate::DIR), &owner, request)?;
    // This operation runs from a detached, checked release ELF. The package
    // payload and all service entry points must already have been removed.
    let run = Path::new("/var/run/xkeenwrt");
    let retired_run = retired_path(run, request)?;
    let lock_root = if absent(run)? {
        verify_marker(&retired_run, &marker(&owner, request))?;
        &retired_run
    } else {
        run
    };
    let _ = private_dir(lock_root)?;
    let _bootstrap = MutationLock::acquire(
        &lock_root.join("runtime-bootstrap.lock"),
        Duration::from_secs(3),
    )?;
    let _runtime = MutationLock::acquire(&lock_root.join("runtime.lock"), Duration::from_secs(3))?;
    let _recovery =
        MutationLock::acquire(&lock_root.join("recovery.lock"), Duration::from_secs(3))?;
    let _mutation =
        MutationLock::acquire(&lock_root.join("mutation.lock"), Duration::from_secs(3))?;
    let group = crate::supervisor::command_group(&owner)?;
    crate::commands::set_cgroup(group.try_clone()?)?;
    let result = (|| {
        deployment_absent()?;
        all_children_stopped()?;
        match xkeenwrt_recovery::read_journal(Path::new(crate::DIR)) {
            Ok(j) => crate::rollback::verify_removed(&j)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                crate::validate_private_file(&Path::new(crate::DIR).join("network-generation"))?;
                if fs::read(Path::new(crate::DIR).join("network-generation"))? != b"0\n"
                    || !crate::rollback::no_project_table()?
                {
                    return Err(invalid());
                }
            }
            Err(e) => return Err(e),
        }
        let grant = lock_root.join("launch.json");
        if !absent(&grant)? {
            crate::validate_private_file(&grant)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&grant)?;
            let mut bytes = Vec::new();
            file.take(1_048_577).read_to_end(&mut bytes)?;
            let grant = serde_json::from_slice::<xkeenwrt_recovery::LaunchGrant>(&bytes)
                .map_err(io::Error::other)?;
            if bytes.len() > 1_048_576 || !grant.valid() || grant.desired_running {
                return Err(invalid());
            }
        }
        deployment_absent()?;
        crate::supervisor::ensure_quiescent(&group)?;
        archive_volatile(Path::new("/tmp/xkeenwrt"), &owner, request)?;
        archive_volatile(run, &owner, request)?;
        let archived = xkeenwrt_recovery::retirement::archive_finalized_remove(
            Path::new(crate::DIR),
            &owner,
            request,
        )?;
        println!("Archived removed installation: {}", archived.display());
        Ok(())
    })();
    crate::supervisor::ensure_quiescent(&group)?;
    result
}
