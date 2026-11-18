//! Readiness marker validation; caller obtains pid independently from procd.
use serde::Deserialize;
use std::{
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub use xkeenwrt_recovery::SupervisorIdentity;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyMarker {
    version: u32,
    owner_id: String,
    boot_id: String,
    pid: u32,
    starttime: u64,
    nonce: String,
    exe_sha256: String,
    tx_id: String,
    generation: u64,
}
fn read_private_marker<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe recovery marker",
        ));
    }
    let mut bytes = Vec::new();
    f.take(2049).read_to_end(&mut bytes)?;
    if bytes.len() > 2048 {
        return Err(io::Error::other("oversized recovery marker"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
pub fn read_idle(path: &Path) -> io::Result<SupervisorIdentity> {
    read_private_marker(path)
}
pub(crate) fn read_registration(path: &Path) -> io::Result<SupervisorIdentity> {
    read_private_marker(path)
}
/// Require the exact supervisor incarnation observed idle before pending.
pub fn ready_matches(path: &Path, tx_id: &str, generation: u64, supervisor: &SupervisorIdentity) -> io::Result<bool> {
    let m: ReadyMarker = read_private_marker(path)?;
    Ok(m.version == 1
        && supervisor.version == 1
        && generation > 0
        && m.tx_id == tx_id
        && m.generation == generation
        && m.owner_id == supervisor.owner_id
        && m.boot_id == supervisor.boot_id
        && m.pid == supervisor.pid
        && m.starttime == supervisor.starttime
        && m.nonce == supervisor.nonce
        && m.exe_sha256 == supervisor.exe_sha256)
}
/// Exact sole persistent rescue service instance.
pub fn procd_pid(input: &[u8]) -> io::Result<u32> {
    if input.len() > 1_048_576 {
        return Err(io::Error::other("oversized procd response"));
    }
    let root: serde_json::Value = serde_json::from_slice(input).map_err(io::Error::other)?;
    let instances = root
        .get("xkeenwrt-rescue")
        .and_then(|s| s.get("instances"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| io::Error::other("missing rescue instance"))?;
    if instances.len() != 1 {
        return Err(io::Error::other("ambiguous rescue instances"));
    }
    let instance = instances
        .values()
        .next()
        .ok_or_else(|| io::Error::other("missing rescue instance"))?;
    let command = instance
        .get("command")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::other("missing rescue command"))?;
    if instance.get("running").and_then(serde_json::Value::as_bool) != Some(true)
        || command.len() != 2
        || command[0].as_str() != Some("/etc/xkeenwrt/rescue/xkeenwrt-recovery")
        || command[1].as_str() != Some("supervise")
    {
        return Err(io::Error::other("unexpected rescue instance"));
    }
    instance
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p > 1)
        .ok_or_else(|| io::Error::other("invalid rescue pid"))
}
/// Verify marker against the fixed procd instance, kernel PID/starttime and a
/// package-verified persistent rescue executable, never against marker alone.
pub(crate) fn verify_supervisor(
    id: &SupervisorIdentity, expected_owner: &str, expected_boot: &str, cgroup: &std::fs::File,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if !id.valid() || id.owner_id != expected_owner || id.boot_id != expected_boot || id.pid <= 1 || id.starttime == 0 {
        return Err(io::Error::other("rescue identity mismatch"));
    }
    let nonce = uuid::Uuid::parse_str(&id.nonce).map_err(io::Error::other)?;
    if nonce.to_string() != id.nonce {
        return Err(io::Error::other("invalid rescue nonce"));
    }
    let registration: SupervisorIdentity = read_private_marker(Path::new("/var/run/xkeenwrt/supervisor.json"))?;
    if &registration != id {
        return Err(io::Error::other("rescue registration mismatch"));
    }
    let procd = super::read::query(super::read::Query::RecoveryService, cgroup)?;
    if procd_pid(&procd)? != id.pid {
        return Err(io::Error::other("rescue procd identity mismatch"));
    }
    let f = std::fs::File::open(format!("/proc/{}/stat", id.pid))?;
    let mut stat = String::new();
    f.take(4097).read_to_string(&mut stat)?;
    if runtime_identity_from_stat(&stat)? != (id.pid, id.starttime) {
        return Err(io::Error::other("rescue process changed"));
    }
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid rescue process"))?;
    if stat[end + 1..]
        .split_ascii_whitespace()
        .next()
        .is_none_or(|s| ["Z", "X", "x"].contains(&s))
    {
        return Err(io::Error::other("rescue process unavailable"));
    }
    let (_, digest, build_id) = crate::platform::Platform::verified_recovery(cgroup.as_raw_fd())
        .ok_or_else(|| io::Error::other("rescue package unavailable"))?;
    if digest != id.exe_sha256 {
        return Err(io::Error::other("rescue digest mismatch"));
    }
    let expected = xkeenwrt_recovery::rescue::verify(&digest, build_id)?;
    let running = std::fs::File::open(format!("/proc/{}/exe", id.pid))?;
    let a = expected.metadata()?;
    let b = running.metadata()?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(io::Error::other("rescue executable mismatch"));
    }
    let registration_after: SupervisorIdentity = read_private_marker(Path::new("/var/run/xkeenwrt/supervisor.json"))?;
    let mut stat_after = String::new();
    std::fs::File::open(format!("/proc/{}/stat", id.pid))?
        .take(4097)
        .read_to_string(&mut stat_after)?;
    let procd_after = super::read::query(super::read::Query::RecoveryService, cgroup)?;
    if &registration_after != id
        || runtime_identity_from_stat(&stat_after)? != (id.pid, id.starttime)
        || procd_pid(&procd_after)? != id.pid
    {
        return Err(io::Error::other("rescue identity changed"));
    }
    Ok(())
}

/// A fence existing in the private run directory always revokes the generation,
/// even if its contents are malformed. Caller also checks the durable journal.
pub fn generation_unfenced(generation: u64) -> io::Result<bool> {
    if generation == 0 {
        return Err(io::Error::other("invalid generation"));
    }
    let dir = std::fs::symlink_metadata("/var/run/xkeenwrt")?;
    if !dir.is_dir() || dir.file_type().is_symlink() || dir.uid() != 0 || dir.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe recovery directory",
        ));
    }
    let path = format!("/var/run/xkeenwrt/revoked-{generation}");
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

/// Start only the fixed procd recovery service. The launcher child is contained
/// in the previously verified operation cgroup; the service remains independent.
pub fn start(cgroup_dir: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
    let ok = xkeenwrt_recovery::run_fixed_in_cgroup(
        xkeenwrt_recovery::FixedProgram::RescueInit,
        &["start".to_owned()],
        cgroup_dir.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        std::time::Duration::from_secs(3),
    )?;
    if ok {
        Ok(())
    } else {
        Err(io::Error::other("recovery start failed"))
    }
}

/// Parse process identity without assuming that the parenthesized comm field
/// lacks spaces or parentheses. Field 22 is kernel starttime, not wall clock.
pub fn runtime_identity_from_stat(stat: &str) -> io::Result<(u32, u64)> {
    if stat.len() > 4096 {
        return Err(io::Error::other("oversized process stat"));
    }
    let (pid, rest) = stat
        .split_once(' ')
        .ok_or_else(|| io::Error::other("invalid process stat"))?;
    let pid: u32 = pid.parse().map_err(io::Error::other)?;
    if pid <= 1 || !rest.starts_with('(') {
        return Err(io::Error::other("invalid runtime pid"));
    }
    let end = rest
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid process comm"))?;
    let fields: Vec<_> = rest[end + 1..].split_ascii_whitespace().collect();
    let starttime: u64 = fields
        .get(19)
        .ok_or_else(|| io::Error::other("missing process starttime"))?
        .parse()
        .map_err(io::Error::other)?;
    if starttime == 0 {
        return Err(io::Error::other("invalid process starttime"));
    }
    Ok((pid, starttime))
}

pub fn current_runtime_identity() -> io::Result<(u32, u64)> {
    let file = std::fs::File::open("/proc/self/stat")?;
    let mut stat = String::new();
    file.take(4097).read_to_string(&mut stat)?;
    let identity = runtime_identity_from_stat(&stat)?;
    if identity.0 != std::process::id() {
        return Err(io::Error::other("runtime identity changed"));
    }
    Ok(identity)
}

/// Resolve the sole procd core instance and verify that its PID currently runs
/// the fixed Mihomo executable. Recheck this identity after reading sockets.
pub(crate) fn core_identity(cgroup: &std::fs::File) -> io::Result<(u32, u64)> {
    let data = super::read::query(super::read::Query::CoreService, cgroup)?;
    let root: serde_json::Value = serde_json::from_slice(&data).map_err(io::Error::other)?;
    let instances = root
        .get("xkeenwrt-core")
        .and_then(|s| s.get("instances"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| io::Error::other("missing core instance"))?;
    if instances.len() != 1 {
        return Err(io::Error::other("ambiguous core instances"));
    }
    let instance = instances
        .values()
        .next()
        .ok_or_else(|| io::Error::other("missing core instance"))?;
    let command = instance
        .get("command")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::other("missing core command"))?;
    if instance.get("running").and_then(serde_json::Value::as_bool) != Some(true)
        || command.len() != 3
        || command[0].as_str() != Some("/usr/bin/xkeenwrt-ui")
        || command[1].as_str() != Some("core-run")
        || !command[2].as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128)
    {
        return Err(io::Error::other("unexpected core instance"));
    }
    let pid = instance
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p > 1)
        .ok_or_else(|| io::Error::other("invalid core pid"))?;
    let (verified_core, _) = mihomo_release::verify_process_exe(pid)?;
    drop(verified_core);
    let f = std::fs::File::open(format!("/proc/{pid}/stat"))?;
    let mut stat = String::new();
    f.take(4097).read_to_string(&mut stat)?;
    let identity = runtime_identity_from_stat(&stat)?;
    if identity.0 != pid {
        return Err(io::Error::other("core identity changed"));
    }
    Ok(identity)
}

pub(crate) fn process_socket_inodes(pid: u32) -> io::Result<Vec<u64>> {
    if pid <= 1 {
        return Err(io::Error::other("invalid core pid"));
    }
    let mut inodes = Vec::new();
    for (count, entry) in std::fs::read_dir(format!("/proc/{pid}/fd"))?.enumerate() {
        if count >= 4096 {
            return Err(io::Error::other("too many core descriptors"));
        }
        let path = std::fs::read_link(entry?.path())?;
        let Some(name) = path.to_str() else {
            return Err(io::Error::other("invalid core descriptor"));
        };
        if let Some(number) = name.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
            let inode: u64 = number.parse().map_err(io::Error::other)?;
            if inode == 0 {
                return Err(io::Error::other("invalid socket inode"));
            }
            inodes.push(inode);
        }
    }
    Ok(inodes)
}
