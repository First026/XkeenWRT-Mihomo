//! Fixed runtime adapter for the two-phase persistent rescue replacement.
//! The caller holds mutation.lock for A/C, but MUST release it during B.
use super::networking::{
    helper,
    read::{self, Query},
};
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};
use xkeenwrt_recovery::{
    RuntimeIncarnationIdentity, SupervisorIdentity,
    rescue::{UpgradeAdapter, UpgradePhase, UpgradeSpec},
    runtime_incarnation_path,
};
const RUN: &str = "/var/run/xkeenwrt";
const DATA: &str = "/etc/xkeenwrt";
const CORE: &str = "/sys/fs/cgroup/xkeenwrt/core";
const RECOVERY: &str = "/sys/fs/cgroup/xkeenwrt/recovery";
const REMOVE_RESUME_READY: &str = "/var/run/xkeenwrt/recovery.remove-ready";
fn bad() -> io::Error {
    io::Error::other("rescue upgrade proof unavailable")
}
pub(crate) fn private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > limit {
        return Err(bad());
    }
    let mut data = Vec::new();
    f.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(bad());
    }
    Ok(data)
}
fn boot() -> io::Result<String> {
    let mut s = String::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(129)
        .read_to_string(&mut s)?;
    let v = s.trim().to_owned();
    if uuid::Uuid::parse_str(&v).map_err(io::Error::other)?.to_string() != v {
        return Err(bad());
    }
    Ok(v)
}
fn group(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    let mut st: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !m.is_dir()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o700
        || unsafe { nix::libc::fstatfs(f.as_raw_fd(), &mut st) } != 0
        || st.f_type as u64 != 0x6367_7270
    {
        return Err(bad());
    }
    Ok(f)
}
fn group_file(dir: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn empty(dir: &File) -> io::Result<bool> {
    let mut s = String::new();
    group_file(dir, c"cgroup.events", nix::libc::O_RDONLY)?
        .take(4097)
        .read_to_string(&mut s)?;
    let matches: Vec<_> = s.lines().filter(|l| l.starts_with("populated ")).collect();
    match matches.as_slice() {
        ["populated 0"] => Ok(true),
        ["populated 1"] => Ok(false),
        _ => Err(bad()),
    }
}
fn recovery_children_empty(parent: &Path, mut is_empty: impl FnMut(&Path) -> io::Result<bool>) -> io::Result<()> {
    for (n, e) in fs::read_dir(parent)?.enumerate() {
        if n >= 128 {
            return Err(bad());
        }
        let e = e?;
        let kind = e.file_type()?;
        if kind.is_file() {
            continue;
        }
        if !kind.is_dir() {
            return Err(bad());
        }
        let name = e.file_name().into_string().map_err(|_| bad())?;
        let (owner, nonce) = name.split_at_checked(36).ok_or_else(bad)?;
        if !nonce.starts_with('-')
            || uuid::Uuid::parse_str(owner).map_err(|_| bad())?.to_string() != owner
            || uuid::Uuid::parse_str(&nonce[1..]).map_err(|_| bad())?.to_string() != nonce[1..]
        {
            return Err(bad());
        }
        if !is_empty(&e.path())? {
            return Err(bad());
        }
    }
    Ok(())
}
fn all_recovery_groups_empty() -> io::Result<()> {
    let parent = Path::new(RECOVERY);
    let verified_parent = group(parent)?;
    let pinned_parent = format!("/proc/self/fd/{}", verified_parent.as_raw_fd());
    recovery_children_empty(Path::new(&pinned_parent), |path| empty(&group(path)?))
}
fn pidfd_exited(fd: i32, timeout_ms: i32) -> io::Result<bool> {
    let mut poll = nix::libc::pollfd {
        fd,
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { nix::libc::poll(&mut poll, 1, timeout_ms) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(false);
    }
    if poll.revents & (nix::libc::POLLIN | nix::libc::POLLHUP) == 0 {
        return Err(bad());
    }
    Ok(true)
}
fn proc_identity(pid: u32) -> io::Result<Option<((u32, u64), bool)>> {
    let file = match File::open(format!("/proc/{pid}/stat")) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut stat = String::new();
    file.take(4097).read_to_string(&mut stat)?;
    if stat.len() > 4096 {
        return Err(bad());
    }
    let state = stat
        .rsplit_once(')')
        .ok_or_else(bad)?
        .1
        .split_whitespace()
        .next()
        .ok_or_else(bad)?;
    Ok(Some((
        helper::runtime_identity_from_stat(&stat)?,
        matches!(state, "Z" | "X" | "x"),
    )))
}
fn exact_live_process(observed: Option<((u32, u64), bool)>, pid: u32, starttime: u64) -> bool {
    observed == Some(((pid, starttime), false))
}
fn service_stopped(input: &[u8], name: &str) -> io::Result<bool> {
    let v: serde_json::Value = serde_json::from_slice(input).map_err(io::Error::other)?;
    let top = v.as_object().ok_or_else(bad)?;
    let Some(s) = top.get(name) else { return Ok(true) };
    let instances = s.get("instances").and_then(|v| v.as_object()).ok_or_else(bad)?;
    if instances.len() > 32 {
        return Err(bad());
    }
    for instance in instances.values() {
        match instance.get("running").and_then(|v| v.as_bool()) {
            Some(false) => (),
            Some(true) => return Ok(false),
            None => return Err(bad()),
        }
    }
    Ok(true)
}
fn ui_stopped_or_current(input: &[u8], verified_backend: &File) -> io::Result<bool> {
    if input.len() > 1_048_576 {
        return Err(bad());
    }
    let root: serde_json::Value = serde_json::from_slice(input).map_err(io::Error::other)?;
    let services = root.as_object().ok_or_else(bad)?;
    let Some(service) = services.get("xkeenwrt-ui") else {
        return Ok(true);
    };
    let instances = service
        .get("instances")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(bad)?;
    if instances.len() > 32 {
        return Err(bad());
    }
    let mut running = Vec::new();
    for instance in instances.values() {
        match instance.get("running").and_then(serde_json::Value::as_bool) {
            Some(false) => (),
            Some(true) => running.push(instance),
            None => return Err(bad()),
        }
    }
    if running.is_empty() {
        return Ok(true);
    }
    if running.len() != 1 || instances.len() != 1 {
        return Ok(false);
    }
    let instance = running[0];
    let command = instance
        .get("command")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(bad)?;
    if command.len() != 2 || command[0].as_str() != Some("/usr/bin/xkeenwrt-ui") || command[1].as_str() != Some("serve")
    {
        return Ok(false);
    }
    let Some(pid) = instance
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p > 1)
    else {
        return Err(bad());
    };
    let before = proc_identity(pid)?;
    let Some((identity, false)) = before else {
        return Ok(false);
    };
    if identity.0 != pid {
        return Ok(false);
    }
    let running_exe = match File::open(format!("/proc/{pid}/exe")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let expected = verified_backend.metadata()?;
    let actual = running_exe.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Ok(false);
    }
    Ok(proc_identity(pid)? == before && exact_live_process(before, identity.0, identity.1))
}
fn no_project_table(raw: &[u8]) -> io::Result<()> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(io::Error::other)?;
    let entries = v.get("nftables").and_then(|v| v.as_array()).ok_or_else(bad)?;
    for e in entries {
        if e.get("table").is_some_and(|t| {
            t.get("family").and_then(|v| v.as_str()) == Some("inet")
                && t.get("name").and_then(|v| v.as_str()) == Some("xkeenwrt")
        }) {
            return Err(bad());
        }
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleReady {
    version: u32,
    request_id: String,
    supervisor: SupervisorIdentity,
}
fn ready_binding(m: &LifecycleReady, spec: &UpgradeSpec, current_boot: &str) -> bool {
    m.version == 1
        && m.request_id == spec.request_id
        && m.supervisor.valid()
        && m.supervisor.owner_id == spec.owner_id
        && m.supervisor.boot_id == current_boot
        && m.supervisor.exe_sha256 == spec.new_sha256
}
/// Cgroup FD and identity must be the runtime's previously authenticated incarnation.
pub(crate) struct NativeUpgradeAdapter<'a> {
    pub(crate) incarnation: &'a File,
    pub(crate) identity: &'a RuntimeIncarnationIdentity,
}
impl NativeUpgradeAdapter<'_> {
    fn query(&self, q: Query) -> io::Result<Vec<u8>> {
        let v = read::query(q, self.incarnation)?;
        if !empty(self.incarnation)? {
            return Err(bad());
        }
        Ok(v)
    }
    fn ready(&self, new: &File, spec: &UpgradeSpec) -> io::Result<()> {
        if !spec.valid() {
            return Err(bad());
        }
        let verified = xkeenwrt_recovery::rescue::verify(&spec.new_sha256, &spec.new_build_id)?;
        let expected = verified.metadata()?;
        let supplied = new.metadata()?;
        if expected.dev() != supplied.dev() || expected.ino() != supplied.ino() {
            return Err(bad());
        }
        let m: LifecycleReady = serde_json::from_slice(&private(
            Path::new(RUN).join("recovery.lifecycle-ready").as_path(),
            4096,
        )?)
        .map_err(io::Error::other)?;
        let b = boot()?;
        if !ready_binding(&m, spec, &b) {
            return Err(bad());
        }
        helper::verify_supervisor(&m.supervisor, &spec.owner_id, &b, self.incarnation)?;
        let exe = File::open(format!("/proc/{}/exe", m.supervisor.pid))?;
        let a = exe.metadata()?;
        let n = new.metadata()?;
        if a.dev() != n.dev() || a.ino() != n.ino() {
            return Err(bad());
        }
        let again: LifecycleReady = serde_json::from_slice(&private(
            Path::new(RUN).join("recovery.lifecycle-ready").as_path(),
            4096,
        )?)
        .map_err(io::Error::other)?;
        if !ready_binding(&again, spec, &b) || again.supervisor != m.supervisor {
            return Err(bad());
        }
        Ok(())
    }

    fn verify_runtime_identity(&self, owner: &str) -> io::Result<()> {
        if self.identity.pid != std::process::id() || self.identity.boot_id != boot()? {
            return Err(bad());
        }
        let published: RuntimeIncarnationIdentity =
            serde_json::from_slice(&private(&Path::new(RUN).join("incarnation.json"), 4096)?)
                .map_err(io::Error::other)?;
        if &published != self.identity {
            return Err(bad());
        }
        let expected = group(&runtime_incarnation_path(self.identity)?)?;
        let a = expected.metadata()?;
        let b = self.incarnation.metadata()?;
        if a.dev() != b.dev()
            || a.ino() != b.ino()
            || helper::current_runtime_identity()? != (self.identity.pid, self.identity.starttime)
            || !empty(self.incarnation)?
        {
            return Err(bad());
        }
        if private(&Path::new(DATA).join("owner-id"), 128)? != owner.as_bytes() {
            return Err(bad());
        }
        Ok(())
    }

    /// Shared strict quiescence proof used by both lifecycle protocols. Each
    /// caller verifies its own typed receipt before entering this check.
    fn verify_quiescent_runtime(&self, owner: &str) -> io::Result<()> {
        if !empty(&group(Path::new(CORE))?)? || !service_stopped(&self.query(Query::CoreService)?, "xkeenwrt-core")? {
            return Err(bad());
        }
        let Some(verified_backend) = crate::platform::Platform::verified_component(
            crate::platform::VerifiedComponent::Ui,
            Some(self.incarnation.as_raw_fd()),
        ) else {
            return Err(bad());
        };
        if !ui_stopped_or_current(&self.query(Query::UiService)?, &verified_backend)? {
            return Err(bad());
        }
        match private(Path::new(RUN).join("launch.json").as_path(), 16384) {
            Ok(bytes) => {
                let grant: xkeenwrt_recovery::LaunchGrant = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if !grant.valid() || grant.desired_running {
                    return Err(bad());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let nft = self.query(Query::NftRuleset)?;
        no_project_table(&nft)?;
        match private(&Path::new(DATA).join("recovery.json"), 1_048_576) {
            Ok(bytes) => {
                let j: xkeenwrt_recovery::Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if j.decision(&j.boot_id, j.created_boottime_ms, false) == xkeenwrt_recovery::Decision::Invalid
                    || j.current.owner_id != owner
                    || j.state != xkeenwrt_recovery::State::Disabled
                {
                    return Err(bad());
                }
                let r4 = self.query(Query::Rules4)?;
                let r6 = self.query(Query::Rules6)?;
                let t4 = self.query(Query::Routes4)?;
                let t6 = self.query(Query::Routes6)?;
                xkeenwrt_recovery::evidence::resources_absent(&j.current, &nft, &r4, &r6, &t4, &t6)?;
                if let Some(p) = &j.previous_good {
                    xkeenwrt_recovery::evidence::resources_absent(p, &nft, &r4, &r6, &t4, &t6)?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !super::networking::identity::never_enabled_present(Path::new(DATA))?
                    || private(&Path::new(DATA).join("network-generation"), 32)? != b"0\n"
                {
                    return Err(bad());
                }
            }
            Err(e) => return Err(e),
        }
        all_recovery_groups_empty()?;
        if !empty(self.incarnation)? {
            return Err(bad());
        }
        Ok(())
    }

    pub(crate) fn verify_remove_resume_quiescent(&self, owner: &str, request_id: &str) -> io::Result<()> {
        self.verify_runtime_identity(owner)?;
        xkeenwrt_recovery::verify_remove_after_integrity_check(Path::new(DATA), owner, request_id)?;
        if xkeenwrt_recovery::rescue::upgrade_status()?.is_some()
            || !matches!(fs::symlink_metadata(Path::new(DATA).join("lifecycle.json")), Err(e) if e.kind() == io::ErrorKind::NotFound)
            || !matches!(fs::symlink_metadata(Path::new(DATA).join(".rescue-next")), Err(e) if e.kind() == io::ErrorKind::NotFound)
        {
            return Err(bad());
        }
        self.verify_quiescent_runtime(owner)
    }

    pub(crate) fn verify_remove_resume_ready(
        &self, owner: &str, request_id: &str, package_helper: &File, persistent_helper: &File, helper_sha256: &str,
        helper_build_id: &str,
    ) -> io::Result<()> {
        let Some((installed_helper, digest, build_id)) =
            crate::platform::Platform::verified_recovery(self.incarnation.as_raw_fd())
        else {
            return Err(bad());
        };
        let installed_meta = installed_helper.metadata()?;
        let package_meta = package_helper.metadata()?;
        if digest != helper_sha256
            || build_id != helper_build_id
            || installed_meta.dev() != package_meta.dev()
            || installed_meta.ino() != package_meta.ino()
        {
            return Err(bad());
        }
        let persistent_again = xkeenwrt_recovery::rescue::verify(helper_sha256, helper_build_id)?;
        let persistent_meta = persistent_again.metadata()?;
        let pinned_meta = persistent_helper.metadata()?;
        if persistent_meta.dev() != pinned_meta.dev() || persistent_meta.ino() != pinned_meta.ino() {
            return Err(bad());
        }
        let current_boot = boot()?;
        let marker: xkeenwrt_recovery::RemoveResumeReady =
            serde_json::from_slice(&private(Path::new(REMOVE_RESUME_READY), 4096)?).map_err(io::Error::other)?;
        if !marker.valid_for(owner, request_id, &current_boot, helper_sha256) {
            return Err(bad());
        }
        helper::verify_supervisor(&marker.supervisor, owner, &current_boot, self.incarnation)?;
        let running_exe = File::open(format!("/proc/{}/exe", marker.supervisor.pid))?;
        let expected = persistent_helper.metadata()?;
        let actual = running_exe.metadata()?;
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err(bad());
        }
        let again: xkeenwrt_recovery::RemoveResumeReady =
            serde_json::from_slice(&private(Path::new(REMOVE_RESUME_READY), 4096)?).map_err(io::Error::other)?;
        if again != marker {
            return Err(bad());
        }
        Ok(())
    }

    pub(crate) fn wait_remove_resume_ready(
        &self, owner: &str, request_id: &str, package_helper: &File, persistent_helper: &File, helper_sha256: &str,
        helper_build_id: &str,
    ) -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match self.verify_remove_resume_ready(
                owner,
                request_id,
                package_helper,
                persistent_helper,
                helper_sha256,
                helper_build_id,
            ) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < until => (),
                Err(error) => return Err(error),
            }
            if Instant::now() >= until {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Remove readiness unavailable"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
impl UpgradeAdapter for NativeUpgradeAdapter<'_> {
    fn verify_quiescent(&mut self, spec: &UpgradeSpec) -> io::Result<()> {
        if !spec.valid() {
            return Err(bad());
        }
        self.verify_runtime_identity(&spec.owner_id)?;
        match xkeenwrt_recovery::verify_upgrade_after_integrity_check(Path::new(DATA), &spec.owner_id, &spec.request_id)
        {
            Ok(()) => (),
            Err(_) => {
                let intent = xkeenwrt_recovery::rescue::upgrade_status()?.ok_or_else(bad)?;
                if intent.spec != *spec
                    || intent.phase != UpgradePhase::Finalizing
                    || !matches!(fs::symlink_metadata(Path::new(DATA).join("removal.json")), Err(e) if e.kind()==io::ErrorKind::NotFound)
                {
                    return Err(bad());
                }
            }
        }
        self.verify_quiescent_runtime(&spec.owner_id)
    }
    fn stop_old(&mut self, old: &File, spec: &UpgradeSpec) -> io::Result<()> {
        if !spec.valid() {
            return Err(bad());
        }
        let id = helper::read_idle(Path::new(RUN).join("supervisor.json").as_path())?;
        if !id.valid() || id.owner_id != spec.owner_id || id.boot_id != boot()? {
            return Err(bad());
        }
        if id.exe_sha256 == spec.new_sha256
            && let Some(intent) = xkeenwrt_recovery::rescue::upgrade_status()?
            && intent.spec == *spec
        {
            let new = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open("/etc/xkeenwrt/rescue/xkeenwrt-recovery")?;
            let a = new.metadata()?;
            let b = old.metadata()?;
            if a.dev() != b.dev() || a.ino() != b.ino() {
                self.ready(&new, spec)?;
                all_recovery_groups_empty()?;
                return Ok(());
            }
        }
        if id.exe_sha256 != spec.old_sha256 {
            return Err(bad());
        }
        let current = proc_identity(id.pid)?;
        if exact_live_process(current, id.pid, id.starttime) {
            let exe = File::open(format!("/proc/{}/exe", id.pid))?;
            let a = exe.metadata()?;
            let b = old.metadata()?;
            if a.dev() != b.dev()
                || a.ino() != b.ino()
                || helper::procd_pid(&self.query(Query::RecoveryService)?)? != id.pid
            {
                return Err(bad());
            }
            let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, id.pid, 0) } as i32;
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            use std::os::fd::FromRawFd;
            let pidfd = unsafe { File::from_raw_fd(raw) };
            if !exact_live_process(proc_identity(id.pid)?, id.pid, id.starttime)
                || helper::read_idle(&Path::new(RUN).join("supervisor.json"))? != id
            {
                return Err(bad());
            }
            fixed_delete_rescue(self.incarnation)?;
            if !empty(self.incarnation)? {
                return Err(bad());
            }
            if !pidfd_exited(pidfd.as_raw_fd(), 3000)? {
                if !exact_live_process(proc_identity(id.pid)?, id.pid, id.starttime) {
                    return Err(bad());
                }
                if unsafe {
                    nix::libc::syscall(
                        nix::libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        nix::libc::SIGKILL,
                        0,
                        0,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if !pidfd_exited(pidfd.as_raw_fd(), 3000)? {
                    return Err(bad());
                }
            }
        } else if !service_stopped(&self.query(Query::RecoveryService)?, "xkeenwrt-rescue")? {
            return Err(bad());
        }
        if !service_stopped(&self.query(Query::RecoveryService)?, "xkeenwrt-rescue")? {
            return Err(bad());
        }
        let parent = group(Path::new(RECOVERY))?;
        drop(parent);
        let old_path = xkeenwrt_recovery::supervisor_cgroup_path(&id.owner_id, &id.nonce)?;
        match group(&old_path) {
            Ok(dir) => {
                use std::io::Write;
                group_file(&dir, c"cgroup.kill", nix::libc::O_WRONLY)?.write_all(b"1\n")?;
                let until = Instant::now() + Duration::from_secs(3);
                while !empty(&dir)? {
                    if Instant::now() >= until {
                        return Err(bad());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        all_recovery_groups_empty()?;
        Ok(())
    }
    fn start_new_ready(&mut self, new: &File, spec: &UpgradeSpec) -> io::Result<()> {
        if !spec.valid() {
            return Err(bad());
        }
        if self.ready(new, spec).is_ok() {
            return Ok(());
        }
        helper::start(self.incarnation)?;
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if self.ready(new, spec).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "rescue lifecycle readiness unavailable",
        ))
    }
    fn verify_new_ready(&mut self, new: &File, spec: &UpgradeSpec) -> io::Result<()> {
        self.ready(new, spec)
    }
}
fn fixed_delete_rescue(cgroup: &File) -> io::Result<()> {
    let null = OpenOptions::new().read(true).write(true).open("/dev/null")?;
    let args = ["call", "service", "delete", "{\"name\":\"xkeenwrt-rescue\"}"].map(str::to_owned);
    if !xkeenwrt_recovery::run_fixed_in_cgroup(
        xkeenwrt_recovery::FixedProgram::Ubus,
        &args,
        cgroup.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        Duration::from_secs(3),
    )? {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn temporary_group_dir() -> PathBuf {
        let root = std::env::temp_dir().join(format!("xkeenwrt-recovery-groups-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        root
    }
    fn child_group_name() -> &'static str {
        "00000000-0000-4000-8000-000000000001-00000000-0000-4000-8000-000000000002"
    }
    #[test]
    fn recovery_parent_ignores_regular_control_files_and_checks_child_groups() {
        let root = temporary_group_dir();
        fs::write(root.join("cgroup.events"), "populated 0\n").unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        let child = root.join(child_group_name());
        fs::create_dir(&child).unwrap();
        let mut checked = 0;
        let result = recovery_children_empty(&root, |path| {
            assert_eq!(path, child);
            checked += 1;
            Ok(true)
        });
        fs::remove_dir_all(&root).unwrap();
        assert!(result.is_ok());
        assert_eq!(checked, 1);
    }
    #[test]
    fn recovery_parent_rejects_foreign_child_names_symlinks_and_populated_groups() {
        let foreign_root = temporary_group_dir();
        fs::create_dir(foreign_root.join("foreign-child")).unwrap();
        let foreign = recovery_children_empty(&foreign_root, |_| Ok(true));
        fs::remove_dir_all(&foreign_root).unwrap();
        assert!(foreign.is_err());

        let symlink_root = temporary_group_dir();
        let target = symlink_root.join("target");
        fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, symlink_root.join(child_group_name())).unwrap();
        let symlink = recovery_children_empty(&symlink_root, |_| Ok(true));
        fs::remove_dir_all(&symlink_root).unwrap();
        assert!(symlink.is_err());

        let populated_root = temporary_group_dir();
        fs::create_dir(populated_root.join(child_group_name())).unwrap();
        let populated = recovery_children_empty(&populated_root, |_| Ok(false));
        fs::remove_dir_all(&populated_root).unwrap();
        assert!(populated.is_err());
    }
    fn spec() -> UpgradeSpec {
        UpgradeSpec {
            owner_id: "00000000-0000-4000-8000-000000000001".into(),
            request_id: "00000000-0000-4000-8000-000000000002".into(),
            old_sha256: "a".repeat(64),
            old_build_id: "b".repeat(64),
            new_sha256: "c".repeat(64),
            new_build_id: "d".repeat(64),
        }
    }
    fn marker(s: &UpgradeSpec) -> LifecycleReady {
        LifecycleReady {
            version: 1,
            request_id: s.request_id.clone(),
            supervisor: SupervisorIdentity {
                version: 1,
                owner_id: s.owner_id.clone(),
                nonce: "00000000-0000-4000-8000-000000000003".into(),
                pid: 123,
                starttime: 7,
                boot_id: "00000000-0000-4000-8000-000000000004".into(),
                exe_sha256: s.new_sha256.clone(),
            },
        }
    }
    #[test]
    fn lifecycle_ready_rejects_wrong_request_owner_boot_or_build() {
        let s = spec();
        let b = "00000000-0000-4000-8000-000000000004";
        let mut m = marker(&s);
        assert!(ready_binding(&m, &s, b));
        m.request_id = "00000000-0000-4000-8000-000000000005".into();
        assert!(!ready_binding(&m, &s, b));
        m = marker(&s);
        m.supervisor.owner_id = "00000000-0000-4000-8000-000000000005".into();
        assert!(!ready_binding(&m, &s, b));
        m = marker(&s);
        assert!(!ready_binding(&m, &s, "00000000-0000-4000-8000-000000000005"));
        m.supervisor.exe_sha256 = "a".repeat(64);
        assert!(!ready_binding(&m, &s, b));
        m = marker(&s);
        m.supervisor.starttime = 0;
        assert!(!ready_binding(&m, &s, b));
    }
    #[test]
    fn reused_pid_and_zombie_never_identify_old_supervisor() {
        assert!(exact_live_process(Some(((123, 7), false)), 123, 7));
        assert!(!exact_live_process(Some(((123, 8), false)), 123, 7));
        assert!(!exact_live_process(Some(((124, 7), false)), 123, 7));
        assert!(!exact_live_process(Some(((123, 7), true)), 123, 7));
        assert!(!exact_live_process(None, 123, 7));
    }
    #[test]
    fn unknown_service_and_project_table_never_prove_quiescence() {
        assert!(service_stopped(br#"{}"#, "xkeenwrt-core").unwrap());
        assert!(
            !service_stopped(
                br#"{"xkeenwrt-core":{"instances":{"one":{"running":true}}}}"#,
                "xkeenwrt-core"
            )
            .unwrap()
        );
        assert!(service_stopped(br#"{"xkeenwrt-core":{"instances":{"one":{}}}}"#, "xkeenwrt-core").is_err());
        assert!(no_project_table(br#"{"nftables":[{"table":{"family":"inet","name":"xkeenwrt"}}]}"#).is_err());
        assert!(no_project_table(br#"{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}"#).is_ok());
        assert!(no_project_table(br#"{}"#).is_err());
    }

    #[test]
    fn upgrade_quiescence_accepts_only_stopped_or_current_verified_ui() {
        let current = File::open("/proc/self/exe").unwrap();
        assert!(ui_stopped_or_current(br#"{}"#, &current).unwrap());
        assert!(
            ui_stopped_or_current(br#"{"xkeenwrt-ui":{"instances":{"main":{"running":false}}}}"#, &current).unwrap()
        );

        let pid = std::process::id();
        let running = serde_json::json!({
            "xkeenwrt-ui": { "instances": { "main": {
                "running": true,
                "command": ["/usr/bin/xkeenwrt-ui", "serve"],
                "pid": pid
            } } }
        });
        let running = serde_json::to_vec(&running).unwrap();
        assert!(ui_stopped_or_current(&running, &current).unwrap());

        let mut wrong_command: serde_json::Value = serde_json::from_slice(&running).unwrap();
        wrong_command["xkeenwrt-ui"]["instances"]["main"]["command"][1] = "runtime".into();
        let wrong_command = serde_json::to_vec(&wrong_command).unwrap();
        assert!(!ui_stopped_or_current(&wrong_command, &current).unwrap());

        let mut multiple: serde_json::Value = serde_json::from_slice(&running).unwrap();
        multiple["xkeenwrt-ui"]["instances"]["second"] = multiple["xkeenwrt-ui"]["instances"]["main"].clone();
        let multiple = serde_json::to_vec(&multiple).unwrap();
        assert!(!ui_stopped_or_current(&multiple, &current).unwrap());

        let unrelated = File::open("/bin/sh").unwrap();
        assert!(!ui_stopped_or_current(&running, &unrelated).unwrap());
    }
}
