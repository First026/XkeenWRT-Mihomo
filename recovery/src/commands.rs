//! Fixed executables in an atomically assigned cgroup; private stdio files.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use xkeenwrt_recovery::{FixedProgram, run_fixed_in_cgroup};
static NEXT: AtomicU64 = AtomicU64::new(0);
static GROUP: OnceLock<Mutex<Option<File>>> = OnceLock::new();
fn group() -> &'static Mutex<Option<File>> {
    GROUP.get_or_init(|| Mutex::new(None))
}
pub fn set_cgroup(dir: File) -> io::Result<()> {
    *group()
        .lock()
        .map_err(|_| io::Error::other("recovery group poisoned"))? = Some(dir);
    Ok(())
}
pub struct Output {
    pub success: bool,
    pub bytes: Vec<u8>,
}
fn private_file(label: &str) -> io::Result<(String, File)> {
    let path = format!(
        "/var/run/xkeenwrt/.recovery-{}-{}-{}",
        label,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    Ok((path, file))
}
fn run(program: FixedProgram, args: &[String], input: Option<&str>) -> io::Result<Output> {
    let (out_path, mut output) = private_file("out")?;
    let mut in_path = None;
    let result = (|| {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        let input_file = if let Some(input) = input {
            if input.len() > 1_048_576 {
                return Err(io::Error::other("command input too large"));
            }
            let (path, mut file) = private_file("in")?;
            in_path = Some(path);
            file.write_all(input.as_bytes())?;
            file.seek(SeekFrom::Start(0))?;
            file
        } else {
            null.try_clone()?
        };
        let group = group()
            .lock()
            .map_err(|_| io::Error::other("recovery group poisoned"))?
            .as_ref()
            .ok_or_else(|| io::Error::other("missing recovery group"))?
            .try_clone()?;
        let result = run_fixed_in_cgroup(
            program,
            args,
            group.as_raw_fd(),
            input_file.as_raw_fd(),
            output.as_raw_fd(),
            null.as_raw_fd(),
            Duration::from_secs(3),
        );
        crate::supervisor::ensure_quiescent(&group)?;
        let success = result?;
        output.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        output.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return Err(io::Error::other("command output too large"));
        }
        Ok(Output { success, bytes })
    })();
    let _ = fs::remove_file(&out_path);
    if let Some(path) = in_path {
        let _ = fs::remove_file(path);
    }
    result
}
pub fn nft(args: &[&str], input: Option<&str>) -> io::Result<Output> {
    run(
        FixedProgram::Nft,
        &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        input,
    )
}
pub fn ip(args: &[String]) -> io::Result<Output> {
    run(FixedProgram::Ip, args, None)
}
pub fn start_rescue() -> io::Result<()> {
    let out = run(FixedProgram::RescueInit, &["start".to_owned()], None)?;
    if out.success {
        Ok(())
    } else {
        Err(io::Error::other("rescue init start failed"))
    }
}
pub fn stop_rescue() -> io::Result<()> {
    stop_service("xkeenwrt-rescue")
}
pub fn stop_package_recovery() -> io::Result<()> {
    stop_service("xkeenwrt-recovery")
}
pub fn stop_runtime() -> io::Result<()> {
    stop_service("xkeenwrt-runtime")
}
pub fn start_runtime() -> io::Result<()> {
    if run(FixedProgram::RuntimeInit, &["start".into()], None)?.success {
        Ok(())
    } else {
        Err(io::Error::other("runtime start failed"))
    }
}
fn stop_service(name: &'static str) -> io::Result<()> {
    let args = vec![
        "call".into(),
        "service".into(),
        "delete".into(),
        format!("{{\"name\":\"{}\"}}", name),
    ];
    let out = run(FixedProgram::Ubus, &args, None)?;
    if out.success || service_is_stopped(name)? {
        Ok(())
    } else {
        Err(io::Error::other("could not stop service"))
    }
}
pub fn core_action(action: &'static str, nonce: Option<&str>) -> io::Result<()> {
    if action == "stop" {
        return stop_service("xkeenwrt-core");
    }
    if action != "start" {
        return Err(io::Error::other("invalid core action"));
    }
    let nonce = nonce.ok_or_else(|| io::Error::other("missing launch nonce"))?;
    if run(
        FixedProgram::CoreInit,
        &["start".into(), nonce.into()],
        None,
    )?
    .success
    {
        Ok(())
    } else {
        Err(io::Error::other("core start failed"))
    }
}
/// Bounded procd query for the sole fixed project core service.
pub(crate) fn core_instances() -> io::Result<Option<serde_json::Map<String, serde_json::Value>>> {
    service_info("xkeenwrt-core")
}
pub fn core_is_stopped() -> io::Result<bool> {
    service_is_stopped("xkeenwrt-core")
}
pub fn runtime_is_stopped() -> io::Result<bool> {
    service_is_stopped("xkeenwrt-runtime")
}
pub fn ui_is_stopped() -> io::Result<bool> {
    service_is_stopped("xkeenwrt-ui")
}
pub fn rescue_is_stopped() -> io::Result<bool> {
    service_is_stopped("xkeenwrt-rescue")
}
pub fn package_recovery_is_stopped() -> io::Result<bool> {
    service_is_stopped("xkeenwrt-recovery")
}
pub fn stop_ui() -> io::Result<()> {
    stop_service("xkeenwrt-ui")
}
/// Final clean installation requires deleted procd definitions, including
/// stopped instances that could otherwise still carry a respawn policy.
pub(crate) fn project_services_absent() -> io::Result<bool> {
    for name in [
        "xkeenwrt-ui",
        "xkeenwrt-runtime",
        "xkeenwrt-core",
        "xkeenwrt-recovery",
        "xkeenwrt-rescue",
    ] {
        if service_info(name)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}
fn service_info(
    name: &'static str,
) -> io::Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let args = vec![
        "call".into(),
        "service".into(),
        "list".into(),
        format!("{{\"name\":\"{}\"}}", name),
    ];
    let out = run(FixedProgram::Ubus, &args, None)?;
    if !out.success {
        return Err(io::Error::other("cannot inspect service"));
    }
    let value: serde_json::Value = serde_json::from_slice(&out.bytes).map_err(io::Error::other)?;
    let top = value
        .as_object()
        .ok_or_else(|| io::Error::other("invalid service inventory"))?;
    let Some(service) = top.get(name) else {
        return Ok(None);
    };
    Ok(Some(
        service
            .get("instances")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| io::Error::other("missing service instances"))?
            .clone(),
    ))
}
fn service_is_stopped(name: &'static str) -> io::Result<bool> {
    let Some(instances) = service_info(name)? else {
        return Ok(true);
    };
    for instance in instances.values() {
        match instance.get("running").and_then(serde_json::Value::as_bool) {
            Some(true) => return Ok(false),
            Some(false) => {}
            None => return Err(io::Error::other("unknown service state")),
        }
    }
    Ok(true)
}
pub fn runtime_pid() -> io::Result<Option<u32>> {
    service_pid("xkeenwrt-runtime")
}
pub fn core_pid() -> io::Result<Option<u32>> {
    service_pid("xkeenwrt-core")
}
pub fn ui_pid() -> io::Result<Option<u32>> {
    service_pid("xkeenwrt-ui")
}
fn service_pid(name: &'static str) -> io::Result<Option<u32>> {
    let Some(instances) = service_info(name)? else {
        return Ok(None);
    };
    let mut pid = None;
    for instance in instances.values() {
        match instance.get("running").and_then(serde_json::Value::as_bool) {
            Some(false) => {}
            Some(true) => {
                let value = instance
                    .get("pid")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v > 0)
                    .ok_or_else(|| io::Error::other("missing service PID"))?;
                if pid.replace(value).is_some() {
                    return Err(io::Error::other("multiple service instances"));
                }
            }
            None => return Err(io::Error::other("unknown service state")),
        }
    }
    Ok(pid)
}

/// Read-only topology inputs. The caller cannot supply executable names or argv.
#[derive(Clone, Copy)]
pub(crate) enum InventoryQuery {
    Addresses,
    Neighbours,
    Links,
    Rules4,
    Rules6,
    Routes4,
    Routes6,
    NftRuleset,
    NetworkStatus,
    DnsConfig,
    ProxyConfig,
    ProxyService,
}
pub(crate) fn inventory(query: InventoryQuery) -> io::Result<Vec<u8>> {
    use InventoryQuery::*;
    let (program, args): (FixedProgram, &[&str]) = match query {
        Addresses => (FixedProgram::Ip, &["-j", "address", "show"]),
        Neighbours => (FixedProgram::Ip, &["-j", "neigh", "show"]),
        Links => (FixedProgram::Ip, &["-j", "link", "show"]),
        Rules4 => (FixedProgram::Ip, &["-j", "-4", "rule", "show"]),
        Rules6 => (FixedProgram::Ip, &["-j", "-6", "rule", "show"]),
        Routes4 => (
            FixedProgram::Ip,
            &["-j", "-4", "route", "show", "table", "all"],
        ),
        Routes6 => (
            FixedProgram::Ip,
            &["-j", "-6", "route", "show", "table", "all"],
        ),
        NftRuleset => (FixedProgram::Nft, &["-j", "list", "ruleset"]),
        NetworkStatus => (FixedProgram::Ubus, &["call", "network.interface", "dump"]),
        DnsConfig => (
            FixedProgram::Ubus,
            &["call", "uci", "get", "{\"config\":\"dhcp\"}"],
        ),
        ProxyConfig => (
            FixedProgram::Ubus,
            &["call", "uci", "get", "{\"config\":\"https-dns-proxy\"}"],
        ),
        ProxyService => (
            FixedProgram::Ubus,
            &["call", "service", "list", "{\"name\":\"https-dns-proxy\"}"],
        ),
    };
    let output = run(
        program,
        &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        None,
    )?;
    if !output.success {
        return Err(io::Error::other("inventory query failed"));
    }
    if matches!(query, InventoryQuery::DnsConfig) {
        xkeenwrt_recovery::dns_snapshot::capture(&output.bytes)
    } else {
        Ok(output.bytes)
    }
}

/// The caller must first verify the dnsmasq configuration permits this fixed path.
pub(crate) fn default_leases() -> io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let path = "/tmp/dhcp.leases";
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || before.nlink() != 1
        || before.len() > 1_048_576
    {
        return Err(io::Error::other("unsafe dnsmasq leases"));
    }
    let mut data = Vec::new();
    (&file).take(1_048_577).read_to_end(&mut data)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if data.len() > 1_048_576
        || named.file_type().is_symlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || after.dev() != named.dev()
        || after.ino() != named.ino()
    {
        return Err(io::Error::other("dnsmasq leases changed during read"));
    }
    Ok(data)
}
