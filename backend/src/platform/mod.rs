use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PlatformInfo {
    pub platform: &'static str,
    pub core: &'static str,
    pub capabilities: Vec<&'static str>,
    pub unsupported_reasons: Vec<&'static str>,
}

pub struct Platform;
#[derive(Clone, Copy)]
pub(crate) enum VerifiedComponent {
    Ui,
    Core,
    Validator,
    Recovery,
}
impl Platform {
    /// Inspection is read-only and does not probe Keenetic or Entware paths.
    pub fn inspect() -> PlatformInfo {
        let openwrt = std::fs::read_to_string("/etc/openwrt_release")
            .map(|s| s.lines().any(|l| l.trim().starts_with("DISTRIB_ID='OpenWrt'")))
            .unwrap_or(false);
        PlatformInfo {
            platform: if openwrt { "openwrt" } else { "unsupported" },
            core: "mihomo",
            capabilities: vec!["platform_inspect"],
            unsupported_reasons: if openwrt {
                vec!["Managed configuration validation and network recovery are not ready"]
            } else {
                vec!["OpenWrt release marker not found; router operations are unavailable"]
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Running,
    Stopped,
}
/// Both installed packages must match the version embedded in this executable.
pub fn package_pair_matches(inventory: &str, expected: &str) -> bool {
    if expected.is_empty()
        || expected.len() > 128
        || !expected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return false;
    }
    let mut ui = None;
    let mut core = None;
    for line in inventory.lines() {
        if let Some(version) = line.strip_prefix("xkeenwrt-ui-") {
            if ui.replace(version).is_some() {
                return false;
            }
        } else if let Some(version) = line.strip_prefix("xkeenwrt-core-")
            && core.replace(version).is_some()
        {
            return false;
        }
    }
    ui == Some(expected) && core == Some(expected)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentManifest {
    version: u32,
    build_id: String,
    package_version: String,
    sha256: ComponentHashes,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentHashes {
    ui: String,
    core: String,
    validator: String,
    recovery: String,
    init_runtime: String,
    init_ui: String,
    init_core: String,
    init_recovery: String,
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn package_manifests_match(ui: &[u8], core: &[u8], version: &str, build_id: &str) -> bool {
    if ui != core || ui.len() > 16384 || !valid_digest(build_id) {
        return false;
    }
    let Ok(m) = serde_json::from_slice::<ComponentManifest>(ui) else {
        return false;
    };
    m.version == 1
        && m.package_version == version
        && m.build_id == build_id
        && [
            &m.sha256.ui,
            &m.sha256.core,
            &m.sha256.validator,
            &m.sha256.recovery,
            &m.sha256.init_runtime,
            &m.sha256.init_ui,
            &m.sha256.init_core,
            &m.sha256.init_recovery,
        ]
        .into_iter()
        .all(|v| valid_digest(v))
}
/// Interpret the fixed `ubus service list` response; malformed data is never
/// presented as a stopped service.
pub fn parse_service_status(json: &str) -> Result<ServiceStatus, &'static str> {
    if json.len() > 65536 {
        return Err("invalid ubus response");
    }
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| "invalid ubus response")?;
    let root = value.as_object().ok_or("invalid ubus response")?;
    let Some(service) = root.get("xkeenwrt-core") else {
        return Ok(ServiceStatus::Stopped);
    };
    let instances = service
        .get("instances")
        .and_then(|v| v.as_object())
        .ok_or("missing instances")?;
    let mut running = false;
    for instance in instances.values() {
        running |= instance
            .get("running")
            .and_then(|v| v.as_bool())
            .ok_or("missing running status")?;
    }
    Ok(if running {
        ServiceStatus::Running
    } else {
        ServiceStatus::Stopped
    })
}

impl Platform {
    pub fn compatible_packages() -> bool {
        Self::compatible_packages_in(None)
    }
    pub(crate) fn compatible_packages_in(cgroup: Option<std::os::fd::RawFd>) -> bool {
        use std::{
            io::Read,
            os::{fd::AsRawFd, unix::process::CommandExt},
            process::Stdio,
            time::{Duration, Instant},
        };
        let Some(expected) = option_env!("XKEENWRT_PACKAGE_VERSION") else {
            return false;
        };
        if Self::inspect().platform != "openwrt" {
            return false;
        }
        if let Some(fd) = cgroup {
            use std::io::{Seek, SeekFrom};
            use std::os::fd::FromRawFd;
            let raw = unsafe { nix::libc::memfd_create(c"xkeenwrt-apk".as_ptr(), nix::libc::MFD_CLOEXEC) };
            if raw < 0 {
                return false;
            }
            let mut output = unsafe { std::fs::File::from_raw_fd(raw) };
            let Ok(null) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") else {
                return false;
            };
            let args = ["info".to_owned(), "-v".to_owned()];
            if !xkeenwrt_recovery::run_fixed_in_cgroup(
                xkeenwrt_recovery::FixedProgram::Apk,
                &args,
                fd,
                null.as_raw_fd(),
                output.as_raw_fd(),
                null.as_raw_fd(),
                Duration::from_secs(5),
            )
            .unwrap_or(false)
            {
                return false;
            }
            if output.seek(SeekFrom::Start(0)).is_err() {
                return false;
            }
            let mut bytes = Vec::new();
            if output.take(256 * 1024 + 1).read_to_end(&mut bytes).is_err() || bytes.len() > 256 * 1024 {
                return false;
            }
            return String::from_utf8(bytes)
                .ok()
                .is_some_and(|s| package_pair_matches(&s, expected))
                && Self::compatible_components(expected);
        }
        let Ok(mut child) = std::process::Command::new("/usr/bin/apk")
            .args(["info", "-v"])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let result = (|| {
            let mut out = child.stdout.take()?;
            let fd = out.as_raw_fd();
            let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
            if flags < 0 || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) } < 0 {
                return None;
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            let mut eof = false;
            loop {
                if !eof {
                    match out.read(&mut buffer) {
                        Ok(0) => eof = true,
                        Ok(n) if bytes.len() + n <= 256 * 1024 => bytes.extend_from_slice(&buffer[..n]),
                        Ok(_) => return None,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => return None,
                    }
                }
                if let Some(status) = child.try_wait().ok()? {
                    if !status.success() {
                        return None;
                    }
                    if eof {
                        return Some(bytes);
                    }
                }
                if Instant::now() >= deadline {
                    return None;
                }
                let mut pfd = nix::libc::pollfd {
                    fd: if eof { -1 } else { fd },
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                unsafe {
                    nix::libc::poll(&mut pfd, 1, 50);
                }
            }
        })();
        if result.is_none() {
            let _ = crate::runtime::process::terminate(&mut child);
        }
        result
            .and_then(|v| String::from_utf8(v).ok())
            .is_some_and(|s| package_pair_matches(&s, expected))
            && Self::compatible_components(expected)
    }
    fn compatible_components(expected_version: &str) -> bool {
        use sha2::{Digest, Sha256};
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
            path::Path,
            time::{Duration, Instant},
        };
        fn open_root_file(path: &Path, limit: u64, proc_exe: bool) -> Option<std::fs::File> {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK | if proc_exe { 0 } else { nix::libc::O_NOFOLLOW });
            let f = options.open(path).ok()?;
            let m = f.metadata().ok()?;
            if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o022 != 0 || m.len() > limit {
                return None;
            }
            Some(f)
        }
        let Some(build_id) = option_env!("XKEENWRT_BUILD_ID") else {
            return false;
        };
        let read_manifest = |path: &str| -> Option<Vec<u8>> {
            let mut bytes = Vec::new();
            open_root_file(Path::new(path), 16384, false)?
                .take(16385)
                .read_to_end(&mut bytes)
                .ok()?;
            if bytes.len() > 16384 {
                return None;
            }
            Some(bytes)
        };
        let Some(ui) = read_manifest("/usr/share/xkeenwrt/ui-manifest.json") else {
            return false;
        };
        let Some(core) = read_manifest("/usr/share/xkeenwrt/core-manifest.json") else {
            return false;
        };
        if !package_manifests_match(&ui, &core, expected_version, build_id) {
            return false;
        }
        let Ok(manifest) = serde_json::from_slice::<ComponentManifest>(&ui) else {
            return false;
        };
        for name in ["xkeenwrt-runtime", "xkeenwrt-ui", "xkeenwrt-core", "xkeenwrt-recovery"] {
            let link = format!("/etc/init.d/{name}");
            let target = format!("/usr/libexec/xkeenwrt/init/{name}");
            let Ok(meta) = std::fs::symlink_metadata(&link) else {
                return false;
            };
            if !meta.file_type().is_symlink()
                || meta.uid() != 0
                || std::fs::read_link(&link).ok().as_deref() != Some(Path::new(&target))
            {
                return false;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let components = [
            ("/usr/bin/xkeenwrt-ui", &manifest.sha256.ui, false),
            ("/proc/self/exe", &manifest.sha256.ui, true),
            (
                "/usr/libexec/xkeenwrt/xkeenwrt-validate",
                &manifest.sha256.validator,
                false,
            ),
            (
                "/usr/libexec/xkeenwrt/xkeenwrt-recovery",
                &manifest.sha256.recovery,
                false,
            ),
            (
                "/usr/libexec/xkeenwrt/init/xkeenwrt-runtime",
                &manifest.sha256.init_runtime,
                false,
            ),
            (
                "/usr/libexec/xkeenwrt/init/xkeenwrt-ui",
                &manifest.sha256.init_ui,
                false,
            ),
            (
                "/usr/libexec/xkeenwrt/init/xkeenwrt-core",
                &manifest.sha256.init_core,
                false,
            ),
            (
                "/usr/libexec/xkeenwrt/init/xkeenwrt-recovery",
                &manifest.sha256.init_recovery,
                false,
            ),
        ];
        for (path, expected, proc_exe) in components {
            let Some(mut file) = open_root_file(Path::new(path), 128 * 1024 * 1024, proc_exe) else {
                return false;
            };
            let Ok(before) = file.metadata() else {
                return false;
            };
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                if Instant::now() >= deadline {
                    return false;
                }
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                    Err(_) => return false,
                }
            }
            let Ok(after) = file.metadata() else {
                return false;
            };
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || after.nlink() != 1
            {
                return false;
            }
            if !proc_exe {
                let Ok(current) = std::fs::symlink_metadata(path) else {
                    return false;
                };
                if !current.is_file()
                    || current.file_type().is_symlink()
                    || current.dev() != after.dev()
                    || current.ino() != after.ino()
                {
                    return false;
                }
            }
            let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if &actual != expected {
                return false;
            }
        }
        crate::core_update::installed_core_valid()
    }
    /// Pin the exact previously verified ELF, even if APK replaces its path later.
    pub(crate) fn verified_component(
        component: VerifiedComponent, cgroup: Option<std::os::fd::RawFd>,
    ) -> Option<std::fs::File> {
        Self::verified_component_with_digest(component, cgroup).map(|(file, _)| file)
    }
    fn verified_component_with_digest(
        component: VerifiedComponent, cgroup: Option<std::os::fd::RawFd>,
    ) -> Option<(std::fs::File, String)> {
        use sha2::{Digest, Sha256};
        use std::{
            io::{Read, Seek, SeekFrom},
            os::unix::fs::{MetadataExt, OpenOptionsExt},
            time::{Duration, Instant},
        };
        if !Self::compatible_packages_in(cgroup) {
            return None;
        }
        if matches!(component, VerifiedComponent::Core) {
            return crate::core_update::open_active_core();
        }
        let version = option_env!("XKEENWRT_PACKAGE_VERSION")?;
        let build_id = option_env!("XKEENWRT_BUILD_ID")?;
        let read_manifest = |path: &str| -> Option<Vec<u8>> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)
                .ok()?;
            let m = f.metadata().ok()?;
            if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o022 != 0 || m.len() > 16384 {
                return None;
            }
            let mut data = Vec::new();
            f.take(16385).read_to_end(&mut data).ok()?;
            if data.len() > 16384 {
                return None;
            }
            Some(data)
        };
        let ui = read_manifest("/usr/share/xkeenwrt/ui-manifest.json")?;
        let core = read_manifest("/usr/share/xkeenwrt/core-manifest.json")?;
        if !package_manifests_match(&ui, &core, version, build_id) {
            return None;
        }
        let manifest: ComponentManifest = serde_json::from_slice(&ui).ok()?;
        let (path, expected) = match component {
            VerifiedComponent::Ui => ("/usr/bin/xkeenwrt-ui", manifest.sha256.ui),
            VerifiedComponent::Core => return crate::core_update::open_active_core(),
            VerifiedComponent::Validator => ("/usr/libexec/xkeenwrt/xkeenwrt-validate", manifest.sha256.validator),
            VerifiedComponent::Recovery => ("/usr/libexec/xkeenwrt/xkeenwrt-recovery", manifest.sha256.recovery),
        };
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        let before = file.metadata().ok()?;
        if !before.is_file()
            || before.uid() != 0
            || before.nlink() != 1
            || before.mode() & 0o022 != 0
            || before.len() > 128 * 1024 * 1024
        {
            return None;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hash.update(&buffer[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(_) => return None,
            }
        }
        let after = file.metadata().ok()?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || after.nlink() != 1
        {
            return None;
        }
        let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if actual != expected {
            return None;
        }
        file.seek(SeekFrom::Start(0)).ok()?;
        Some((file, expected))
    }
    pub(crate) fn verified_recovery(cgroup: std::os::fd::RawFd) -> Option<(std::fs::File, String, &'static str)> {
        let (file, digest) = Self::verified_component_with_digest(VerifiedComponent::Recovery, Some(cgroup))?;
        let build_id = option_env!("XKEENWRT_BUILD_ID")?;
        Some((file, digest, build_id))
    }
    /// Only the fixed OpenWrt service is queried. ubus has its own bounded timeout.
    pub fn service_status() -> Result<ServiceStatus, &'static str> {
        Self::service_status_in(None)
    }
    pub(crate) fn service_status_in(operation_fd: Option<std::os::fd::RawFd>) -> Result<ServiceStatus, &'static str> {
        if Self::inspect().platform != "openwrt" {
            return Err("UNSUPPORTED");
        }
        if let Some(fd) = operation_fd {
            use std::{
                io::{Read, Seek, SeekFrom},
                os::fd::{AsRawFd, FromRawFd},
                time::Duration,
            };
            let raw = unsafe { nix::libc::memfd_create(c"xkeenwrt-ubus".as_ptr(), nix::libc::MFD_CLOEXEC) };
            if raw < 0 {
                return Err("UBUS_UNAVAILABLE");
            }
            let mut output = unsafe { std::fs::File::from_raw_fd(raw) };
            let null = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map_err(|_| "UBUS_UNAVAILABLE")?;
            let args = [
                "-t".to_owned(),
                "2".to_owned(),
                "call".to_owned(),
                "service".to_owned(),
                "list".to_owned(),
                r#"{"name":"xkeenwrt-core"}"#.to_owned(),
            ];
            if !xkeenwrt_recovery::run_fixed_in_cgroup(
                xkeenwrt_recovery::FixedProgram::Ubus,
                &args,
                fd,
                null.as_raw_fd(),
                output.as_raw_fd(),
                null.as_raw_fd(),
                Duration::from_secs(3),
            )
            .unwrap_or(false)
            {
                return Err("UBUS_UNAVAILABLE");
            }
            output.seek(SeekFrom::Start(0)).map_err(|_| "UBUS_INVALID")?;
            let mut bytes = Vec::new();
            output.take(65537).read_to_end(&mut bytes).map_err(|_| "UBUS_INVALID")?;
            if bytes.len() > 65536 {
                return Err("UBUS_INVALID");
            }
            return parse_service_status(std::str::from_utf8(&bytes).map_err(|_| "UBUS_INVALID")?)
                .map_err(|_| "UBUS_INVALID");
        }
        use std::{
            io::Read,
            os::fd::AsRawFd,
            os::unix::process::CommandExt,
            process::Stdio,
            time::{Duration, Instant},
        };
        let mut command = std::process::Command::new("/bin/ubus");
        command
            .args(["-t", "2", "call", "service", "list", r#"{"name":"xkeenwrt-core"}"#])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| "UBUS_UNAVAILABLE")?;
        let result = (|| {
            let mut stdout = child.stdout.take().ok_or("UBUS_UNAVAILABLE")?;
            let fd = stdout.as_raw_fd();
            let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
            if flags < 0 || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) } < 0 {
                return Err("UBUS_UNAVAILABLE");
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            let mut eof = false;
            loop {
                if !eof {
                    match stdout.read(&mut buf) {
                        Ok(0) => eof = true,
                        Ok(n) => {
                            if bytes.len() + n > 65536 {
                                return Err("UBUS_UNAVAILABLE");
                            }
                            bytes.extend_from_slice(&buf[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err("UBUS_UNAVAILABLE"),
                    }
                }
                if let Some(status) = child.try_wait().map_err(|_| "UBUS_UNAVAILABLE")? {
                    if !status.success() {
                        return Err("UBUS_UNAVAILABLE");
                    }
                    if eof {
                        return Ok(bytes);
                    }
                }
                if Instant::now() >= deadline {
                    return Err("UBUS_UNAVAILABLE");
                }
                let mut pollfd = nix::libc::pollfd {
                    fd,
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                unsafe {
                    if eof {
                        nix::libc::poll(std::ptr::null_mut(), 0, 50);
                    } else {
                        nix::libc::poll(&mut pollfd, 1, 50);
                    }
                }
            }
        })();
        if result.is_err() {
            let _ = crate::runtime::process::terminate(&mut child);
        }
        let bytes = result?;
        let json = std::str::from_utf8(&bytes).map_err(|_| "UBUS_INVALID")?;
        parse_service_status(json).map_err(|_| "UBUS_INVALID")
    }
}
