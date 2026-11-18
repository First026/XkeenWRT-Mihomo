//! Fixed procd adapter gated by explicit deployment enablement or a feature-gated lab guest.
use crate::configuration::{ActivationError, ManualCore};
use std::{
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(feature = "lab-hooks")]
pub fn marked_lab() -> bool {
    if unsafe { nix::libc::geteuid() } != 0 || crate::platform::Platform::inspect().platform != "openwrt" {
        return false;
    }
    if !std::fs::read_to_string("/proc/cmdline")
        .is_ok_and(|s| s.split_ascii_whitespace().any(|x| x == "xkeenwrt.isolation_lab=1"))
    {
        return false;
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open("/etc/xkeenwrt-isolation-lab")
    else {
        return false;
    };
    let Ok(m) = f.metadata() else {
        return false;
    };
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o022 != 0 || m.len() != 26 {
        return false;
    }
    let mut value = Vec::new();
    f.read_to_end(&mut value).is_ok() && value == b"xkeenwrt-validator-lab-v1\n"
}
#[cfg(not(feature = "lab-hooks"))]
pub fn marked_lab() -> bool {
    false
}
/// The fixed OpenWrt package hook creates this root-owned gate during a normal
/// install. It admits the controller on supported OpenWrt only; it never
/// starts Mihomo or enables network capture.
pub fn deployment_allowed() -> bool {
    if !std::fs::read_to_string("/etc/openwrt_release")
        .is_ok_and(|s| s.lines().any(|line| line.trim() == "DISTRIB_RELEASE='25.12.6'"))
    {
        return false;
    }
    if marked_lab() {
        return true;
    }
    if unsafe { nix::libc::geteuid() } != 0 || crate::platform::Platform::inspect().platform != "openwrt" {
        return false;
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open("/etc/xkeenwrt/runtime-enabled")
    else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 || meta.len() != 20 {
        return false;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).is_ok() && bytes == b"xkeenwrt-runtime-v1\n"
}
pub(crate) fn ensure_no_lifecycle_request() -> Result<(), ActivationError> {
    for path in [
        "/etc/xkeenwrt/removal.json",
        "/etc/xkeenwrt/lifecycle.json",
        "/etc/xkeenwrt/rescue-replacement.json",
    ] {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Ok(_) => return Err(ActivationError::Conflict),
            Err(_) => return Err(ActivationError::Storage),
        }
    }
    Ok(())
}
fn service(action: &str, nonce: Option<&str>, operation_fd: Option<std::os::fd::RawFd>) -> Result<(), ActivationError> {
    ensure_no_lifecycle_request()?;
    if !deployment_allowed() || !matches!(action, "start" | "stop") {
        return Err(ActivationError::Unavailable);
    }
    if let Some(fd) = operation_fd {
        use std::os::fd::AsRawFd;
        if (action == "start") != nonce.is_some() || nonce.is_some_and(|n| uuid::Uuid::parse_str(n).is_err()) {
            return Err(ActivationError::Invalid);
        }
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| ActivationError::Unavailable)?;
        let mut args = vec![action.to_owned()];
        if let Some(nonce) = nonce {
            args.push(nonce.to_owned());
        }
        if !xkeenwrt_recovery::run_fixed_in_cgroup(
            xkeenwrt_recovery::FixedProgram::CoreInit,
            &args,
            fd,
            null.as_raw_fd(),
            null.as_raw_fd(),
            null.as_raw_fd(),
            Duration::from_secs(8),
        )
        .unwrap_or(false)
        {
            return Err(ActivationError::Unavailable);
        }
        let expected = if action == "start" {
            crate::platform::ServiceStatus::Running
        } else {
            crate::platform::ServiceStatus::Stopped
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if crate::platform::Platform::service_status_in(Some(fd)).ok() == Some(expected) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        return Err(ActivationError::Unavailable);
    }
    let mut command = Command::new("/etc/init.d/xkeenwrt-core");
    command.arg(action);
    if let Some(nonce) = nonce {
        if action != "start" || uuid::Uuid::parse_str(nonce).is_err() {
            return Err(ActivationError::Invalid);
        }
        command.arg(nonce);
    }
    if action == "start" && nonce.is_none() {
        return Err(ActivationError::Invalid);
    }
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| ActivationError::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => {
                if !s.success() {
                    return Err(ActivationError::Unavailable);
                }
                let expected = if action == "start" {
                    crate::platform::ServiceStatus::Running
                } else {
                    crate::platform::ServiceStatus::Stopped
                };
                while Instant::now() < deadline {
                    if crate::platform::Platform::service_status_in(operation_fd).ok() == Some(expected) {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                return Err(ActivationError::Unavailable);
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = super::process::terminate(&mut child);
                return Err(ActivationError::Unavailable);
            }
        }
    }
}
fn private_dir(p: &Path) -> Result<(), ActivationError> {
    match std::fs::DirBuilder::new().mode(0o700).create(p) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(ActivationError::Storage),
    }
    let m = std::fs::symlink_metadata(p).map_err(|_| ActivationError::Storage)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(ActivationError::Storage);
    }
    Ok(())
}
struct LaunchTicket {
    nonce: String,
    retired: Option<std::path::PathBuf>,
}

pub struct ProcdCore {
    pub secret: String,
    incarnation_cgroup: std::sync::Arc<std::fs::File>,
    operation_cgroup: Option<std::sync::Arc<std::fs::File>>,
}
fn remove_owned_home(path: &Path) -> Result<(), ActivationError> {
    fn inspect(
        dir: &Path, depth: usize, files: &mut Vec<std::path::PathBuf>, dirs: &mut Vec<std::path::PathBuf>,
    ) -> Result<(), ActivationError> {
        let m = std::fs::symlink_metadata(dir).map_err(|_| ActivationError::Storage)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o077 != 0 || depth > 3 {
            return Err(ActivationError::Storage);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(dir).map_err(|_| ActivationError::Storage)? {
            let entry = entry.map_err(|_| ActivationError::Storage)?;
            count += 1;
            if count > 64 {
                return Err(ActivationError::Storage);
            }
            let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|_| ActivationError::Storage)?;
            let allowed_dir =
                (depth == 0 && name == "providers") || (depth == 1 && (name == "proxies" || name == "rules"));
            let runtime_cache = depth == 0
                && name == "cache.db"
                && xkeenwrt_recovery::core_cache::removable(dir).map_err(|_| ActivationError::Storage)?;
            let allowed_file = (depth == 0 && name == "config.yaml")
                || runtime_cache
                || (depth == 2
                    && name.strip_suffix(".yaml").is_some_and(|n| {
                        n.parse::<u8>()
                            .is_ok_and(|i| usize::from(i) < profile_policy::MAX_PROVIDER_FILES && n == i.to_string())
                    }));
            if allowed_dir {
                inspect(&entry.path(), depth + 1, files, dirs)?;
            } else if allowed_file
                && meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == 0
                && meta.nlink() == 1
                && (meta.mode() & 0o077 == 0 || runtime_cache)
            {
                files.push(entry.path());
            } else {
                return Err(ActivationError::Storage);
            }
        }
        dirs.push(dir.to_path_buf());
        Ok(())
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    inspect(path, 0, &mut files, &mut dirs)?;
    for file in files {
        std::fs::remove_file(file).map_err(|_| ActivationError::Storage)?;
    }
    for dir in dirs {
        std::fs::remove_dir(dir).map_err(|_| ActivationError::Storage)?;
    }
    Ok(())
}

fn bundle_bytes(bundle: &crate::configuration::ValidatedBundle) -> u64 {
    bundle.config.len() as u64 + bundle.assets.iter().map(|a| a.content.len() as u64).sum::<u64>()
}
/// History appended by pinning one snapshot of `bundle`.
pub(crate) fn snapshot_need(
    bundle: &crate::configuration::ValidatedBundle,
) -> xkeenwrt_recovery::resources::HistoryNeed {
    xkeenwrt_recovery::resources::HistoryNeed::snapshot(bundle_bytes(bundle), bundle.assets.len())
}
/// Byte-identical snapshot contents: configuration, assets and overlay.
pub(crate) fn same_contents(
    a: &crate::configuration::ValidatedBundle, b: &crate::configuration::ValidatedBundle,
) -> bool {
    a.config == b.config && a.assets == b.assets && a.overlay == b.overlay
}
/// A role whose contents are byte-identical to an already pinned snapshot
/// shares that directory; only the running flag and controller port differ.
pub(crate) fn reuse_snapshot(
    pinned: &xkeenwrt_recovery::CoreSnapshot, pinned_bundle: &crate::configuration::ValidatedBundle,
    bundle: &crate::configuration::ValidatedBundle, running: bool,
) -> Option<xkeenwrt_recovery::CoreSnapshot> {
    same_contents(pinned_bundle, bundle).then(|| xkeenwrt_recovery::CoreSnapshot {
        running,
        controller_port: if running { 9090 } else { 0 },
        ..pinned.clone()
    })
}

impl ManualCore for ProcdCore {
    fn check_fence(&self) -> Result<(), ActivationError> {
        ensure_no_lifecycle_request()
    }
    fn admit(
        &self, bundle_bytes: u64, flash_staging_bytes: u64, _history_staging_bytes: u64,
    ) -> Result<(), ActivationError> {
        // History is reserved by the caller before its first write.
        super::resources::admit(bundle_bytes, flash_staging_bytes, self.reclaimable_memory())
    }
    fn can_apply(&self) -> Result<(), ActivationError> {
        ensure_no_lifecycle_request()?;
        if !deployment_allowed() {
            return Err(ActivationError::Unavailable);
        }
        super::grant::preflight_core_limits()?;
        let base = Path::new("/tmp/xkeenwrt/runtime");
        let entries = match std::fs::read_dir(base) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(ActivationError::Storage),
        };
        let mut leftovers = 0usize;
        for entry in entries {
            let entry = entry.map_err(|_| ActivationError::Storage)?;
            let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
            if let Some(id) = name
                .strip_prefix("retired-")
                .or_else(|| name.strip_prefix("candidate-"))
            {
                if uuid::Uuid::parse_str(id).is_err() {
                    return Err(ActivationError::Storage);
                }
                if remove_owned_home(&entry.path()).is_err() {
                    leftovers += 1;
                }
            }
        }
        if leftovers >= 4 {
            Err(ActivationError::Storage)
        } else {
            Ok(())
        }
    }
    fn running(&self) -> Result<bool, ActivationError> {
        if !deployment_allowed() {
            return Err(ActivationError::Unavailable);
        }
        crate::platform::Platform::service_status_in(self.operation_fd())
            .map(|s| s == crate::platform::ServiceStatus::Running)
            .map_err(|_| ActivationError::Unavailable)
    }
    fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError> {
        if let Some(config) = config {
            return self.replace_assets(Some(config), &[]);
        }
        if !deployment_allowed() {
            return Err(ActivationError::Unavailable);
        }
        super::grant::revoke()?;
        service("stop", None, self.operation_fd())?;
        super::input_guard::protect(None, &self.incarnation_cgroup)
    }
    fn emergency_stop(&mut self) -> Result<(), ActivationError> {
        use std::os::fd::AsRawFd;
        ensure_no_lifecycle_request()?;
        super::grant::revoke()?;
        let fd = self.operation_fd().ok_or(ActivationError::Unavailable)?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| ActivationError::Unavailable)?;
        if !xkeenwrt_recovery::run_fixed_in_cgroup(
            xkeenwrt_recovery::FixedProgram::CoreInit,
            &["stop".to_owned()],
            fd,
            null.as_raw_fd(),
            null.as_raw_fd(),
            null.as_raw_fd(),
            Duration::from_secs(8),
        )
        .unwrap_or(false)
        {
            return Err(ActivationError::Unavailable);
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if crate::platform::Platform::service_status_in(Some(fd)).ok()
                == Some(crate::platform::ServiceStatus::Stopped)
            {
                return super::input_guard::protect(None, &self.incarnation_cgroup);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(ActivationError::Unavailable)
    }
    fn replace_assets(
        &mut self, config: Option<&str>, assets: &[profile_policy::Asset],
    ) -> Result<(), ActivationError> {
        if let Some(config) = config {
            let explicit = super::inputs::load()?.explicit;
            let inputs = profile_policy::InputsOverlay {
                explicit,
                gateway: None,
            };
            let combined =
                profile_policy::compose_inputs(config, assets, &inputs).map_err(|_| ActivationError::Invalid)?;
            self.publish(
                Some(&combined),
                assets,
                &profile_policy::ManagedOverlay::Composite(inputs),
            )
        } else {
            self.publish(None, assets, &profile_policy::ManagedOverlay::Manual)
        }
    }
}
impl ProcdCore {
    pub(crate) fn new(secret: String, incarnation_cgroup: std::sync::Arc<std::fs::File>) -> Self {
        Self {
            secret,
            incarnation_cgroup,
            operation_cgroup: None,
        }
    }
    fn operation_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        Some(
            self.operation_cgroup
                .as_ref()
                .unwrap_or(&self.incarnation_cgroup)
                .as_raw_fd(),
        )
    }
    pub(crate) fn set_operation_cgroup(
        &mut self, file: std::fs::File, identity: &xkeenwrt_recovery::RuntimeIncarnationIdentity, owner: &str,
        generation: u64, tx: &str,
    ) -> Result<(), ActivationError> {
        use std::os::fd::AsRawFd;
        let expected = xkeenwrt_recovery::operation_cgroup_path(identity, owner, generation, tx)
            .map_err(|_| ActivationError::Invalid)?;
        let link =
            std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| ActivationError::Storage)?;
        let metadata = file.metadata().map_err(|_| ActivationError::Storage)?;
        let mut fs: nix::libc::statfs = unsafe { std::mem::zeroed() };
        if link != expected
            || !metadata.is_dir()
            || metadata.uid() != 0
            || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0
            || fs.f_type as u64 != 0x63677270
        {
            return Err(ActivationError::Storage);
        }
        self.operation_cgroup = Some(std::sync::Arc::new(file));
        Ok(())
    }
    pub(crate) fn clear_operation_cgroup(&mut self) {
        self.operation_cgroup = None;
    }
    fn read_pinned(
        &self, snapshot: &xkeenwrt_recovery::CoreSnapshot, overlay: &profile_policy::ManagedOverlay,
    ) -> Result<(String, Vec<profile_policy::Asset>), ActivationError> {
        use sha2::{Digest, Sha256};
        use std::collections::{BTreeMap, BTreeSet};
        fn inspect_dir(path: &Path, expected: &BTreeSet<String>) -> Result<(), ActivationError> {
            let m = std::fs::symlink_metadata(path).map_err(|_| ActivationError::Storage)?;
            if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
                return Err(ActivationError::Storage);
            }
            let mut names = BTreeSet::new();
            for entry in std::fs::read_dir(path).map_err(|_| ActivationError::Storage)? {
                if names.len() >= profile_policy::MAX_PROVIDER_FILES {
                    return Err(ActivationError::Storage);
                }
                names.insert(
                    entry
                        .map_err(|_| ActivationError::Storage)?
                        .file_name()
                        .into_string()
                        .map_err(|_| ActivationError::Storage)?,
                );
            }
            if &names != expected {
                return Err(ActivationError::Storage);
            }
            Ok(())
        }
        fn read_file(path: &Path, max: u64) -> Result<Vec<u8>, ActivationError> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| ActivationError::Storage)?;
            let m = f.metadata().map_err(|_| ActivationError::Storage)?;
            if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 || m.len() > max {
                return Err(ActivationError::Storage);
            }
            let mut out = Vec::new();
            f.take(max + 1)
                .read_to_end(&mut out)
                .map_err(|_| ActivationError::Storage)?;
            if out.len() as u64 > max {
                return Err(ActivationError::Storage);
            }
            Ok(out)
        }
        let digest = |bytes: &[u8]| -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() };
        if !deployment_allowed()
            || uuid::Uuid::parse_str(&snapshot.snapshot_id).is_err()
            || snapshot.assets.len() > profile_policy::MAX_PROVIDER_FILES
            || (snapshot.running && snapshot.controller_port != 9090)
            || &snapshot.overlay != overlay
        {
            return Err(ActivationError::Invalid);
        }
        let history = Path::new("/etc/xkeenwrt/history");
        let hm = std::fs::symlink_metadata(history).map_err(|_| ActivationError::Storage)?;
        if !hm.is_dir() || hm.file_type().is_symlink() || hm.uid() != 0 || hm.mode() & 0o777 != 0o700 {
            return Err(ActivationError::Storage);
        }
        let root = history.join(&snapshot.snapshot_id);
        let mut top = BTreeSet::from(["config.yaml".to_owned()]);
        if !snapshot.assets.is_empty() {
            top.insert("assets".into());
        }
        inspect_dir(&root, &top)?;
        let secret = read_file(Path::new("/etc/xkeenwrt/controller-secret"), 64)?;
        if digest(&secret) != snapshot.controller_secret_sha256 || secret != self.secret.as_bytes() {
            return Err(ActivationError::Conflict);
        }
        let config = read_file(&root.join("config.yaml"), 1024 * 1024)?;
        if digest(&config) != snapshot.sha256 {
            return Err(ActivationError::Storage);
        }
        let config = String::from_utf8(config).map_err(|_| ActivationError::Storage)?;
        let mut grouped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for item in &snapshot.assets {
            let rest = item
                .relative_path
                .strip_prefix("providers/")
                .ok_or(ActivationError::Invalid)?;
            let (kind, name) = rest.split_once('/').ok_or(ActivationError::Invalid)?;
            if !matches!(kind, "proxies" | "rules")
                || !name.strip_suffix(".yaml").is_some_and(|n| {
                    n.parse::<u8>()
                        .is_ok_and(|i| usize::from(i) < profile_policy::MAX_PROVIDER_FILES && n == i.to_string())
                })
                || !grouped.entry(kind.to_owned()).or_default().insert(name.to_owned())
            {
                return Err(ActivationError::Invalid);
            }
        }
        let mut assets = Vec::new();
        let mut total = 0usize;
        if !snapshot.assets.is_empty() {
            let base = root.join("assets");
            inspect_dir(&base, &BTreeSet::from(["providers".to_owned()]))?;
            let providers = base.join("providers");
            inspect_dir(&providers, &grouped.keys().cloned().collect())?;
            for (kind, names) in &grouped {
                inspect_dir(&providers.join(kind), names)?;
            }
            for item in &snapshot.assets {
                let bytes = read_file(&base.join(&item.relative_path), 8 * 1024 * 1024)?;
                if bytes.len() as u64 != item.size || digest(&bytes) != item.sha256 {
                    return Err(ActivationError::Storage);
                }
                total = total.checked_add(bytes.len()).ok_or(ActivationError::Storage)?;
                if total > 8 * 1024 * 1024 {
                    return Err(ActivationError::Storage);
                }
                assets.push(profile_policy::Asset {
                    path: item.relative_path.clone(),
                    content: bytes,
                });
            }
        }
        if !profile_policy::complete_for(&config, &assets, overlay) {
            return Err(ActivationError::Invalid);
        }
        Ok((config, assets))
    }
    pub(crate) fn verify_pinned(&self, snapshot: &xkeenwrt_recovery::CoreSnapshot) -> Result<(), ActivationError> {
        self.read_pinned(snapshot, &snapshot.overlay).map(|_| ())
    }
    pub(crate) fn restore_pinned(&mut self, snapshot: &xkeenwrt_recovery::CoreSnapshot) -> Result<(), ActivationError> {
        let (config, assets) = self.read_pinned(snapshot, &snapshot.overlay)?;
        if snapshot.running {
            self.publish(Some(&config), &assets, &snapshot.overlay)
        } else {
            self.emergency_stop()
        }
    }
    pub(crate) fn snapshot_pin(
        &self, bundle: &crate::configuration::ValidatedBundle, running: bool,
    ) -> Result<xkeenwrt_recovery::CoreSnapshot, ActivationError> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        if !deployment_allowed()
            || bundle.assets.len() > profile_policy::MAX_PROVIDER_FILES
            || bundle.config.len() > 1024 * 1024
            || bundle.assets.iter().map(|a| a.content.len()).sum::<usize>() > 8 * 1024 * 1024
            || !profile_policy::complete_for(&bundle.config, &bundle.assets, &bundle.overlay)
        {
            return Err(ActivationError::Unavailable);
        }
        let bytes = bundle_bytes(bundle);
        super::resources::admit(bytes, bytes, self.reclaimable_memory())?;
        let document = profile_policy::parse_document(&bundle.config).map_err(|_| ActivationError::Invalid)?;
        if document.get("secret").and_then(serde_json::Value::as_str) != Some(self.secret.as_str()) {
            return Err(ActivationError::Conflict);
        }
        let mut secret = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open("/etc/xkeenwrt/controller-secret")
            .map_err(|_| ActivationError::Storage)?;
        let m = secret.metadata().map_err(|_| ActivationError::Storage)?;
        if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 || m.len() != 64 {
            return Err(ActivationError::Storage);
        }
        let mut value = String::new();
        secret
            .read_to_string(&mut value)
            .map_err(|_| ActivationError::Storage)?;
        if value != self.secret {
            return Err(ActivationError::Conflict);
        }
        let history = Path::new("/etc/xkeenwrt/history");
        private_dir(history)?;
        // The operation reserved its whole history cost before its first
        // write. Pinning never prunes, so it cannot remove a snapshot that
        // the same operation wrote and has not yet referenced from a journal.
        xkeenwrt_recovery::resources::history_fits(Path::new("/etc/xkeenwrt"), &snapshot_need(bundle))
            .map_err(|_| ActivationError::Storage)?;
        if std::fs::read_dir(history)
            .map_err(|_| ActivationError::Storage)?
            .take(129)
            .count()
            >= 128
        {
            return Err(ActivationError::Storage);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let stage = history.join(format!(".stage-{id}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage)
            .map_err(|_| ActivationError::Storage)?;
        let write = |path: &Path, bytes: &[u8]| -> Result<(), ActivationError> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| ActivationError::Storage)?;
            f.write_all(bytes).map_err(|_| ActivationError::Storage)?;
            f.sync_all().map_err(|_| ActivationError::Storage)
        };
        let digest = |bytes: &[u8]| -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() };
        write(&stage.join("config.yaml"), bundle.config.as_bytes())?;
        let mut records = Vec::new();
        if !bundle.assets.is_empty() {
            let assets_dir = stage.join("assets");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&assets_dir)
                .map_err(|_| ActivationError::Storage)?;
            let providers_dir = assets_dir.join("providers");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&providers_dir)
                .map_err(|_| ActivationError::Storage)?;
            for asset in &bundle.assets {
                let rest = asset.path.strip_prefix("providers/").ok_or(ActivationError::Invalid)?;
                let (kind, name) = rest.split_once('/').ok_or(ActivationError::Invalid)?;
                if !matches!(kind, "proxies" | "rules")
                    || !name.strip_suffix(".yaml").is_some_and(|n| {
                        n.parse::<u8>()
                            .is_ok_and(|i| usize::from(i) < profile_policy::MAX_PROVIDER_FILES && n == i.to_string())
                    })
                {
                    return Err(ActivationError::Invalid);
                }
                let kind_dir = providers_dir.join(kind);
                match std::fs::DirBuilder::new().mode(0o700).create(&kind_dir) {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(_) => return Err(ActivationError::Storage),
                }
                write(&kind_dir.join(name), &asset.content)?;
                records.push(xkeenwrt_recovery::SnapshotAsset {
                    relative_path: asset.path.clone(),
                    sha256: digest(&asset.content),
                    size: asset.content.len() as u64,
                });
            }
            for kind in ["proxies", "rules"] {
                let p = providers_dir.join(kind);
                if p.exists() {
                    std::fs::File::open(p)
                        .and_then(|d| d.sync_all())
                        .map_err(|_| ActivationError::Storage)?;
                }
            }
            std::fs::File::open(&providers_dir)
                .and_then(|d| d.sync_all())
                .map_err(|_| ActivationError::Storage)?;
            std::fs::File::open(&assets_dir)
                .and_then(|d| d.sync_all())
                .map_err(|_| ActivationError::Storage)?;
        }
        std::fs::File::open(&stage)
            .and_then(|d| d.sync_all())
            .map_err(|_| ActivationError::Storage)?;
        let history_fd = std::fs::File::open(history).map_err(|_| ActivationError::Storage)?;
        rustix::fs::renameat_with(
            &history_fd,
            format!(".stage-{id}"),
            &history_fd,
            id.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| ActivationError::Storage)?;
        history_fd.sync_all().map_err(|_| ActivationError::Storage)?;
        Ok(xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: id,
            sha256: digest(bundle.config.as_bytes()),
            controller_secret_sha256: digest(self.secret.as_bytes()),
            overlay: bundle.overlay.clone(),
            running,
            controller_port: if running { 9090 } else { 0 },
            assets: records,
        })
    }
    /// Memory of this project's verified running core. Every admission that
    /// calls this replaces or restarts that core, which releases it first.
    pub(crate) fn reclaimable_memory(&self) -> u64 {
        if self.running().unwrap_or(false) {
            super::grant::own_core_memory(&self.incarnation_cgroup)
        } else {
            0
        }
    }
    pub(crate) fn health(&self) -> Result<(), ActivationError> {
        if !deployment_allowed() {
            return Err(ActivationError::Unavailable);
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .map_err(|_| ActivationError::Unavailable)?;
        let response = client
            .get("http://127.0.0.1:9090/version")
            .bearer_auth(&self.secret)
            .send()
            .map_err(|_| ActivationError::Unavailable)?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 4096) {
            return Err(ActivationError::Unavailable);
        }
        let mut bytes = Vec::new();
        if response.take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 {
            return Err(ActivationError::Unavailable);
        }
        let version = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(str::to_owned));
        if !version
            .as_deref()
            .is_some_and(mihomo_release::active_api_version_matches)
            || crate::platform::Platform::service_status_in(self.operation_fd()).ok()
                != Some(crate::platform::ServiceStatus::Running)
        {
            return Err(ActivationError::Unavailable);
        }
        if let Some(e) = super::grant::selected_explicit()? {
            super::input_guard::verify(&e, &self.incarnation_cgroup)?;
        }
        Ok(())
    }
    pub(crate) fn publish_transient(
        &mut self, bundle: &crate::configuration::ValidatedBundle,
    ) -> Result<(), ActivationError> {
        if self.operation_cgroup.is_none() {
            return Err(ActivationError::Unavailable);
        }
        self.publish(Some(&bundle.config), &bundle.assets, &bundle.overlay)
    }
    pub(crate) fn publish(
        &mut self, config: Option<&str>, assets: &[profile_policy::Asset], overlay: &profile_policy::ManagedOverlay,
    ) -> Result<(), ActivationError> {
        let Some(config) = config else {
            return self.replace(None);
        };
        let ticket = self.prepare(config, assets, overlay)?;
        self.start_ticket(&ticket)
    }
    fn prepare(
        &mut self, config: &str, assets: &[profile_policy::Asset], overlay: &profile_policy::ManagedOverlay,
    ) -> Result<LaunchTicket, ActivationError> {
        use std::io::Write;
        ensure_no_lifecycle_request()?;
        if !deployment_allowed() || !profile_policy::complete_for(config, assets, overlay) {
            return Err(ActivationError::Unavailable);
        }
        super::grant::preflight_core_limits()?;
        super::resources::admit(
            config.len() as u64 + assets.iter().map(|a| a.content.len() as u64).sum::<u64>(),
            0,
            self.reclaimable_memory(),
        )?;
        for path in ["/tmp/xkeenwrt", "/tmp/xkeenwrt/runtime"] {
            private_dir(Path::new(path))?;
        }
        let base = Path::new("/tmp/xkeenwrt/runtime");
        // Interrupted swaps are cleaned only after validating their owned names and contents.
        for entry in std::fs::read_dir(base).map_err(|_| ActivationError::Storage)? {
            let entry = entry.map_err(|_| ActivationError::Storage)?;
            let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
            if let Some(id) = name
                .strip_prefix("retired-")
                .or_else(|| name.strip_prefix("candidate-"))
            {
                if uuid::Uuid::parse_str(id).is_err() {
                    return Err(ActivationError::Storage);
                }
                let _ = remove_owned_home(&entry.path());
            }
        }
        let staged = crate::mihomo::providers::stage_profile_assets(base, assets, config)
            .map_err(|_| ActivationError::Storage)?;
        let stage = staged.path().to_path_buf();
        let staged_file = stage.join("config.yaml");
        let prepared = (|| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&staged_file)
                .map_err(|_| ActivationError::Storage)?;
            f.write_all(config.as_bytes()).map_err(|_| ActivationError::Storage)?;
            f.sync_all().map_err(|_| ActivationError::Storage)?;
            std::fs::File::open(&stage)
                .and_then(|d| d.sync_all())
                .map_err(|_| ActivationError::Storage)
        })();
        if let Err(e) = prepared {
            let _ = std::fs::remove_file(staged_file);
            let _ = staged.cleanup();
            return Err(e);
        }
        if let Err(e) = self.replace(None) {
            let _ = std::fs::remove_file(staged_file);
            let _ = staged.cleanup();
            return Err(e);
        }
        ensure_no_lifecycle_request()?;
        let active = base.join("active");
        let retired = base.join(format!("retired-{}", uuid::Uuid::new_v4()));
        let had_old = match std::fs::symlink_metadata(&active) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o077 == 0 => {
                std::fs::rename(&active, &retired).map_err(|_| ActivationError::Storage)?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            _ => return Err(ActivationError::Storage),
        };
        let stage = staged.into_path();
        if std::fs::rename(&stage, &active).is_err() {
            if had_old {
                let _ = std::fs::rename(&retired, &active);
            }
            let _ = remove_owned_home(&stage);
            return Err(ActivationError::Storage);
        }
        std::fs::File::open(base)
            .and_then(|d| d.sync_all())
            .map_err(|_| ActivationError::Storage)?;
        ensure_no_lifecycle_request()?;
        super::input_guard::protect(overlay.explicit(), &self.incarnation_cgroup)?;
        let nonce = super::grant::issue(config, assets, overlay, &self.secret)?;
        Ok(LaunchTicket {
            nonce,
            retired: had_old.then_some(retired),
        })
    }
    fn start_ticket(&mut self, ticket: &LaunchTicket) -> Result<(), ActivationError> {
        ensure_no_lifecycle_request()?;
        if !super::grant::current(&ticket.nonce) {
            return Err(ActivationError::Conflict);
        }
        service("start", Some(&ticket.nonce), self.operation_fd())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            ensure_no_lifecycle_request()?;
            if !super::grant::current(&ticket.nonce) {
                return Err(ActivationError::Conflict);
            }
            if self.health().is_ok() {
                if let Some(retired) = &ticket.retired {
                    let _ = remove_owned_home(retired);
                    let _ = std::fs::File::open("/tmp/xkeenwrt/runtime").and_then(|d| d.sync_all());
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(ActivationError::Unavailable)
    }
}

#[cfg(test)]
mod snapshot_reuse_tests {
    use super::*;
    use crate::configuration::{ValidatedBundle, ValidatedCandidate};

    fn bundle(config: &str) -> ValidatedBundle {
        ValidatedBundle {
            meta: ValidatedCandidate {
                candidate_id: "candidate".into(),
                profile_id: "profile".into(),
                revision: "revision".into(),
                status: "validated".into(),
            },
            config: config.into(),
            assets: vec![profile_policy::Asset {
                path: "providers/rules/0.yaml".into(),
                content: b"payload: []\n".to_vec(),
            }],
            overlay: profile_policy::ManagedOverlay::Manual,
        }
    }
    fn pinned(running: bool) -> xkeenwrt_recovery::CoreSnapshot {
        xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000001".into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: "a".repeat(64),
            running,
            controller_port: if running { 9090 } else { 0 },
            controller_secret_sha256: "b".repeat(64),
            assets: vec![],
        }
    }

    #[test]
    fn identical_next_baseline_shares_the_previous_snapshot() {
        let previous = bundle("mode: rule\n");
        let shared = reuse_snapshot(&pinned(true), &previous, &bundle("mode: rule\n"), false)
            .expect("byte-identical contents need one snapshot");
        assert_eq!(shared.snapshot_id, pinned(true).snapshot_id);
        assert!(!shared.running);
        assert_eq!(shared.controller_port, 0);
        assert!(reuse_snapshot(&pinned(false), &previous, &bundle("mode: global\n"), false).is_none());
        let mut other_assets = bundle("mode: rule\n");
        other_assets.assets[0].content = b"payload: [x]\n".to_vec();
        assert!(reuse_snapshot(&pinned(false), &previous, &other_assets, false).is_none());
    }

    #[test]
    fn snapshot_need_counts_every_staged_entry() {
        let need = snapshot_need(&bundle("mode: rule\n"));
        assert_eq!(need.entries, 7);
        assert_eq!(need.snapshots, 1);
        assert_eq!(need.bytes, ("mode: rule\n".len() + "payload: []\n".len()) as u64);
    }
}
