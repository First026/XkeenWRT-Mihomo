//! Fixed launch grant: a late procd start cannot use a revoked nonce.
use crate::configuration::ActivationError;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use xkeenwrt_recovery::{LaunchGrant, SnapshotAsset};
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const OWNED_CORE_CONTROLLERS: [&str; 2] = ["memory", "pids"];
fn limits_match(values: &[String]) -> bool {
    values.len() == xkeenwrt_recovery::CORE_CGROUP_LIMITS.len()
        && values
            .iter()
            .zip(xkeenwrt_recovery::CORE_CGROUP_LIMITS)
            .all(|(actual, (_, expected))| actual.trim() == expected)
}
fn core_cgroup_file(name: &str, write: bool) -> Result<std::fs::File, ActivationError> {
    let path = Path::new("/sys/fs/cgroup/xkeenwrt/core").join(name);
    let f = std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| ActivationError::Unavailable)?;
    let m = f.metadata().map_err(|_| ActivationError::Unavailable)?;
    let mut fs: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !m.is_file()
        || m.uid() != 0
        || unsafe { nix::libc::fstatfs(f.as_raw_fd(), &mut fs) } != 0
        || fs.f_type as u64 != 0x63677270
    {
        return Err(ActivationError::Unavailable);
    }
    Ok(f)
}
fn read_core_cgroup(name: &str) -> Result<String, ActivationError> {
    let mut text = String::new();
    core_cgroup_file(name, false)?
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| ActivationError::Unavailable)?;
    if text.len() > 128 {
        return Err(ActivationError::Unavailable);
    }
    Ok(text)
}
fn verify_core_limits() -> Result<(), ActivationError> {
    let values = xkeenwrt_recovery::CORE_CGROUP_LIMITS
        .iter()
        .map(|(name, _)| read_core_cgroup(name))
        .collect::<Result<Vec<_>, _>>()?;
    if limits_match(&values) {
        Ok(())
    } else {
        Err(ActivationError::Unavailable)
    }
}
fn prepare_core_limits() -> Result<(), ActivationError> {
    ensure_core_cgroup()?;
    if !read_core_cgroup("cgroup.events")?
        .lines()
        .any(|line| line == "populated 0")
    {
        return Err(ActivationError::Unavailable);
    }
    for (name, value) in xkeenwrt_recovery::CORE_CGROUP_LIMITS {
        core_cgroup_file(name, true)?
            .write_all(value.as_bytes())
            .map_err(|_| ActivationError::Unavailable)?;
    }
    verify_core_limits()
}
/// Memory charged to this project's running core, which an operation that
/// replaces or stops the core releases first (decision 023). Counted only for
/// the single verified Mihomo process in the dedicated core cgroup whose PID
/// and start time are unchanged across the reading; anything else is zero.
pub(crate) fn own_core_memory(cgroup: &File) -> u64 {
    let read = || -> Result<u64, ActivationError> {
        let identity = super::networking::helper::core_identity(cgroup).map_err(|_| ActivationError::Unavailable)?;
        let procs = read_core_cgroup("cgroup.procs")?;
        if procs.lines().filter(|line| !line.is_empty()).collect::<Vec<_>>() != [identity.0.to_string()] {
            return Err(ActivationError::Unavailable);
        }
        let current = read_core_cgroup("memory.current")?
            .trim()
            .parse::<u64>()
            .map_err(|_| ActivationError::Unavailable)?;
        if super::networking::helper::core_identity(cgroup).ok() != Some(identity)
            || read_core_cgroup("cgroup.procs")? != procs
        {
            return Err(ActivationError::Unavailable);
        }
        Ok(current)
    };
    read().unwrap_or(0)
}
pub(crate) fn preflight_core_limits() -> Result<(), ActivationError> {
    ensure_core_cgroup()?;
    for (name, _) in xkeenwrt_recovery::CORE_CGROUP_LIMITS {
        let _ = core_cgroup_file(name, true)?;
        let _ = read_core_cgroup(name)?;
    }
    Ok(())
}
fn open_cgroup_file_at(dir: &File, name: &CStr, write: bool) -> Result<File, ActivationError> {
    let access = if write {
        nix::libc::O_WRONLY
    } else {
        nix::libc::O_RDONLY
    };
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            access | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(ActivationError::Unavailable);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| ActivationError::Unavailable)?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_file()
        || metadata.uid() != 0
        || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(ActivationError::Unavailable);
    }
    Ok(file)
}
fn read_cgroup_file_at(dir: &File, name: &CStr) -> Result<String, ActivationError> {
    let mut text = String::new();
    open_cgroup_file_at(dir, name, false)?
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|_| ActivationError::Unavailable)?;
    if text.len() > 4096 {
        return Err(ActivationError::Unavailable);
    }
    Ok(text)
}
fn controller_tokens(text: &str) -> Result<BTreeSet<String>, ActivationError> {
    if text.len() > 4096 {
        return Err(ActivationError::Unavailable);
    }
    let mut tokens = BTreeSet::new();
    for token in text.split_ascii_whitespace() {
        if !token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !tokens.insert(token.to_owned())
        {
            return Err(ActivationError::Unavailable);
        }
    }
    Ok(tokens)
}
fn ensure_subtree_controllers<F>(
    available: &str, enabled: &str, direct_processes: &str, mut write_and_readback: F,
) -> Result<(), ActivationError>
where
    F: FnMut(Option<&str>) -> Result<String, ActivationError>,
{
    if !direct_processes.is_empty() {
        return Err(ActivationError::Unavailable);
    }
    let available = controller_tokens(available)?;
    let enabled = controller_tokens(enabled)?;
    if !enabled.is_subset(&available)
        || OWNED_CORE_CONTROLLERS
            .iter()
            .any(|controller| !available.contains(*controller))
    {
        return Err(ActivationError::Unavailable);
    }
    let additions: Vec<_> = OWNED_CORE_CONTROLLERS
        .iter()
        .copied()
        .filter(|controller| !enabled.contains(*controller))
        .collect();
    let command = additions
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>()
        .join(" ");
    let after = write_and_readback((!command.is_empty()).then_some(command.as_str()))?;
    let after = controller_tokens(&after)?;
    if !after.is_subset(&available)
        || !enabled.is_subset(&after)
        || OWNED_CORE_CONTROLLERS
            .iter()
            .any(|controller| !after.contains(*controller))
    {
        return Err(ActivationError::Unavailable);
    }
    Ok(())
}
fn open_cgroup_directory(path: &Path, private: bool) -> Result<File, ActivationError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ActivationError::Unavailable)?;
    verify_cgroup_directory(&file, path, private)?;
    Ok(file)
}
fn open_cgroup_child(parent: &File, name: &CStr, path: &Path, private: bool) -> Result<File, ActivationError> {
    let fd = unsafe {
        nix::libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            nix::libc::O_RDONLY | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ActivationError::Unavailable);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    verify_cgroup_directory(&file, path, private)?;
    Ok(file)
}
fn ensure_cgroup_child(parent: &File, name: &CStr, path: &Path) -> Result<File, ActivationError> {
    let created = unsafe { nix::libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
    if !created && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err(ActivationError::Unavailable);
    }
    let child = open_cgroup_child(parent, name, path, !created)?;
    if created && unsafe { nix::libc::fchmod(child.as_raw_fd(), 0o700) } != 0 {
        return Err(ActivationError::Unavailable);
    }
    verify_cgroup_directory(&child, path, true)?;
    Ok(child)
}
fn verify_cgroup_directory(file: &File, path: &Path, private: bool) -> Result<(), ActivationError> {
    let metadata = file.metadata().map_err(|_| ActivationError::Unavailable)?;
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_dir()
        || metadata.uid() != 0
        || (private && metadata.mode() & 0o777 != 0o700)
        || (!private && metadata.mode() & 0o022 != 0)
        || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(ActivationError::Unavailable);
    }
    let pinned_path =
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| ActivationError::Unavailable)?;
    let by_path = std::fs::symlink_metadata(path).map_err(|_| ActivationError::Unavailable)?;
    if pinned_path != path
        || !by_path.is_dir()
        || by_path.file_type().is_symlink()
        || by_path.uid() != 0
        || by_path.dev() != metadata.dev()
        || by_path.ino() != metadata.ino()
        || (private && by_path.mode() & 0o777 != 0o700)
        || (!private && by_path.mode() & 0o022 != 0)
    {
        return Err(ActivationError::Unavailable);
    }
    Ok(())
}
fn ensure_owned_subtree_controllers(parent: &File) -> Result<(), ActivationError> {
    let available = read_cgroup_file_at(parent, c"cgroup.controllers")?;
    let enabled = read_cgroup_file_at(parent, c"cgroup.subtree_control")?;
    let mut processes = open_cgroup_file_at(parent, c"cgroup.procs", false)?;
    let mut first = [0u8; 1];
    let direct_processes = if processes.read(&mut first).map_err(|_| ActivationError::Unavailable)? == 0 {
        ""
    } else {
        "occupied"
    };
    ensure_subtree_controllers(&available, &enabled, direct_processes, |command| {
        if let Some(command) = command {
            open_cgroup_file_at(parent, c"cgroup.subtree_control", true)?
                .write_all(command.as_bytes())
                .map_err(|_| ActivationError::Unavailable)?;
        }
        read_cgroup_file_at(parent, c"cgroup.subtree_control")
    })
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|x| format!("{x:02x}")).collect()
}
pub(crate) fn ensure_core_cgroup() -> Result<(), ActivationError> {
    if !super::core::deployment_allowed() {
        return Err(ActivationError::Unavailable);
    }
    let root_path = Path::new("/sys/fs/cgroup");
    let root = open_cgroup_directory(root_path, false)?;
    // OpenWrt mounts cgroup v2 without delegating controllers by default.
    // The root cgroup is exempt from the no-internal-process restriction.
    // Add only our required controllers; never remove another service's ones.
    let available = read_cgroup_file_at(&root, c"cgroup.controllers")?;
    let enabled = read_cgroup_file_at(&root, c"cgroup.subtree_control")?;
    ensure_subtree_controllers(&available, &enabled, "", |command| {
        if let Some(command) = command {
            open_cgroup_file_at(&root, c"cgroup.subtree_control", true)?
                .write_all(command.as_bytes())
                .map_err(|_| ActivationError::Unavailable)?;
        }
        read_cgroup_file_at(&root, c"cgroup.subtree_control")
    })?;
    let validation_path = root_path.join("xkeenwrt-validation");
    let validation = ensure_cgroup_child(&root, c"xkeenwrt-validation", &validation_path)?;
    ensure_owned_subtree_controllers(&validation)?;
    let owned_path = root_path.join("xkeenwrt");
    let owned = ensure_cgroup_child(&root, c"xkeenwrt", &owned_path)?;
    let core_path = owned_path.join("core");
    let core = ensure_cgroup_child(&owned, c"core", &core_path)?;
    for name in [c"cgroup.procs", c"cgroup.kill", c"cgroup.events"] {
        let _ = open_cgroup_file_at(&core, name, false)?;
    }
    ensure_owned_subtree_controllers(&owned)?;
    let child_controllers = controller_tokens(&read_cgroup_file_at(&core, c"cgroup.controllers")?)?;
    if OWNED_CORE_CONTROLLERS
        .iter()
        .any(|controller| !child_controllers.contains(*controller))
    {
        return Err(ActivationError::Unavailable);
    }
    Ok(())
}
fn private_file(path: &Path, limit: u64) -> Result<Vec<u8>, ActivationError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ActivationError::Storage)?;
    let m = f.metadata().map_err(|_| ActivationError::Storage)?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 || m.len() > limit {
        return Err(ActivationError::Storage);
    }
    let mut bytes = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActivationError::Storage)?;
    if bytes.len() as u64 > limit {
        return Err(ActivationError::Storage);
    }
    Ok(bytes)
}
fn directory(path: &Path, expected: &BTreeSet<String>) -> Result<(), ActivationError> {
    let m = std::fs::symlink_metadata(path).map_err(|_| ActivationError::Storage)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(ActivationError::Storage);
    }
    let mut names = BTreeSet::new();
    for item in std::fs::read_dir(path).map_err(|_| ActivationError::Storage)? {
        if names.len() >= profile_policy::MAX_PROVIDER_FILES {
            return Err(ActivationError::Storage);
        }
        names.insert(
            item.map_err(|_| ActivationError::Storage)?
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
fn join_core_cgroup() -> Result<(), ActivationError> {
    use std::os::fd::AsRawFd;
    let path = Path::new("/sys/fs/cgroup/xkeenwrt/core/cgroup.procs");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ActivationError::Unavailable)?;
    let m = file.metadata().map_err(|_| ActivationError::Unavailable)?;
    let link =
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| ActivationError::Unavailable)?;
    let mut fs: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if link != path
        || !m.is_file()
        || m.uid() != 0
        || unsafe { nix::libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0
        || fs.f_type as u64 != 0x63677270
    {
        return Err(ActivationError::Unavailable);
    }
    file.write_all(b"0\n").map_err(|_| ActivationError::Unavailable)?;
    let mut membership = String::new();
    std::fs::File::open("/proc/self/cgroup")
        .map_err(|_| ActivationError::Unavailable)?
        .take(4097)
        .read_to_string(&mut membership)
        .map_err(|_| ActivationError::Unavailable)?;
    if membership.len() > 4096 || !membership.lines().any(|line| line == "0::/xkeenwrt/core") {
        return Err(ActivationError::Unavailable);
    }
    let mut members = String::new();
    std::fs::File::open(path)
        .map_err(|_| ActivationError::Unavailable)?
        .take(65537)
        .read_to_string(&mut members)
        .map_err(|_| ActivationError::Unavailable)?;
    let pid = std::process::id().to_string();
    if members.len() > 65536 || !members.lines().any(|line| line == pid) {
        return Err(ActivationError::Unavailable);
    }
    Ok(())
}
fn publish(grant: &LaunchGrant) -> Result<(), ActivationError> {
    let dir = Path::new("/var/run/xkeenwrt");
    let m = std::fs::symlink_metadata(dir).map_err(|_| ActivationError::Storage)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(ActivationError::Storage);
    }
    let tmp = dir.join(format!(".grant-{}", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec(grant).map_err(|_| ActivationError::Storage)?;
    if bytes.len() > 16384 {
        return Err(ActivationError::Storage);
    }
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|_| ActivationError::Storage)?;
        f.write_all(&bytes).map_err(|_| ActivationError::Storage)?;
        f.sync_all().map_err(|_| ActivationError::Storage)?;
        std::fs::rename(&tmp, dir.join("launch.json")).map_err(|_| ActivationError::Storage)?;
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| ActivationError::Storage)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}
pub(crate) fn read_current() -> Result<Option<LaunchGrant>, ActivationError> {
    let path = Path::new("/var/run/xkeenwrt/launch.json");
    if matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    let bytes = private_file(path, 16384)?;
    let grant: LaunchGrant = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Storage)?;
    if !grant.valid() {
        return Err(ActivationError::Storage);
    }
    Ok(Some(grant))
}
pub(crate) fn selected_explicit() -> Result<Option<profile_policy::ExplicitOverlay>, ActivationError> {
    Ok(read_current()?
        .filter(|g| g.desired_running)
        .and_then(|g| g.overlay.explicit().cloned()))
}
pub(crate) fn revoke() -> Result<(), ActivationError> {
    if let Some(mut grant) = read_current()? {
        grant.desired_running = false;
        grant.nonce = uuid::Uuid::new_v4().to_string();
        return publish(&grant);
    }
    let grant = LaunchGrant {
        version: 1,
        nonce: uuid::Uuid::new_v4().to_string(),
        desired_running: false,
        config_sha256: "0".repeat(64),
        controller_secret_sha256: "0".repeat(64),
        assets: vec![],
        overlay: profile_policy::ManagedOverlay::Manual,
    };
    publish(&grant)
}
pub(crate) fn current(nonce: &str) -> bool {
    private_file(Path::new("/var/run/xkeenwrt/launch.json"), 16384)
        .ok()
        .and_then(|data| serde_json::from_slice::<LaunchGrant>(&data).ok())
        .is_some_and(|grant| grant.version == 1 && grant.desired_running && grant.nonce == nonce)
}
pub(crate) fn issue(
    config: &str, assets: &[profile_policy::Asset], overlay: &profile_policy::ManagedOverlay, secret: &str,
) -> Result<String, ActivationError> {
    super::core::ensure_no_lifecycle_request()?;
    prepare_core_limits()?;
    if !profile_policy::complete_for(config, assets, overlay)
        || assets.len() > profile_policy::MAX_PROVIDER_FILES
        || config.len() > 1024 * 1024
        || assets.iter().map(|a| a.content.len()).sum::<usize>() > 8 * 1024 * 1024
    {
        return Err(ActivationError::Invalid);
    }
    let nonce = uuid::Uuid::new_v4().to_string();
    let grant = LaunchGrant {
        version: 1,
        nonce: nonce.clone(),
        desired_running: true,
        config_sha256: hash(config.as_bytes()),
        controller_secret_sha256: hash(secret.as_bytes()),
        assets: assets
            .iter()
            .map(|a| SnapshotAsset {
                relative_path: a.path.clone(),
                sha256: hash(&a.content),
                size: a.content.len() as u64,
            })
            .collect(),
        overlay: overlay.clone(),
    };
    publish(&grant)?;
    Ok(nonce)
}
/// Validate only the fixed active home and execute only the packaged core.
pub fn exec(expected_nonce: &str) -> Result<(), ActivationError> {
    if !super::core::deployment_allowed() || uuid::Uuid::parse_str(expected_nonce).is_err() {
        return Err(ActivationError::Unavailable);
    }
    join_core_cgroup()?;
    verify_core_limits()?;
    super::core::ensure_no_lifecycle_request()?;
    let bytes = private_file(Path::new("/var/run/xkeenwrt/launch.json"), 16384)?;
    let grant: LaunchGrant = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Storage)?;
    if grant.version != 1
        || !grant.desired_running
        || grant.nonce != expected_nonce
        || grant.assets.len() > profile_policy::MAX_PROVIDER_FILES
    {
        return Err(ActivationError::Conflict);
    }
    let secret = private_file(Path::new("/etc/xkeenwrt/controller-secret"), 64)?;
    if secret.len() != 64 || hash(&secret) != grant.controller_secret_sha256 {
        return Err(ActivationError::Conflict);
    }
    let root = Path::new("/tmp/xkeenwrt/runtime/active");
    let mut top = BTreeSet::from(["config.yaml".to_string()]);
    if !grant.assets.is_empty() {
        top.insert("providers".into());
    }
    directory(root, &top)?;
    let config = private_file(&root.join("config.yaml"), 1024 * 1024)?;
    if hash(&config) != grant.config_sha256 {
        return Err(ActivationError::Conflict);
    }
    let config = String::from_utf8(config).map_err(|_| ActivationError::Invalid)?;
    if profile_policy::parse_document(&config)
        .map_err(|_| ActivationError::Invalid)?
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .map(str::as_bytes)
        != Some(secret.as_slice())
    {
        return Err(ActivationError::Conflict);
    }
    let mut grouped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in &grant.assets {
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
            || !grouped.entry(kind.into()).or_default().insert(name.into())
        {
            return Err(ActivationError::Invalid);
        }
    }
    let mut total = 0usize;
    let mut assets = Vec::new();
    if !grant.assets.is_empty() {
        let providers = root.join("providers");
        directory(&providers, &grouped.keys().cloned().collect())?;
        for (kind, names) in &grouped {
            directory(&providers.join(kind), names)?;
        }
        for item in &grant.assets {
            let data = private_file(&root.join(&item.relative_path), 8 * 1024 * 1024)?;
            if data.len() as u64 != item.size || hash(&data) != item.sha256 {
                return Err(ActivationError::Conflict);
            }
            total = total.checked_add(data.len()).ok_or(ActivationError::Invalid)?;
            if total > 8 * 1024 * 1024 {
                return Err(ActivationError::Invalid);
            }
            assets.push(profile_policy::Asset {
                path: item.relative_path.clone(),
                content: data,
            });
        }
    }
    if !profile_policy::complete_for(&config, &assets, &grant.overlay) {
        return Err(ActivationError::Invalid);
    }
    let executable = crate::platform::Platform::verified_component(crate::platform::VerifiedComponent::Core, None)
        .ok_or(ActivationError::Unavailable)?;
    // Re-read after expensive hashing to reject a grant revoked during preflight.
    let current = private_file(Path::new("/var/run/xkeenwrt/launch.json"), 16384)?;
    if current != bytes {
        return Err(ActivationError::Conflict);
    }
    super::core::ensure_no_lifecycle_request()?;
    verify_core_limits()?;
    let file_limit = nix::libc::rlimit {
        rlim_cur: 16 * 1024 * 1024,
        rlim_max: 16 * 1024 * 1024,
    };
    if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_FSIZE, &file_limit) } != 0 {
        return Err(ActivationError::Unavailable);
    }
    let argv = [
        c"mihomo".as_ptr(),
        c"-d".as_ptr(),
        c"/tmp/xkeenwrt/runtime/active".as_ptr(),
        c"-f".as_ptr(),
        c"/tmp/xkeenwrt/runtime/active/config.yaml".as_ptr(),
        std::ptr::null(),
    ];
    let env = [c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(), std::ptr::null()];
    unsafe {
        // Mihomo opens its lazy cache with mode 0666. Keep that mutable state
        // private without admitting it to the immutable launch bundle.
        nix::libc::umask(0o077);
        nix::libc::fexecve(executable.as_raw_fd(), argv.as_ptr(), env.as_ptr());
    }
    Err(ActivationError::Unavailable)
}

#[cfg(test)]
mod resource_tests {
    #[test]
    fn core_limits_require_every_exact_value() {
        let values: Vec<String> = xkeenwrt_recovery::CORE_CGROUP_LIMITS
            .iter()
            .map(|(_, v)| format!("{v}\n"))
            .collect();
        assert!(super::limits_match(&values));
        let mut changed = values.clone();
        changed[0] = "max\n".into();
        assert!(!super::limits_match(&changed));
        assert!(!super::limits_match(&values[..3]));
    }

    #[test]
    fn own_cgroup_delegation_adds_memory_and_pids_without_removing_existing_controllers() {
        let enabled = std::cell::RefCell::new(String::from("cpu"));
        let mut writes = Vec::new();
        super::ensure_subtree_controllers("cpu io memory pids", "cpu", "", |command| {
            if let Some(command) = command {
                writes.push(command.to_owned());
                for token in command.split_ascii_whitespace() {
                    let controller = token.strip_prefix('+').unwrap();
                    if !enabled.borrow().split_ascii_whitespace().any(|v| v == controller) {
                        let mut current = enabled.borrow_mut();
                        if !current.is_empty() {
                            current.push(' ');
                        }
                        current.push_str(controller);
                    }
                }
            }
            Ok(enabled.borrow().clone())
        })
        .unwrap();

        assert_eq!(writes, ["+memory +pids"]);
        assert_eq!(*enabled.borrow(), "cpu memory pids");
    }
}
