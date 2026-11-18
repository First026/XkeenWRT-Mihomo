//! Asset-free, immutable previous core restoration. No data from HTTP is executed.
use crate::commands::{core_action, core_is_stopped, core_pid};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};
use xkeenwrt_recovery::CoreSnapshot;
fn private_read(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > max
    {
        return Err(io::Error::other("unsafe snapshot file"));
    }
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::other("snapshot too large"));
    }
    Ok(bytes)
}
fn private_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe core directory"));
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn exact_entries(dir: &Path, expected: &std::collections::BTreeSet<String>) -> io::Result<()> {
    if &entries(dir)? != expected {
        return Err(io::Error::other("snapshot contents mismatch"));
    }
    Ok(())
}
fn entries(dir: &Path) -> io::Result<std::collections::BTreeSet<String>> {
    let mut actual = std::collections::BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        if actual.len() >= profile_policy::MAX_PROVIDER_FILES {
            return Err(io::Error::other("snapshot has too many entries"));
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("non-UTF8 snapshot entry"))?;
        if !actual.insert(name) {
            return Err(io::Error::other("duplicate snapshot entry"));
        }
    }
    Ok(actual)
}
struct Bundle {
    config: Vec<u8>,
    assets: Vec<(String, Vec<u8>)>,
}
/// The pinned snapshot a restore needs is absent or no longer matches its
/// journal record. The restore cannot proceed; callers fall back to Direct.
#[derive(Debug)]
pub(crate) struct SnapshotUnavailable {
    pub snapshot_id: String,
    reason: String,
}
impl std::fmt::Display for SnapshotUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SNAPSHOT_MISSING snapshot={}: {}",
            self.snapshot_id, self.reason
        )
    }
}
impl std::error::Error for SnapshotUnavailable {}
pub(crate) fn snapshot_unavailable(error: &io::Error) -> Option<&SnapshotUnavailable> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<SnapshotUnavailable>())
}
fn read_bundle(snapshot: &CoreSnapshot) -> io::Result<Bundle> {
    read_bundle_at(Path::new("/etc/xkeenwrt/history"), snapshot)
}
fn read_bundle_at(history: &Path, snapshot: &CoreSnapshot) -> io::Result<Bundle> {
    read_bundle_from(history, snapshot).map_err(|error| {
        io::Error::other(SnapshotUnavailable {
            snapshot_id: snapshot.snapshot_id.clone(),
            reason: error.to_string(),
        })
    })
}
fn read_bundle_from(history: &Path, snapshot: &CoreSnapshot) -> io::Result<Bundle> {
    private_dir(history)?;
    let root = history.join(&snapshot.snapshot_id);
    let root = root
        .to_str()
        .ok_or_else(|| io::Error::other("invalid snapshot path"))?;
    private_dir(Path::new(&root))?;
    let mut root_expected = std::collections::BTreeSet::from(["config.yaml".to_owned()]);
    if !snapshot.assets.is_empty() {
        root_expected.insert("assets".to_owned());
    }
    exact_entries(Path::new(&root), &root_expected)?;
    let config = private_read(&Path::new(&root).join("config.yaml"), 1024 * 1024)?;
    if hex(&config) != snapshot.sha256 {
        return Err(io::Error::other("snapshot digest mismatch"));
    }
    let mut total = 0u64;
    let mut assets = Vec::new();
    if !snapshot.assets.is_empty() {
        private_dir(&Path::new(&root).join("assets"))?;
        private_dir(&Path::new(&root).join("assets/providers"))?;
        exact_entries(
            &Path::new(&root).join("assets"),
            &std::collections::BTreeSet::from(["providers".to_owned()]),
        )?;
        let mut kinds = std::collections::BTreeSet::new();
        for asset in &snapshot.assets {
            if let Some((kind, _)) = asset
                .relative_path
                .strip_prefix("providers/")
                .and_then(|s| s.split_once('/'))
            {
                kinds.insert(kind.to_owned());
            }
        }
        exact_entries(&Path::new(&root).join("assets/providers"), &kinds)?;
        for kind in &kinds {
            private_dir(&Path::new(&root).join("assets/providers").join(kind))?;
            let names: std::collections::BTreeSet<String> = snapshot
                .assets
                .iter()
                .filter_map(|asset| {
                    asset
                        .relative_path
                        .strip_prefix(&format!("providers/{kind}/"))
                        .map(str::to_owned)
                })
                .collect();
            exact_entries(
                &Path::new(&root).join("assets/providers").join(kind),
                &names,
            )?;
        }
    }
    for asset in &snapshot.assets {
        let parent = Path::new(&root).join("assets").join(&asset.relative_path);
        private_dir(
            parent
                .parent()
                .ok_or_else(|| io::Error::other("invalid asset path"))?,
        )?;
        let bytes = private_read(&parent, 8 * 1024 * 1024)?;
        if bytes.len() as u64 != asset.size || hex(&bytes) != asset.sha256 {
            return Err(io::Error::other("asset digest mismatch"));
        }
        total = total
            .checked_add(asset.size)
            .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
        if total > 8 * 1024 * 1024 {
            return Err(io::Error::other("snapshot too large"));
        }
        assets.push((asset.relative_path.clone(), bytes));
    }
    let text = std::str::from_utf8(&config).map_err(io::Error::other)?;
    let policy_assets: Vec<profile_policy::Asset> = assets
        .iter()
        .map(|(path, content)| profile_policy::Asset {
            path: path.clone(),
            content: content.clone(),
        })
        .collect();
    if !profile_policy::complete_for(text, &policy_assets, &snapshot.overlay) {
        return Err(io::Error::other("snapshot violates managed overlay"));
    }
    Ok(Bundle { config, assets })
}
/// Compare the entire private active home with the pinned bundle, including
/// the exact provider directory shape; no unexpected files are accepted.
pub(crate) fn verify_active_home(snapshot: &CoreSnapshot) -> io::Result<()> {
    let bundle = read_bundle(snapshot)?;
    let root = Path::new("/tmp/xkeenwrt/runtime/active");
    private_dir(Path::new("/tmp/xkeenwrt"))?;
    private_dir(Path::new("/tmp/xkeenwrt/runtime"))?;
    private_dir(root)?;
    let mut entries = std::collections::BTreeSet::from(["config.yaml".to_owned()]);
    if !bundle.assets.is_empty() {
        entries.insert("providers".to_owned());
    }
    let mut actual = self::entries(root)?;
    actual.remove("cache.db");
    if actual != entries {
        return Err(io::Error::other("active contents mismatch"));
    }
    // Presence is optional across the two reads: the genuine core may lazily
    // create its cache. Every immutable entry stays exact and cache metadata
    // is checked if present, including a file created after readdir.
    xkeenwrt_recovery::core_cache::present(root)?;
    if private_read(&root.join("config.yaml"), 1024 * 1024)? != bundle.config {
        return Err(io::Error::other(
            "active configuration differs from snapshot",
        ));
    }
    if !bundle.assets.is_empty() {
        let providers = root.join("providers");
        private_dir(&providers)?;
        let mut kinds = std::collections::BTreeSet::new();
        for (relative, _) in &bundle.assets {
            let (kind, _) = relative
                .strip_prefix("providers/")
                .and_then(|v| v.split_once('/'))
                .ok_or_else(|| io::Error::other("invalid provider path"))?;
            kinds.insert(kind.to_owned());
        }
        exact_entries(&providers, &kinds)?;
        for kind in kinds {
            let dir = providers.join(&kind);
            private_dir(&dir)?;
            let names = bundle
                .assets
                .iter()
                .filter_map(|(relative, _)| {
                    relative
                        .strip_prefix(&format!("providers/{kind}/"))
                        .map(str::to_owned)
                })
                .collect();
            exact_entries(&dir, &names)?;
        }
        for (relative, bytes) in &bundle.assets {
            if private_read(&root.join(relative), 8 * 1024 * 1024)? != *bytes {
                return Err(io::Error::other("active asset differs from snapshot"));
            }
        }
    }
    Ok(())
}
pub fn preflight(snapshot: &CoreSnapshot) -> io::Result<()> {
    let _ = read_bundle(snapshot)?;
    let _ = secret(snapshot)?;
    Ok(())
}
pub(crate) fn secret(snapshot: &CoreSnapshot) -> io::Result<String> {
    let bytes = private_read(Path::new("/etc/xkeenwrt/controller-secret"), 1024)?;
    if hex(&bytes) != snapshot.controller_secret_sha256 {
        return Err(io::Error::other("controller secret digest mismatch"));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(io::Error::other)?
        .trim_end_matches('\n');
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(io::Error::other("invalid controller secret"));
    }
    Ok(value.to_owned())
}
pub(crate) fn health(port: u16, secret: &str) -> io::Result<()> {
    health_until(port, secret, Instant::now() + Duration::from_secs(3))
}
fn health_until(port: u16, secret: &str, until: Instant) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    while Instant::now() < until {
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            stream.set_write_timeout(Some(Duration::from_millis(200)))?;
            let request = format!(
                "GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                secret
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = Vec::new();
                let mut buf = [0u8; 1024];
                while Instant::now() < until && response.len() < 16384 {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => response.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                if let Some(split) = response.windows(4).position(|v| v == b"\r\n\r\n")
                    && (response.starts_with(b"HTTP/1.1 200 ")
                        || response.starts_with(b"HTTP/1.0 200 "))
                    && serde_json::from_slice::<serde_json::Value>(&response[split + 4..])
                        .ok()
                        .and_then(|v| v.get("version").and_then(|v| v.as_str()).map(str::to_owned))
                        .as_deref()
                        .is_some_and(mihomo_release::active_api_version_matches)
                {
                    return Ok(());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "previous core health failed",
    ))
}
pub(crate) fn fresh_nonce() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn store_grant(grant: &xkeenwrt_recovery::LaunchGrant) -> io::Result<()> {
    if !grant.valid() {
        return Err(io::Error::other("invalid launch grant"));
    }
    let dir = Path::new("/var/run/xkeenwrt");
    let temp = dir.join(format!(".launch-{}-{}", std::process::id(), grant.nonce));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    serde_json::to_writer(&mut file, grant).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp, dir.join("launch.json"))?;
    fs::File::open(dir)?.sync_all()
}
pub fn publish_launch(snapshot: &CoreSnapshot, desired_running: bool) -> io::Result<String> {
    let nonce = fresh_nonce()?;
    let grant =
        xkeenwrt_recovery::LaunchGrant::from_snapshot(snapshot, nonce.clone(), desired_running)?;
    store_grant(&grant)?;
    Ok(nonce)
}
pub fn revoke_existing_launch() -> io::Result<()> {
    let path = Path::new("/var/run/xkeenwrt/launch.json");
    let bytes = match private_read(path, 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut grant: xkeenwrt_recovery::LaunchGrant =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if !grant.valid() {
        return Err(io::Error::other("invalid existing launch grant"));
    }
    grant.nonce = fresh_nonce()?;
    grant.desired_running = false;
    store_grant(&grant)
}

fn ensure_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    private_dir(path)
}
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
fn exchange(from: &Path, to: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let a = CString::new(from.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let b = CString::new(to.as_os_str().as_bytes()).map_err(io::Error::other)?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            2u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn stop_confirm() -> io::Result<()> {
    let original = match core_pid()? {
        Some(pid) => crate::process_identity(pid)?.map(|(_, start)| (pid, start)),
        None => None,
    };
    core_action("stop", None)?;
    crate::fence::quiesce_core()?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let old_gone = match original {
            Some((pid, start)) => crate::process_identity(pid)?
                .is_none_or(|(state, current)| state == "Z" || current != start),
            None => true,
        };
        if core_is_stopped()? && old_gone {
            crate::input_guard::protect(None)?;
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "core did not stop"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
/// Without a usable snapshot the core cannot be restored: revoke its launch
/// grant and stop it. Explicit inputs stay closed (`stop_confirm`).
pub(crate) fn stop_without_snapshot() -> io::Result<()> {
    revoke_existing_launch()?;
    stop_confirm()
}
/// Restore `snapshot`, or stop the core when that snapshot is unusable.
/// Returns the unusable snapshot ID; any other failure stays an error.
pub(crate) fn restore_or_stop(snapshot: &CoreSnapshot) -> io::Result<Option<String>> {
    match restore(snapshot) {
        Ok(()) => Ok(None),
        Err(error) => {
            let Some(missing) = snapshot_unavailable(&error) else {
                return Err(error);
            };
            let id = missing.snapshot_id.clone();
            stop_without_snapshot()?;
            Ok(Some(id))
        }
    }
}
pub fn restore(snapshot: &CoreSnapshot) -> io::Result<()> {
    let bundle = read_bundle(snapshot)?;
    let _ = secret(snapshot)?;
    ensure_dir(Path::new("/tmp/xkeenwrt"))?;
    let runtime = Path::new("/tmp/xkeenwrt/runtime");
    ensure_dir(runtime)?;
    let mut stage = None;
    for attempt in 0..32 {
        let candidate = runtime.join(format!(
            ".recovery-stage-{}-{}",
            std::process::id(),
            attempt
        ));
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => {
                private_dir(&candidate)?;
                stage = Some(candidate);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let stage = stage.ok_or_else(|| io::Error::other("no safe staging directory"))?;
    write_private(
        &stage.join(".xkeenwrt-recovery-owned"),
        b"xkeenwrt-recovery-stage-v1\n",
    )?;
    write_private(&stage.join("config.yaml"), &bundle.config)?;
    if !bundle.assets.is_empty() {
        ensure_dir(&stage.join("providers"))?;
    }
    for (relative, bytes) in &bundle.assets {
        let path = stage.join(relative);
        ensure_dir(
            path.parent()
                .ok_or_else(|| io::Error::other("invalid asset"))?,
        )?;
        write_private(&path, bytes)?;
    }
    for dir in ["providers/proxies", "providers/rules", "providers"] {
        let path = stage.join(dir);
        if path.exists() {
            fs::File::open(path)?.sync_all()?;
        }
    }
    fs::remove_file(stage.join(".xkeenwrt-recovery-owned"))?;
    fs::File::open(&stage)?.sync_all()?;
    let _ = publish_launch(snapshot, false)?;
    stop_confirm()?;
    crate::fence::configure_core_limits()?;
    let active = runtime.join("active");
    match fs::symlink_metadata(&active) {
        Ok(_) => {
            private_dir(&active)?;
            exchange(&stage, &active)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::rename(&stage, &active)?,
        Err(e) => return Err(e),
    }
    fs::File::open(runtime)?.sync_all()?;
    if stage.exists() {
        // The old managed home is now at this private stage path. Marking it is
        // best-effort only and must never delay restarting the previous core.
        let _ = write_private(
            &stage.join(".xkeenwrt-recovery-owned"),
            b"xkeenwrt-recovery-stage-v1\n",
        );
    }
    crate::input_guard::protect(if snapshot.running {
        snapshot.overlay.explicit()
    } else {
        None
    })?;
    if snapshot.running {
        let secret = secret(snapshot)?;
        let nonce = publish_launch(snapshot, true)?;
        core_action("start", Some(&nonce))?;
        // Match the backend's ten-second start-and-health window. One shared
        // deadline prevents the supervisor from spending ten seconds starting
        // and then another ten seconds probing an unhealthy core.
        let until = Instant::now() + Duration::from_secs(10);
        while core_is_stopped()? {
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "core did not start",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        health_until(snapshot.controller_port, &secret, until)?;
        if core_is_stopped()? {
            return Err(io::Error::other("core exited after health check"));
        }
    }
    // Cleanup cannot invalidate a successfully restored core. Unknown or unsafe
    // paths are left intact for later inspection.
    let _ = cleanup_stale(runtime);
    Ok(())
}

fn cleanup_stale(runtime: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    fn inspect(path: &Path, device: u64, depth: usize, count: &mut usize) -> io::Result<()> {
        if depth > 5 || *count >= 128 {
            return Err(io::Error::other("cleanup limit"));
        }
        *count += 1;
        let meta = fs::symlink_metadata(path)?;
        if meta.dev() != device || meta.uid() != 0 || meta.file_type().is_symlink() {
            return Err(io::Error::other("unsafe cleanup entry"));
        }
        if meta.is_dir() {
            if meta.mode() & 0o777 != 0o700 {
                return Err(io::Error::other("unsafe cleanup directory"));
            }
            for entry in fs::read_dir(path)? {
                inspect(&entry?.path(), device, depth + 1, count)?;
            }
        } else if !meta.is_file() || meta.nlink() != 1 {
            return Err(io::Error::other("unsafe cleanup file"));
        }
        Ok(())
    }
    let mut count = 0usize;
    for entry in fs::read_dir(runtime)?.take(64) {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(suffix) = name.strip_prefix(".recovery-stage-") else {
            continue;
        };
        let Some((pid, seq)) = suffix.split_once('-') else {
            continue;
        };
        if pid.is_empty()
            || seq.is_empty()
            || !pid.bytes().all(|c| c.is_ascii_digit())
            || !seq.bytes().all(|c| c.is_ascii_digit())
        {
            continue;
        }
        let path = entry.path();
        if private_dir(&path).is_err() {
            continue;
        }
        if private_read(&path.join(".xkeenwrt-recovery-owned"), 64)
            .ok()
            .as_deref()
            != Some(b"xkeenwrt-recovery-stage-v1\n")
        {
            continue;
        }
        let dev = fs::symlink_metadata(&path)?.dev();
        if inspect(&path, dev, 0, &mut count).is_err() {
            continue;
        }
        let _ = fs::remove_dir_all(&path);
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_unavailable_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn snapshot(id: &str, config: &[u8]) -> CoreSnapshot {
        CoreSnapshot {
            snapshot_id: id.into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: hex(config),
            running: false,
            controller_port: 0,
            controller_secret_sha256: "b".repeat(64),
            assets: vec![],
        }
    }
    fn history() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("xkeen-r26-t5-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    #[test]
    fn missing_or_corrupt_rollback_snapshot_is_typed_with_its_id() {
        let history = history();
        let id = "00000000-0000-4000-8000-000000000042";
        let error = read_bundle_at(&history, &snapshot(id, b"mode: rule\n"))
            .err()
            .expect("missing snapshot");
        assert_eq!(
            snapshot_unavailable(&error).map(|s| s.snapshot_id.as_str()),
            Some(id)
        );
        assert!(error.to_string().contains("SNAPSHOT_MISSING"));
        assert!(error.to_string().contains(id));

        let dir = history.join(id);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        write_private(&dir.join("config.yaml"), b"mode: global\n").unwrap();
        fs::set_permissions(dir.join("config.yaml"), fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_bundle_at(&history, &snapshot(id, b"mode: rule\n"))
            .err()
            .expect("corrupt snapshot");
        assert!(snapshot_unavailable(&error).is_some());
        assert!(error.to_string().contains("digest mismatch"));
        fs::remove_dir_all(history).unwrap();
    }
}
