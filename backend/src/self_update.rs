//! Panel self-update (decision 026).
//!
//! The panel lists the project's GitHub releases. For a newer one it runs that
//! release's own `install.sh` — the Quick Start installer, which checks both
//! APKs by SHA-256 and upgrades the stopped pair in place — inside a transient
//! procd service. The APK upgrade restarts the panel; the transient service
//! outlives it and leaves its log and exit code in a root-private directory,
//! which the new panel reports. The repository is fixed at build time and no
//! request can supply a URL, path or command.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

pub const REPO: &str = "First026/XkeenWRT-Mihomo";
const API_BASE: &str = "https://api.github.com";
const RAW_BASE: &str = "https://raw.githubusercontent.com";
pub const WORK_DIR: &str = "/tmp/xkeenwrt-self-update";
pub const SERVICE: &str = "xkeenwrt-self-update";
const CATALOG_MAX: usize = 1 << 20;
const INSTALLER_MAX: usize = 64 * 1024;
const NOTES_MAX: usize = 16 * 1024;
const LOG_TAIL_BYTES: u64 = 64 * 1024;
const LOG_LINES: usize = 200;
const LOG_LINE_MAX: usize = 400;
/// procd starts the instance asynchronously: a fresh run without an exit code
/// counts as starting, not interrupted, for this long.
pub const START_GRACE: Duration = Duration::from_secs(60);
/// Fixed program of the transient service. It never contains request data:
/// the installer it runs was fetched for an exact listed tag and checked first.
const RUNNER: &str = "umask 077\n\
cd /tmp/xkeenwrt-self-update || exit 1\n\
sh ./install.sh > log 2>&1\n\
echo $? > exit.new && mv exit.new exit\n";

/// A release version: 2 to 5 decimal components, no leading zeros.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(Vec<u32>);

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split('.').collect();
        if !(2..=5).contains(&parts.len()) {
            return None;
        }
        let mut out = Vec::with_capacity(parts.len());
        for part in parts {
            if part.is_empty()
                || part.len() > 6
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return None;
            }
            out.push(part.parse().ok()?);
        }
        Some(Self(out))
    }
    /// `v0.1.26.4`
    pub fn from_tag(tag: &str) -> Option<Self> {
        tag.strip_prefix('v').and_then(Self::parse)
    }
    /// `0.1.26.4-r0`, the APK version embedded in the panel.
    pub fn from_package(package: &str) -> Option<Self> {
        let (version, release) = package.rsplit_once("-r")?;
        if release.is_empty() || release.len() > 4 || !release.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Self::parse(version)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u32::to_string).collect();
        f.write_str(&parts.join("."))
    }
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub version: String,
    pub published: String,
    pub notes: String,
    pub current: bool,
}

/// The installed release and every newer published one, oldest first. Drafts,
/// pre-releases, foreign tag shapes and older releases are not offered:
/// a panel update only moves forward.
pub fn catalog(json: &[u8], current: &Version) -> Result<Vec<Entry>, &'static str> {
    let releases: Vec<GhRelease> = serde_json::from_slice(json).map_err(|_| "GITHUB_UNAVAILABLE")?;
    let mut found: Vec<(Version, Entry)> = Vec::new();
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(version) = Version::from_tag(&release.tag_name) else {
            continue;
        };
        if version < *current || found.iter().any(|(v, _)| *v == version) {
            continue;
        }
        let published = release
            .published_at
            .as_deref()
            .and_then(|p| p.get(..10))
            .filter(|d| d.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
            .unwrap_or("")
            .to_owned();
        let mut notes = release.body.unwrap_or_default();
        if notes.len() > NOTES_MAX {
            let mut end = NOTES_MAX;
            while !notes.is_char_boundary(end) {
                end -= 1;
            }
            notes.truncate(end);
            notes.push('…');
        }
        let entry = Entry {
            version: version.to_string(),
            published,
            notes,
            current: version == *current,
        };
        found.push((version, entry));
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found.into_iter().map(|(_, e)| e).collect())
}

/// The fetched installer must be the release's own Quick Start script for
/// exactly this version of this repository.
pub fn check_installer(script: &[u8], version: &Version) -> Result<(), &'static str> {
    const INVALID: &str = "INSTALLER_INVALID";
    if script.len() > INSTALLER_MAX || script.contains(&0) {
        return Err(INVALID);
    }
    let text = std::str::from_utf8(script).map_err(|_| INVALID)?;
    if !text.starts_with("#!/bin/sh\n") {
        return Err(INVALID);
    }
    let version_prefix = format!("version={version}-r");
    let tag_line = format!("tag=v{version}");
    let repo_line = format!("repo={REPO}");
    let lines: Vec<&str> = text.lines().collect();
    let version_ok = lines.iter().any(|line| {
        line.strip_prefix(&version_prefix)
            .is_some_and(|r| !r.is_empty() && r.len() <= 4 && r.bytes().all(|b| b.is_ascii_digit()))
    });
    if !version_ok || !lines.contains(&tag_line.as_str()) || !lines.contains(&repo_line.as_str()) {
        return Err(INVALID);
    }
    Ok(())
}

/// `ubus call service set` payload for the transient installer service. The
/// optional download proxy is the one the panel itself was started with.
pub fn service_request(proxy: Option<&str>) -> serde_json::Value {
    let mut env = serde_json::Map::new();
    env.insert("PATH".into(), "/usr/sbin:/usr/bin:/sbin:/bin".into());
    if let Some(proxy) = proxy.filter(|p| valid_proxy(p)) {
        env.insert("HTTPS_PROXY".into(), proxy.into());
        env.insert("https_proxy".into(), proxy.into());
    }
    serde_json::json!({
        "name": SERVICE,
        "instances": {"run": {"command": ["/bin/sh", "-c", RUNNER], "env": env}},
    })
}

fn valid_proxy(proxy: &str) -> bool {
    (proxy.starts_with("http://") || proxy.starts_with("https://"))
        && proxy.len() <= 2048
        && !proxy.chars().any(char::is_control)
}

/// What `ubus call service list {"name":SERVICE}` says about the installer
/// instance. `None` means procd's answer is unknown: callers must then treat
/// the installer as possibly running and never remove it or its directory.
pub fn instance_running(json: &str) -> Option<bool> {
    let value = serde_json::from_str::<serde_json::Value>(json).ok()?;
    let Some(service) = value.get(SERVICE) else {
        return value.as_object().map(|_| false);
    };
    Some(
        service
            .get("instances")
            .and_then(|i| i.get("run"))
            .and_then(|r| r.get("running"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    )
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Status {
    /// `idle`, `running`, `done`, `failed` or `interrupted`.
    pub state: &'static str,
    pub target: Option<String>,
    pub exit_code: Option<i32>,
    pub log: Vec<String>,
}

/// `running` is procd's answer; unknown (`None`) never makes a run look interrupted.
pub fn read_status(dir: &Path, running: Option<bool>, start_grace: Duration) -> Status {
    let read_small = |name: &str| -> Option<String> {
        let mut text = String::new();
        open_private(&dir.join(name))
            .ok()?
            .take(64)
            .read_to_string(&mut text)
            .ok()?;
        Some(text.trim().to_owned())
    };
    let Some(target) = read_small("target").filter(|t| Version::parse(t).is_some()) else {
        return Status {
            state: "idle",
            target: None,
            exit_code: None,
            log: Vec::new(),
        };
    };
    let exit_code = read_small("exit").and_then(|e| e.parse::<i32>().ok());
    let starting = || {
        open_private(&dir.join("target"))
            .and_then(|f| f.metadata()?.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < start_grace)
    };
    let state = match exit_code {
        Some(0) => "done",
        Some(_) => "failed",
        None if running != Some(false) || starting() => "running",
        None => "interrupted",
    };
    Status {
        state,
        target: Some(target),
        exit_code,
        log: read_log(&dir.join("log")),
    }
}

fn read_log(path: &Path) -> Vec<String> {
    let Ok(mut file) = open_private(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<String> = text
        .lines()
        .skip(usize::from(start > 0))
        .map(|line| {
            let clean: String = line.chars().filter(|c| !c.is_control() || *c == '\t').collect();
            clean.chars().take(LOG_LINE_MAX).collect::<String>()
        })
        .filter(|line| !line.trim().is_empty())
        .collect();
    let excess = lines.len().saturating_sub(LOG_LINES);
    lines.drain(..excess);
    lines
}

fn open_private(path: &Path) -> std::io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // The result is written by the panel version that started the run, in a
    // root-only 0700 directory: refuse only files others could have changed.
    if !meta.is_file() || meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o022 != 0 {
        return Err(std::io::Error::other("unsafe self-update file"));
    }
    Ok(file)
}

/// A fresh root-private work directory holding only the checked installer and
/// the target version; any earlier run's files are removed first.
pub fn prepare_work_dir(dir: &Path, script: &[u8], version: &Version) -> std::io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() || meta.uid() != nix::unistd::geteuid().as_raw() {
                return Err(std::io::Error::other("unsafe self-update directory"));
            }
            fs::remove_dir_all(dir)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let write = |name: &str, bytes: &[u8]| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(dir.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    write("install.sh", script)?;
    write("target", format!("{version}\n").as_bytes())
}

/// Errors are response codes of `/api/self/*`.
pub struct Updater {
    launch: tokio::sync::Mutex<()>,
}

impl Default for Updater {
    fn default() -> Self {
        Self {
            launch: tokio::sync::Mutex::new(()),
        }
    }
}

impl Updater {
    pub async fn catalog(&self) -> Result<(Version, Vec<Entry>), &'static str> {
        let current = installed_version().ok_or("UNSUPPORTED")?;
        let client = client()?;
        let url = format!("{API_BASE}/repos/{REPO}/releases?per_page=30");
        let json = fetch(&client, &url, "application/vnd.github+json", CATALOG_MAX).await?;
        Ok((current.clone(), catalog(&json, &current)?))
    }

    pub async fn start(&self, requested: &str) -> Result<(), &'static str> {
        let current = installed_version().ok_or("UNSUPPORTED")?;
        let version = Version::parse(requested).ok_or("UNKNOWN_RELEASE")?;
        if version <= current {
            return Err("NOT_NEWER");
        }
        let _launch = self.launch.try_lock().map_err(|_| "UPDATE_RUNNING")?;
        self.ensure_idle().await?;
        let (_, entries) = self.catalog().await?;
        if !entries.iter().any(|e| e.version == version.to_string()) {
            return Err("UNKNOWN_RELEASE");
        }
        let client = client()?;
        let url = format!("{RAW_BASE}/{REPO}/v{version}/install.sh");
        let script = fetch(&client, &url, "text/plain", INSTALLER_MAX).await?;
        check_installer(&script, &version)?;
        let dir = Path::new(WORK_DIR).to_path_buf();
        let prepared = version.clone();
        // The fetches took time: recheck right before the directory is replaced.
        self.ensure_idle().await?;
        tokio::task::spawn_blocking(move || prepare_work_dir(&dir, &script, &prepared))
            .await
            .map_err(|_| "UPDATE_LAUNCH_FAILED")?
            .map_err(|_| "UPDATE_LAUNCH_FAILED")?;
        let _ = ubus(&["call", "service", "delete", &format!(r#"{{"name":"{SERVICE}"}}"#)]).await;
        let proxy = std::env::var("HTTPS_PROXY").ok();
        let request = service_request(proxy.as_deref()).to_string();
        match ubus(&["call", "service", "set", &request]).await {
            Some(_) => Ok(()),
            None => Err("UPDATE_LAUNCH_FAILED"),
        }
    }

    /// A new run may replace the directory only when procd confirms that no
    /// installer instance runs and no recent run is still starting.
    async fn ensure_idle(&self) -> Result<(), &'static str> {
        match service_running().await {
            Some(false) => {}
            Some(true) => return Err("UPDATE_RUNNING"),
            None => return Err("UPDATE_LAUNCH_FAILED"),
        }
        let state = tokio::task::spawn_blocking(|| read_status(Path::new(WORK_DIR), Some(false), START_GRACE).state)
            .await
            .map_err(|_| "UPDATE_LAUNCH_FAILED")?;
        if state == "running" {
            return Err("UPDATE_RUNNING");
        }
        Ok(())
    }

    /// The finished transient service is removed once its exit code is read.
    pub async fn status(&self) -> Status {
        let running = service_running().await;
        let status = tokio::task::spawn_blocking(move || read_status(Path::new(WORK_DIR), running, START_GRACE))
            .await
            .unwrap_or(Status {
                state: "idle",
                target: None,
                exit_code: None,
                log: Vec::new(),
            });
        if running == Some(false) && matches!(status.state, "done" | "failed") {
            let _ = ubus(&["call", "service", "delete", &format!(r#"{{"name":"{SERVICE}"}}"#)]).await;
        }
        status
    }
}

fn installed_version() -> Option<Version> {
    Version::from_package(option_env!("XKEENWRT_PACKAGE_VERSION")?)
}

fn client() -> Result<reqwest::Client, &'static str> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .user_agent("xkeenwrt-panel")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "GITHUB_UNAVAILABLE")
}

async fn fetch(client: &reqwest::Client, url: &str, accept: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    const UNAVAILABLE: &str = "GITHUB_UNAVAILABLE";
    let mut response = client
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .map_err(|_| UNAVAILABLE)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err("UNKNOWN_RELEASE");
    }
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > max as u64) {
        return Err(UNAVAILABLE);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| UNAVAILABLE)? {
        if body.len() + chunk.len() > max {
            return Err(UNAVAILABLE);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn service_running() -> Option<bool> {
    let out = ubus(&["call", "service", "list", &format!(r#"{{"name":"{SERVICE}"}}"#)]).await?;
    instance_running(&out)
}

async fn ubus(args: &[&str]) -> Option<String> {
    let mut command = tokio::process::Command::new("/bin/ubus");
    command
        .arg("-t")
        .arg("5")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(8), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn versions_parse_strictly_and_order_like_apk() {
        assert_eq!(Version::from_package("0.1.26.4-r0"), Some(v("0.1.26.4")));
        assert_eq!(Version::from_tag("v0.1.26.4"), Some(v("0.1.26.4")));
        for bad in [
            "",
            "1",
            "0.1.",
            "0.01.2",
            "0.1.2.3.4.5",
            "0.1.-2",
            "0.1.2a",
            "1.2.1234567",
            " 0.1",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
        for bad in ["0.1.26.4", "0.1.26.4-r", "0.1.26.4-rx", "development"] {
            assert_eq!(Version::from_package(bad), None, "{bad:?}");
        }
        assert_eq!(Version::from_tag("0.1.26.4"), None);
        assert!(v("0.1.26.4") < v("0.1.26.4.1"));
        assert!(v("0.1.26.10") > v("0.1.26.9"));
        assert!(v("0.1.27") > v("0.1.26.9"));
        assert_eq!(v("0.1.26.4").to_string(), "0.1.26.4");
    }

    #[test]
    fn catalog_offers_the_installed_and_newer_releases_only() {
        let json = br#"[
            {"tag_name":"v0.1.26.6","body":"six","published_at":"2026-12-01T10:00:00Z"},
            {"tag_name":"v0.1.26.5","draft":true},
            {"tag_name":"v0.1.26.5-rc1","prerelease":true},
            {"tag_name":"v0.1.27","prerelease":true},
            {"tag_name":"v0.1.26.4","body":"four","published_at":"2026-11-18T12:00:00Z"},
            {"tag_name":"v0.1.26.3","body":"three"},
            {"tag_name":"latest"},
            {"tag_name":"v0.1.26.6","body":"duplicate"}
        ]"#;
        let entries = catalog(json, &v("0.1.26.4")).unwrap();
        let versions: Vec<&str> = entries.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(versions, ["0.1.26.4", "0.1.26.6"]);
        assert!(entries[0].current && !entries[1].current);
        assert_eq!(entries[1].notes, "six");
        assert_eq!(entries[1].published, "2026-12-01");
        assert_eq!(catalog(b"{}", &v("0.1.26.4")), Err("GITHUB_UNAVAILABLE"));
    }

    #[test]
    fn catalog_bounds_release_notes() {
        let long = "ж".repeat(NOTES_MAX);
        let json = serde_json::json!([{"tag_name":"v0.1.26.5","body":long}]).to_string();
        let entries = catalog(json.as_bytes(), &v("0.1.26.4")).unwrap();
        assert!(entries[0].notes.len() <= NOTES_MAX + '…'.len_utf8());
        assert!(entries[0].notes.ends_with('…'));
    }

    #[test]
    fn installer_must_be_this_release_of_this_repository() {
        let tree = include_str!("../../install.sh");
        let line = tree.lines().find_map(|l| l.strip_prefix("version=")).unwrap();
        let version = Version::from_package(line).unwrap();
        assert_eq!(check_installer(tree.as_bytes(), &version), Ok(()));
        let other = Version::parse("9.9.9").unwrap();
        assert_eq!(check_installer(tree.as_bytes(), &other), Err("INSTALLER_INVALID"));
        let ok = "#!/bin/sh\nversion=0.1.26.5-r0\ntag=v0.1.26.5\nrepo=First026/XkeenWRT-Mihomo\n";
        assert_eq!(check_installer(ok.as_bytes(), &v("0.1.26.5")), Ok(()));
        for bad in [
            ok.replace("#!/bin/sh\n", "#!/bin/bash\n"),
            ok.replace("repo=First026/XkeenWRT-Mihomo", "repo=someone/fork"),
            ok.replace("tag=v0.1.26.5", "tag=v0.1.26.6"),
            ok.replace("version=0.1.26.5-r0", "version=0.1.26.5"),
            format!("{ok}\0"),
            format!("{ok}{}", "#".repeat(INSTALLER_MAX)),
        ] {
            assert_eq!(
                check_installer(bad.as_bytes(), &v("0.1.26.5")),
                Err("INSTALLER_INVALID")
            );
        }
    }

    #[test]
    fn transient_service_runs_a_fixed_program() {
        let request = service_request(None);
        assert_eq!(request["name"], SERVICE);
        let command = &request["instances"]["run"]["command"];
        assert_eq!(command[0], "/bin/sh");
        assert_eq!(command[1], "-c");
        assert_eq!(command[2], RUNNER);
        assert!(RUNNER.starts_with("umask 077\n"));
        assert!(request["instances"]["run"].get("respawn").is_none());
        assert!(request["instances"]["run"]["env"].get("HTTPS_PROXY").is_none());
        let proxied = service_request(Some("http://10.0.0.2:3128"));
        assert_eq!(
            proxied["instances"]["run"]["env"]["HTTPS_PROXY"],
            "http://10.0.0.2:3128"
        );
        for bad in ["socks5://x", "http://x\ny", "ftp://x"] {
            assert!(
                service_request(Some(bad))["instances"]["run"]["env"]
                    .get("HTTPS_PROXY")
                    .is_none()
            );
        }
    }

    #[test]
    fn running_instance_is_read_from_procd() {
        let running = format!(r#"{{"{SERVICE}":{{"instances":{{"run":{{"running":true,"pid":42}}}}}}}}"#);
        let stopped = format!(r#"{{"{SERVICE}":{{"instances":{{"run":{{"running":false,"exit_code":0}}}}}}}}"#);
        assert_eq!(instance_running(&running), Some(true));
        assert_eq!(instance_running(&stopped), Some(false));
        assert_eq!(instance_running("{}"), Some(false), "no such service");
        assert_eq!(instance_running("not json"), None);
        assert_eq!(instance_running("[]"), None);
    }

    #[test]
    fn status_follows_the_work_directory() {
        let dir = std::env::temp_dir().join(format!("xk-self-update-{}", uuid::Uuid::new_v4()));
        let grace = START_GRACE;
        assert_eq!(read_status(&dir, Some(false), grace).state, "idle");
        prepare_work_dir(&dir, b"#!/bin/sh\n", &v("0.1.26.5")).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.join("install.sh")).unwrap().mode() & 0o777, 0o600);
        let running = read_status(&dir, Some(true), grace);
        assert_eq!(
            (running.state, running.target.as_deref()),
            ("running", Some("0.1.26.5"))
        );
        assert_eq!(
            read_status(&dir, Some(false), grace).state,
            "running",
            "procd has not started it yet"
        );
        let old = std::time::SystemTime::now() - Duration::from_secs(120);
        fs::File::options()
            .write(true)
            .open(dir.join("target"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(read_status(&dir, Some(false), grace).state, "interrupted");
        assert_eq!(
            read_status(&dir, None, grace).state,
            "running",
            "an unknown procd answer never interrupts a run"
        );
        let private = |name: &str, text: &str| {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(dir.join(name))
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        };
        private("log", "Загрузка\n\x1b[31mshown\x1b[0m\n\n");
        private("exit", "1\n");
        let failed = read_status(&dir, Some(false), grace);
        assert_eq!((failed.state, failed.exit_code), ("failed", Some(1)));
        assert_eq!(failed.log, ["Загрузка", "[31mshown[0m"]);
        private("exit", "0\n");
        assert_eq!(read_status(&dir, Some(false), grace).state, "done");
        fs::set_permissions(dir.join("exit"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_status(&dir, Some(false), grace).state,
            "done",
            "procd's umask 022 result is accepted in the private directory"
        );
        fs::set_permissions(dir.join("exit"), fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(
            read_status(&dir, Some(false), grace).state,
            "interrupted",
            "a result others could change is not trusted"
        );
        prepare_work_dir(&dir, b"#!/bin/sh\n", &v("0.1.26.6")).unwrap();
        let fresh = read_status(&dir, Some(true), grace);
        assert_eq!((fresh.target.as_deref(), fresh.log.len()), (Some("0.1.26.6"), 0));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn work_directory_must_not_be_a_symlink() {
        let base = std::env::temp_dir().join(format!("xk-self-update-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&base).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert!(prepare_work_dir(&link, b"#!/bin/sh\n", &v("0.1.26.5")).is_err());
        assert!(base.exists());
        fs::remove_dir_all(&base).unwrap();
    }
}
