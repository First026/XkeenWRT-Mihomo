//! Pinned Mihomo installer. The release catalogue is fixed to the OpenWrt AArch64 ABI.
use crate::core_catalog::{self, Release};
use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;

const ROOT: &str = "/usr/libexec/xkeenwrt/cores";
const ACTIVE: &str = "/etc/xkeenwrt/mihomo-active";
const PREVIOUS: &str = "/etc/xkeenwrt/mihomo-previous";
const FREE_RESERVE: u64 = 32 * 1024 * 1024;
const RAM_RESERVE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: String,
    pub seq: u64,
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloaded: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Job {
    events: Mutex<Vec<Event>>,
    sender: tokio::sync::broadcast::Sender<Event>,
    cancel: AtomicBool,
    finished: AtomicBool,
    committing: Mutex<bool>,
}
impl Job {
    fn new() -> Arc<Self> {
        let (sender, _) = tokio::sync::broadcast::channel(64);
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            sender,
            cancel: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            committing: Mutex::new(false),
        })
    }
    fn emit(&self, mut event: Event) {
        let mut events = self.events.lock().unwrap();
        event.seq = events.last().map_or(1, |last| last.seq.saturating_add(1));
        events.push(event.clone());
        if events.len() > 200 {
            let excess = events.len() - 200;
            events.drain(..excess);
        }
        drop(events);
        let _ = self.sender.send(event);
    }
    fn event(kind: &str) -> Event {
        Event {
            kind: kind.into(),
            seq: 0,
            ts: chrono::Utc::now().to_rfc3339(),
            stage: None,
            level: None,
            message: None,
            downloaded: None,
            total: None,
            speed: None,
            success: None,
            error: None,
        }
    }
    fn log(&self, message: &str, level: &str) {
        let mut event = Self::event("log");
        event.message = Some(message.into());
        event.level = Some(level.into());
        self.emit(event);
    }
    fn stage(&self, stage: &str) {
        let mut event = Self::event("stage");
        event.stage = Some(stage.into());
        self.emit(event);
    }
    fn progress(&self, downloaded: u64, total: u64, speed: u64) {
        let mut event = Self::event("progress");
        event.downloaded = Some(downloaded);
        event.total = Some(total);
        event.speed = Some(speed);
        self.emit(event);
    }
    fn done(&self, result: Result<(), &'static str>) {
        let mut event = Self::event("done");
        event.success = Some(result.is_ok());
        event.error = result.err().map(str::to_owned);
        if let Some(error) = &event.error {
            event.level = Some("error".into());
            event.message = Some(error.clone());
        }
        self.emit(event);
        self.finished.store(true, Ordering::Release);
    }
    fn history(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub struct Manager {
    job: Mutex<Option<Arc<Job>>>,
}
impl Manager {
    pub fn new() -> Self {
        Self::default()
    }
    fn current_job(&self) -> Option<Arc<Job>> {
        self.job.lock().unwrap().clone()
    }
    pub fn events(&self) -> Option<(Vec<Event>, tokio::sync::broadcast::Receiver<Event>)> {
        let job = self.current_job()?;
        let receiver = job.sender.subscribe();
        Some((job.history(), receiver))
    }
    pub fn start(self: &Arc<Self>, version: &str) -> Result<(), &'static str> {
        let release = core_catalog::release(version).ok_or("Unsupported Mihomo release")?;
        let job = Job::new();
        {
            let mut current = self.job.lock().unwrap();
            if current
                .as_ref()
                .is_some_and(|existing| !existing.finished.load(Ordering::Acquire))
            {
                return Err("A Mihomo update is already running");
            }
            *current = Some(job.clone());
        }
        let release = *release;
        tokio::spawn(async move {
            job.stage("prepare");
            job.log("Подготовка проверки места и каталога ядра", "info");
            let result = download_and_install(&job, &release).await;
            match result {
                Ok(()) => job.log("✓ Mihomo установлен и проверен", "info"),
                Err(error) => job.log(
                    error,
                    if error.contains("Отменено") {
                        "warn"
                    } else {
                        "error"
                    },
                ),
            }
            job.done(result);
        });
        Ok(())
    }
    pub fn cancel(&self) -> Result<(), &'static str> {
        let Some(job) = self.current_job() else {
            return Err("No Mihomo update is running");
        };
        if job.finished.load(Ordering::Acquire) {
            return Err("Mihomo update is already complete");
        }
        let committing = job.committing.lock().unwrap();
        if *committing {
            return Err("Version switch has already begun");
        }
        job.cancel.store(true, Ordering::Release);
        drop(committing);
        job.log("Запрошена отмена загрузки", "warn");
        Ok(())
    }
    pub fn rollback(&self) -> Result<String, &'static str> {
        if self
            .current_job()
            .is_some_and(|job| !job.finished.load(Ordering::Acquire))
        {
            return Err("A Mihomo update is running");
        }
        let previous = read_version_file(Path::new(PREVIOUS))?.ok_or("No previous Mihomo version is recorded")?;
        request_selection(previous.clone())?;
        Ok(previous)
    }
    pub fn catalog(&self) -> serde_json::Value {
        let (installed, integrity) = match read_active_release() {
            Ok(Some(release)) if verified_release_file(release).is_some() => {
                (Some(release.version.to_owned()), "verified")
            }
            Ok(Some(_)) | Err(_) => (None, "invalid"),
            Ok(None) => (None, "not_installed"),
        };
        let releases: Vec<_> = core_catalog::RELEASES
            .iter()
            .map(|release| {
                serde_json::json!({
                    "version":release.version,
                    "published":release.published,
                    "assetSize":release.archive_size,
                    "assetSha256":release.archive_sha256,
                    "elfSize":release.elf_size,
                    "elfSha256":release.elf_sha256,
                    "installed":installed.as_deref()==Some(release.version),
                })
            })
            .collect();
        serde_json::json!({"success":true,"architecture":"aarch64_cortex-a53","installedVersion":installed,"integrity":integrity,"releases":releases})
    }
}

pub fn installed_core_valid() -> bool {
    match read_active_release() {
        Ok(None) => true,
        Ok(Some(release)) => verified_release_file(release).is_some(),
        Err(_) => false,
    }
}

pub fn require_validation_core() -> Result<(), crate::configuration::ActivationError> {
    use crate::configuration::ActivationError;
    match read_active_release() {
        Ok(None) => Err(ActivationError::CoreMissing),
        Ok(Some(release)) if verified_release_file(release).is_some() => Ok(()),
        _ => Err(ActivationError::CoreIntegrity),
    }
}

pub fn open_active_core() -> Option<(File, String)> {
    let release = read_active_release().ok()??;
    let file = verified_release_file(release)?;
    Some((file, release.elf_sha256.to_owned()))
}

fn read_version_file(path: &Path) -> Result<Option<String>, &'static str> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Mihomo version marker is unsafe"),
    };
    let metadata = file.metadata().map_err(|_| "Mihomo version marker is unsafe")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 32
    {
        return Err("Mihomo version marker is unsafe");
    }
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(|_| "Mihomo version marker is unreadable")?;
    if !value.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') || value.is_empty() {
        return Err("Mihomo version marker is invalid");
    }
    Ok(Some(value))
}

fn read_active_release() -> Result<Option<&'static Release>, &'static str> {
    mihomo_release::active_release().map_err(|_| "Installed Mihomo version marker is unsafe")
}

fn release_path(release: &Release) -> PathBuf {
    mihomo_release::version_path(release)
}

fn verify_elf(file: &mut File, expected_size: u64) -> Result<(), &'static str> {
    file.seek(SeekFrom::Start(0)).map_err(|_| "Mihomo ELF is unreadable")?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "Mihomo ELF header is truncated")?;
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || u16::from_le_bytes([header[18], header[19]]) != 183
    {
        return Err("Mihomo ELF is not static AArch64");
    }
    let phoff = u64::from_le_bytes(header[32..40].try_into().map_err(|_| "Invalid ELF program header")?);
    let phentsize = u16::from_le_bytes([header[54], header[55]]) as u64;
    let phnum = u16::from_le_bytes([header[56], header[57]]) as u64;
    if phentsize < 56 || phnum > 256 || phoff.saturating_add(phentsize.saturating_mul(phnum)) > expected_size {
        return Err("Mihomo ELF program headers are invalid");
    }
    for index in 0..phnum {
        file.seek(SeekFrom::Start(phoff + index * phentsize))
            .map_err(|_| "Mihomo ELF program headers are unreadable")?;
        let mut kind = [0u8; 4];
        file.read_exact(&mut kind)
            .map_err(|_| "Mihomo ELF program headers are truncated")?;
        if matches!(u32::from_le_bytes(kind), 2 | 3) {
            return Err("Mihomo ELF must not use a dynamic loader");
        }
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "Mihomo ELF is unreadable")?;
    Ok(())
}

fn verified_release_file(release: &Release) -> Option<File> {
    mihomo_release::open_release_version(release.version)
        .ok()
        .filter(|(_, selected)| *selected == release)
        .map(|(file, _)| file)
}

fn prepare_root() -> Result<File, &'static str> {
    let parent =
        std::fs::symlink_metadata("/usr/libexec/xkeenwrt").map_err(|_| "XkeenWRT release parent is unavailable")?;
    if !parent.is_dir() || parent.file_type().is_symlink() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("XkeenWRT release parent is unsafe");
    }
    let path = Path::new(ROOT);
    if !path.exists() {
        std::fs::create_dir(path).map_err(|_| "Could not create Mihomo release directory")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|_| "Could not set Mihomo release directory permissions")?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "Mihomo release directory is unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("Mihomo release directory is unsafe");
    }
    File::open(path).map_err(|_| "Mihomo release directory is unavailable")
}

fn free_space(root: &File) -> Result<u64, &'static str> {
    let stat = rustix::fs::fstatvfs(root).map_err(|_| "Could not inspect router storage")?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

fn prepare_ram_staging(archive_size: u64) -> Result<PathBuf, &'static str> {
    let tmp = Path::new("/tmp");
    let metadata = std::fs::symlink_metadata(tmp).map_err(|_| "Router RAM staging is unavailable")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o1002 != 0o1002
    {
        return Err("Router RAM staging directory is unsafe");
    }
    let directory = File::open(tmp).map_err(|_| "Router RAM staging is unavailable")?;
    let mut fs: nix::libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstatfs(std::os::fd::AsRawFd::as_raw_fd(&directory), &mut fs) } != 0
        || fs.f_type as u64 != 0x0102_1994
    {
        return Err("Mihomo archive staging requires the router RAM filesystem");
    }
    let stat = rustix::fs::fstatvfs(&directory).map_err(|_| "Could not inspect router RAM staging")?;
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    if available < archive_size.saturating_add(4 * 1024 * 1024) {
        return Err("Недостаточно места в RAM для проверки архива Mihomo");
    }
    let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(|_| "Could not inspect available router memory")?;
    let mut mem_available = None;
    for line in meminfo.lines() {
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            let mut fields = value.split_whitespace();
            let kb = fields
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or("Router memory status is invalid")?;
            if fields.next() != Some("kB") || fields.next().is_some() {
                return Err("Router memory status is invalid");
            }
            mem_available = Some(kb.saturating_mul(1024));
            break;
        }
    }
    if mem_available.unwrap_or(0) < archive_size.saturating_add(RAM_RESERVE) {
        return Err("Недостаточно свободной памяти для безопасной загрузки Mihomo");
    }
    let stage = tmp.join(format!("xkeenwrt-mihomo-{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&stage).map_err(|_| "Could not create private router RAM staging")?;
    if std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).is_err() {
        clean_staging(&stage);
        return Err("Could not secure router RAM staging");
    }
    Ok(stage)
}

fn atomic_private_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags, openat, renameat};
    let parent_path = path.parent().ok_or_else(|| std::io::Error::other("missing parent"))?;
    let name = path.file_name().ok_or_else(|| std::io::Error::other("missing name"))?;
    let parent = File::open(parent_path)?;
    let stage = format!(".mihomo-pointer-{}", Uuid::new_v4().simple());
    let result = (|| {
        let fd = openat(
            &parent,
            stage.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        renameat(&parent, stage.as_str(), &parent, name)?;
        parent.sync_all()
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, stage.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}

async fn download_and_install(job: &Arc<Job>, release: &Release) -> Result<(), &'static str> {
    if job.cancel.load(Ordering::Acquire) {
        return Err("Отменено");
    }
    let root = prepare_root()?;
    let final_path = release_path(release);
    let needed = if final_path.exists() {
        0
    } else {
        release.elf_size.saturating_add(FREE_RESERVE)
    };
    if free_space(&root)? < needed {
        return Err("Недостаточно места на overlay для новой и предыдущей версии Mihomo");
    }
    if final_path.exists() {
        if verified_release_file(release).is_none() {
            return Err("Версионный файл Mihomo уже существует, но не прошёл проверку");
        }
    } else {
        let ram_dir = prepare_ram_staging(release.archive_size)?;
        let temp_dir = Path::new(ROOT).join(format!(".install-{}", Uuid::new_v4().simple()));
        if std::fs::create_dir(&temp_dir).is_err() {
            clean_staging(&ram_dir);
            return Err("Could not create private Mihomo staging directory");
        }
        if std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700)).is_err() {
            clean_staging(&temp_dir);
            clean_staging(&ram_dir);
            return Err("Could not secure Mihomo staging directory");
        }
        let result = install_into_staging(job, release, &temp_dir, &ram_dir).await;
        clean_staging(&ram_dir);
        if result.is_ok() {
            let metadata = std::fs::symlink_metadata(&temp_dir).map_err(|_| "Mihomo staging directory disappeared")?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
                return Err("Mihomo staging directory changed during install");
            }
            let final_dir = final_path.parent().ok_or("Mihomo release directory is invalid")?;
            if final_dir.exists() {
                return Err("Mihomo version directory already exists");
            }
            std::fs::rename(&temp_dir, final_dir).map_err(|_| "Could not atomically publish Mihomo release")?;
            root.sync_all()
                .map_err(|_| "Could not persist Mihomo release publication")?;
        } else {
            clean_staging(&temp_dir);
            return result;
        }
    }
    if job.cancel.load(Ordering::Acquire) {
        return Err("Отменено");
    }
    {
        let mut committing = job.committing.lock().unwrap();
        if job.cancel.load(Ordering::Acquire) {
            return Err("Отменено");
        }
        *committing = true;
    }
    let version = release.version.to_owned();
    tokio::task::spawn_blocking(move || request_selection(version))
        .await
        .map_err(|_| "Runtime version switch failed")??;

    Ok(())
}

fn request_selection(version: String) -> Result<(), &'static str> {
    let reply = crate::runtime::ipc::RuntimeClient::command(crate::runtime::RuntimeCommand::SelectCore { version })
        .map_err(|_| "Runtime did not confirm the version switch; reload the installed version")?;
    if reply.code == "OK" {
        Ok(())
    } else {
        Err("Runtime refused the version switch; stop the core and disable network mode")
    }
}

pub(crate) fn select_verified_version(
    version: &str, validate_active: impl FnOnce() -> Result<(), crate::configuration::ActivationError>,
) -> Result<(), &'static str> {
    let release = core_catalog::release(version).ok_or("Unsupported Mihomo release")?;
    verified_release_file(release).ok_or("New Mihomo failed integrity checks")?;
    let previous = read_active_release()?;
    if let Some(old) = previous {
        verified_release_file(old).ok_or("Previous Mihomo failed integrity checks")?;
    }
    // Persist the recovery pointer before switching, including on power loss.
    if let Some(old) = previous.filter(|old| old.version != version) {
        atomic_private_replace(Path::new(PREVIOUS), old.version.as_bytes())
            .map_err(|_| "Could not retain previous Mihomo")?;
    }
    atomic_private_replace(Path::new(ACTIVE), version.as_bytes()).map_err(|_| "Could not switch Mihomo")?;
    if validate_active().is_err() {
        if let Some(old) = previous {
            atomic_private_replace(Path::new(ACTIVE), old.version.as_bytes())
                .map_err(|_| "Core rollback needs recovery")?;
        } else {
            std::fs::remove_file(ACTIVE).map_err(|_| "Core rollback needs recovery")?;
            File::open("/etc/xkeenwrt")
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "Core rollback needs recovery")?;
        }
        return Err("Active profile is incompatible with this Mihomo release");
    }
    Ok(())
}

async fn install_into_staging(
    job: &Arc<Job>, release: &Release, temp_dir: &Path, ram_dir: &Path,
) -> Result<(), &'static str> {
    let archive_path = ram_dir.join("release.gz");
    let mut archive = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&archive_path)
        .map_err(|_| "Could not create Mihomo archive staging file")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|_| "Could not prepare secure Mihomo downloader")?;
    let response = download_official_asset(&client, release.url).await?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size != release.archive_size)
    {
        return Err("Official Mihomo download returned an unexpected response");
    }
    job.stage("download");
    let started = Instant::now();
    let mut downloaded = 0u64;
    let mut last_report = Instant::now();
    let mut hash = Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if job.cancel.load(Ordering::Acquire) {
            return Err("Отменено");
        }
        let chunk = chunk.map_err(|_| "Mihomo download was interrupted")?;
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        if downloaded > release.archive_size {
            return Err("Mihomo archive exceeds its pinned size");
        }
        hash.update(&chunk);
        archive
            .write_all(&chunk)
            .map_err(|_| "Could not stage Mihomo archive")?;
        if last_report.elapsed() >= Duration::from_millis(300) || downloaded == release.archive_size {
            let speed = downloaded.saturating_mul(1000) / started.elapsed().as_millis().max(1) as u64;
            job.progress(downloaded, release.archive_size, speed);
            last_report = Instant::now();
        }
    }
    archive.sync_all().map_err(|_| "Could not persist Mihomo archive")?;
    drop(archive);
    let archive_hash: String = hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    if downloaded != release.archive_size || archive_hash != release.archive_sha256 {
        return Err("Mihomo archive did not match its pinned size and SHA-256");
    }
    if job.cancel.load(Ordering::Acquire) {
        return Err("Отменено");
    }
    job.stage("verify");
    job.log("Проверка контрольной суммы и ABI AArch64", "info");
    let elf_temp = temp_dir.join("mihomo.tmp");
    let archive_clone = archive_path.clone();
    let elf_clone = elf_temp.clone();
    let release_copy = *release;
    tokio::task::spawn_blocking(move || extract_verified(&archive_clone, &elf_clone, &release_copy))
        .await
        .map_err(|_| "Mihomo verifier task failed")??;
    if job.cancel.load(Ordering::Acquire) {
        return Err("Отменено");
    }
    std::fs::remove_file(&archive_path).map_err(|_| "Could not remove verified Mihomo archive")?;
    std::fs::rename(&elf_temp, temp_dir.join("mihomo")).map_err(|_| "Could not stage verified Mihomo ELF")?;
    std::fs::set_permissions(temp_dir.join("mihomo"), std::fs::Permissions::from_mode(0o755))
        .map_err(|_| "Could not set Mihomo executable permissions")?;
    File::open(temp_dir)
        .and_then(|_| std::fs::set_permissions(temp_dir, std::fs::Permissions::from_mode(0o755)))
        .map_err(|_| "Could not publish Mihomo version directory")?;
    File::open(temp_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "Could not persist verified Mihomo ELF")?;
    job.stage("commit");
    job.log("Атомарная публикация и проверка версии", "info");
    Ok(())
}

const OFFICIAL_RELEASE_HOSTS: [&str; 4] = [
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

fn is_official_release_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .host_str()
            .is_some_and(|host| OFFICIAL_RELEASE_HOSTS.contains(&host))
}

async fn download_official_asset(client: &reqwest::Client, original: &str) -> Result<reqwest::Response, &'static str> {
    use reqwest::StatusCode;
    let mut url = reqwest::Url::parse(original).map_err(|_| "Pinned Mihomo asset URL is invalid")?;
    if url.host_str() != Some("github.com") || !is_official_release_url(&url) {
        return Err("Pinned Mihomo asset URL is outside the official release host");
    }
    for redirect_count in 0..=4 {
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| "Mihomo download failed")?;
        let status = response.status();
        if !matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            return Ok(response);
        }
        if redirect_count == 4 {
            return Err("Official Mihomo download exceeded the redirect limit");
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or("Official Mihomo redirect did not contain a valid target")?;
        let next = url
            .join(location)
            .map_err(|_| "Official Mihomo redirect target is invalid")?;
        if !is_official_release_url(&next) {
            return Err("Official Mihomo redirect target is outside the approved HTTPS hosts");
        }
        // A signed location may contain short-lived query data; it is never retained
        // or emitted to logs. Only the next request carries it.
        url = next;
    }
    Err("Official Mihomo download exceeded the redirect limit")
}

fn extract_verified(archive_path: &Path, elf_path: &Path, release: &Release) -> Result<(), &'static str> {
    use flate2::read::GzDecoder;
    let archive = File::open(archive_path).map_err(|_| "Mihomo archive is unreadable")?;
    let mut decoder = GzDecoder::new(archive);
    let mut elf = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(elf_path)
        .map_err(|_| "Could not create Mihomo ELF staging file")?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| "Mihomo archive is not a valid gzip stream")?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if bytes > release.elf_size {
            return Err("Mihomo ELF exceeds its pinned size");
        }
        hash.update(&buffer[..read]);
        elf.write_all(&buffer[..read])
            .map_err(|_| "Could not write Mihomo ELF")?;
    }
    elf.sync_all().map_err(|_| "Could not persist Mihomo ELF")?;
    if bytes != release.elf_size {
        return Err("Mihomo ELF has an unexpected size");
    }
    let actual: String = hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != release.elf_sha256 {
        return Err("Mihomo ELF did not match its pinned SHA-256");
    }
    let mut read_elf = File::open(elf_path).map_err(|_| "Mihomo ELF is unreadable")?;
    verify_elf(&mut read_elf, release.elf_size)?;
    Ok(())
}

fn clean_staging(path: &Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let file = entry.path();
            if let Ok(metadata) = std::fs::symlink_metadata(&file)
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.nlink() == 1
            {
                let _ = std::fs::remove_file(file);
            }
        }
    }
    let _ = std::fs::remove_dir(path);
}

#[cfg(test)]
mod tests {
    use super::is_official_release_url;

    #[test]
    fn release_redirects_allow_only_https_official_hosts() {
        for value in [
            "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo.gz",
            "https://release-assets.githubusercontent.com/signed/path?token=private",
            "https://objects.githubusercontent.com/signed/path",
        ] {
            assert!(is_official_release_url(&reqwest::Url::parse(value).unwrap()));
        }
        for value in [
            "http://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo.gz",
            "https://example.com/file",
            "https://127.0.0.1/file",
            "https://github.com:444/file",
            "https://user@github.com/file",
            "https://github.com/file#fragment",
        ] {
            assert!(!is_official_release_url(&reqwest::Url::parse(value).unwrap()));
        }
    }
}
