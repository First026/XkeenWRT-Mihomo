//! Bounded application backups for the OpenWrt profile store. These files are
//! JSON snapshots owned by XkeenWRT; they are not whole-router backups.
use crate::configuration::{ConfigError, ConfigStore, Profile};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::SystemTime,
};

pub const BACKUP_DIR: &str = "/etc/xkeenwrt/backups";
pub const BACKUP_SUFFIX: &str = "xkeenwrt.backup.json";
const MAX_BACKUPS: usize = 5;
const MAX_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_CONFIG_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    created_unix: u64,
    profiles: BTreeMap<String, String>,
    #[serde(default)]
    resources: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupItem {
    pub name: String,
    pub mtime: String,
    pub size: u64,
    pub content: BackupContents,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BackupContents {
    pub mihomo: Vec<String>,
}

fn safe_dir() -> io::Result<File> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = fs::symlink_metadata("/etc/xkeenwrt")?;
    if !parent.is_dir() || parent.file_type().is_symlink() || parent.uid() != 0 || parent.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe application data directory"));
    }
    match fs::DirBuilder::new().mode(0o700).create(BACKUP_DIR) {
        Ok(()) => File::open("/etc/xkeenwrt")?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(BACKUP_DIR)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe backup directory"));
    }
    File::open(BACKUP_DIR)
}

fn valid_profile_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn valid_name(name: &str) -> bool {
    name.len() <= 128
        && name.ends_with(BACKUP_SUFFIX)
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn profile_map(profiles: Vec<Profile>) -> Result<BTreeMap<String, String>, String> {
    if profiles.is_empty() || profiles.len() > 128 {
        return Err("число профилей вне допустимого диапазона".into());
    }
    let mut total = 0usize;
    let mut result = BTreeMap::new();
    for profile in profiles {
        if !valid_profile_id(&profile.id) || profile.source.len() > crate::configuration::MAX_PROFILE_BYTES {
            return Err("некорректный профиль в хранилище".into());
        }
        total = total.saturating_add(profile.source.len());
        if total > MAX_TOTAL_CONFIG_BYTES {
            return Err("профили превышают лимит резервной копии".into());
        }
        result.insert(profile.id, profile.source);
    }
    Ok(result)
}

fn backup_bytes(snapshot: &Snapshot) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| "не удалось сериализовать резервную копию")?;
    if bytes.len() as u64 > MAX_BACKUP_BYTES {
        return Err("резервная копия превышает лимит размера".into());
    }
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, String> {
    if bytes.len() as u64 > MAX_BACKUP_BYTES {
        return Err("резервная копия превышает лимит размера".into());
    }
    let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| "неверный формат резервной копии")?;
    if !matches!(snapshot.version, 1 | 2) || snapshot.profiles.is_empty() || snapshot.profiles.len() > 128 {
        return Err("неподдерживаемая резервная копия".into());
    }
    let mut total = 0usize;
    for (id, source) in &snapshot.profiles {
        if !valid_profile_id(id) || source.len() > crate::configuration::MAX_PROFILE_BYTES {
            return Err("некорректный профиль в резервной копии".into());
        }
        total = total.saturating_add(source.len());
        if total > MAX_TOTAL_CONFIG_BYTES {
            return Err("профили превышают лимит резервной копии".into());
        }
        ConfigStore::validate_source(source).map_err(|_| "резервная копия содержит YAML с ошибкой")?;
    }
    for (id, resources) in &snapshot.resources {
        if !snapshot.profiles.contains_key(id) || resources.len() > 32 {
            return Err("Некорректная привязка ресурсов".into());
        }
        let mut bytes_count = 0;
        for (name, encoded) in resources {
            let bytes = STANDARD.decode(encoded).map_err(|_| "Неверные данные ресурса")?;
            crate::resources::verify_snapshot_resource(name, &bytes)?;
            bytes_count += bytes.len();
        }
        if bytes_count > 8 * 1024 * 1024 {
            return Err("Ресурсы профиля превышают лимит".into());
        }
    }
    Ok(snapshot)
}

fn safe_file(dir: &File, name: &str) -> io::Result<(File, u64, SystemTime)> {
    if !valid_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid backup name"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(Path::new(BACKUP_DIR).join(name))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o600
        || meta.len() > MAX_BACKUP_BYTES
    {
        return Err(io::Error::other("unsafe backup file"));
    }
    let _ = dir;
    Ok((file, meta.len(), meta.modified()?))
}

fn read_snapshot(dir: &File, name: &str) -> Result<Snapshot, String> {
    let (mut file, size, _) = safe_file(dir, name).map_err(io_error)?;
    let mut bytes = Vec::with_capacity(size as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    decode_snapshot(&bytes)
}

fn mtime_string(time: SystemTime) -> String {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn item(dir: &File, name: &str) -> Result<BackupItem, String> {
    let (mut file, size, modified) = safe_file(dir, name).map_err(io_error)?;
    let mut bytes = Vec::with_capacity(size as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let snapshot = decode_snapshot(&bytes)?;
    Ok(BackupItem {
        name: name.to_owned(),
        mtime: mtime_string(modified),
        size,
        content: BackupContents {
            mihomo: snapshot.profiles.keys().map(|id| format!("{id}.yaml")).collect(),
        },
    })
}

fn list_names(dir: &File) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(BACKUP_DIR).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid backup file name")?;
        if !valid_name(&name) {
            continue;
        }
        let meta = entry.metadata().map_err(io_error)?;
        if !meta.is_file() || entry.file_type().map_err(io_error)?.is_symlink() {
            continue;
        }
        // Validate the private owner and content before advertising a backup.
        let _ = item(dir, &name)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

pub fn list() -> Result<Vec<BackupItem>, String> {
    let dir = safe_dir().map_err(io_error)?;
    list_names(&dir)?.iter().map(|name| item(&dir, name)).collect()
}

pub fn create(profiles_root: &Path) -> Result<BackupItem, String> {
    let dir = safe_dir().map_err(io_error)?;
    let names = list_names(&dir)?;
    let store = ConfigStore::new(profiles_root).map_err(config_error)?;
    let profiles = profile_map(store.snapshot_all().map_err(config_error)?)?;
    let now = std::time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io_error)?
        .as_secs();
    let mut resources = BTreeMap::new();
    for id in profiles.keys() {
        let mut files = BTreeMap::new();
        for item in crate::resources::list(id)? {
            files.insert(item.id.clone(), STANDARD.encode(crate::resources::read(id, &item.id)?));
        }
        if !files.is_empty() {
            resources.insert(id.clone(), files);
        }
    }
    let snapshot = Snapshot {
        version: 2,
        created_unix: now,
        profiles,
        resources,
    };
    let bytes = backup_bytes(&snapshot)?;
    // Publish the new valid snapshot before rotating old copies. A failed
    // write must never destroy the last successful backup.
    let mut retained = names
        .iter()
        .map(|name| item(&dir, name))
        .collect::<Result<Vec<_>, _>>()?;
    retained.sort_by(|a, b| a.mtime.cmp(&b.mtime).then(a.name.cmp(&b.name)));
    let space = rustix::fs::fstatvfs(&dir).map_err(io_error)?;
    if space.f_bavail.saturating_mul(space.f_frsize) < (bytes.len() as u64).saturating_add(32 * 1024 * 1024) {
        return Err("недостаточно места для резервной копии с сохранением резерва".into());
    }
    let base = DateTime::<Utc>::from_timestamp(now as i64, 0)
        .ok_or_else(|| "неверное системное время".to_owned())?
        .format("%Y-%m-%d_%H-%M-%S")
        .to_string();
    let mut name = format!("{base}_{BACKUP_SUFFIX}");
    let mut suffix = 2u32;
    while names.contains(&name) {
        name = format!("{base}_{suffix}_{BACKUP_SUFFIX}");
        suffix += 1;
    }
    publish(&dir, &name, &bytes).map_err(io_error)?;
    let created = item(&dir, &name)?;
    let mut total = retained.iter().map(|item| item.size).sum::<u64>() + created.size;
    while !retained.is_empty() && (retained.len() >= MAX_BACKUPS || total > MAX_BACKUP_BYTES) {
        let oldest = retained.remove(0);
        delete(&oldest.name)?;
        total = total.saturating_sub(oldest.size);
    }
    Ok(created)
}

pub fn restore(profiles_root: &Path, name: &str, contents: Option<Vec<String>>) -> Result<(), String> {
    let dir = safe_dir().map_err(io_error)?;
    let snapshot = read_snapshot(&dir, name)?;
    if contents
        .as_ref()
        .is_some_and(|items| items.is_empty() || items.iter().any(|item| item != "mihomo"))
    {
        return Err("неизвестный тип содержимого резервной копии".into());
    }
    let store = ConfigStore::new(profiles_root).map_err(config_error)?;
    // Validate every profile before changing any file; ConfigStore publishes
    // each profile with its own revision check and atomic rename.
    for source in snapshot.profiles.values() {
        ConfigStore::validate_source(source).map_err(config_error)?;
    }
    for (id, source) in snapshot.profiles {
        if let Some(resources) = snapshot.resources.get(&id) {
            for (name, encoded) in resources {
                let bytes = STANDARD.decode(encoded).map_err(|_| "Неверные данные ресурса")?;
                crate::resources::restore(&id, name, &bytes)?;
            }
        }
        let expected = match store.read(&id) {
            Ok(profile) => Some(profile.revision),
            Err(ConfigError::NotFound) => None,
            Err(error) => return Err(config_error(error)),
        };
        store.save(&id, &source, expected.as_deref()).map_err(config_error)?;
    }
    Ok(())
}

pub fn delete(name: &str) -> Result<(), String> {
    let dir = safe_dir().map_err(io_error)?;
    let (path, _) = resolve_path(&dir, name)?;
    fs::remove_file(path).map_err(io_error)?;
    dir.sync_all().map_err(io_error)
}

pub fn rename(name: &str, new_name: &str) -> Result<(), String> {
    let dir = safe_dir().map_err(io_error)?;
    let (_path, old_name) = resolve_path(&dir, name)?;
    let new_name = new_name.trim();
    if !valid_name(new_name) || new_name == old_name {
        return Err("некорректное имя резервной копии".into());
    }
    renameat_with(&dir, old_name.as_str(), &dir, new_name, RenameFlags::NOREPLACE).map_err(io_error)?;
    dir.sync_all().map_err(io_error)
}

fn resolve_path(dir: &File, name: &str) -> Result<(PathBuf, String), String> {
    if !valid_name(name) {
        return Err("некорректное имя резервной копии".into());
    }
    let (path, _, _) = safe_file(dir, name).map_err(io_error)?;
    drop(path);
    Ok((Path::new(BACKUP_DIR).join(name), name.to_owned()))
}

fn publish(dir: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = format!(".stage-{}", uuid::Uuid::new_v4().simple());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(Path::new(BACKUP_DIR).join(&temp))?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if !file.metadata()?.is_file() || file.metadata()?.uid() != 0 || file.metadata()?.mode() & 0o777 != 0o600 {
            return Err(io::Error::other("unsafe staged backup"));
        }
        renameat_with(dir, temp.as_str(), dir, name, RenameFlags::NOREPLACE)?;
        dir.sync_all()
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(dir, temp.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}

fn io_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn config_error(error: ConfigError) -> String {
    match error {
        ConfigError::Conflict => "профиль изменился во время операции".into(),
        ConfigError::Busy => "хранилище профилей занято".into(),
        ConfigError::InsufficientSpace => "недостаточно места для безопасной записи".into(),
        ConfigError::LimitReached => "достигнут лимит хранилища профилей".into(),
        _ => "хранилище профилей недоступно или повреждено".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backups_reject_traversal_and_invalid_content() {
        assert!(valid_name("2026-11-14_xkeenwrt.backup.json"));
        for name in [
            "../xkeenwrt.backup.json",
            "/tmp/xkeenwrt.backup.json",
            "xkeenwrt.backup.json/",
            "x\\xkeenwrt.backup.json",
        ] {
            assert!(!valid_name(name));
        }
        assert!(decode_snapshot(br#"{"version":1,"created_unix":0,"profiles":{"../outside":"rules: []"}}"#).is_err());
        assert!(decode_snapshot(br#"{"version":1,"created_unix":0,"profiles":{"config":"["}}"#).is_err());
        assert!(decode_snapshot(br#"{"version":1,"created_unix":0,"profiles":{"config":"rules: []"}}"#).is_ok());
    }
}
