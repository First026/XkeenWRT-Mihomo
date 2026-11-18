//! Profile-owned immutable resources. HTTP names never become arbitrary paths.
use crate::configuration::{ConfigStore, MAX_PROFILE_BYTES};
use rustix::fs::{self as at, AtFlags, Mode, OFlags, RenameFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};
const ROOT: &str = "/etc/xkeenwrt/resources";
const LIMIT: usize = 8 * 1024 * 1024;
const ERROR: &str = "Хранилище ресурсов недоступно или повреждено";
#[derive(Serialize)]
pub struct Resource {
    pub id: String,
    pub size: u64,
    pub format: String,
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_file(name: &str) -> bool {
    name.len() <= 100
        && !name.is_empty()
        && !name.starts_with('.')
        && !name.contains("..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && ["yaml", "yml", "txt", "mrs", "dat"].contains(&name.rsplit('.').next().unwrap_or(""))
}
fn directory(path: &Path, create: bool) -> Result<File, &'static str> {
    if create {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(ERROR),
        }
    }
    let m = fs::symlink_metadata(path).map_err(|_| ERROR)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o7777 != 0o700
    {
        return Err(ERROR);
    }
    at::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ERROR)
}
fn root(id: &str, create: bool) -> Result<File, &'static str> {
    if !valid_id(id) {
        return Err("Некорректный ID профиля");
    }
    directory(Path::new("/etc/xkeenwrt"), false)?;
    directory(Path::new(ROOT), create)?;
    directory(&Path::new(ROOT).join(id), create)
}
fn file(dir: &File, name: &str) -> Result<File, &'static str> {
    if !valid_file(name) {
        return Err("Некорректный ID ресурса");
    }
    let file = at::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ERROR)?;
    let m = file.metadata().map_err(|_| ERROR)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
        || m.len() > LIMIT as u64
    {
        return Err(ERROR);
    }
    Ok(file)
}
pub fn list(id: &str) -> Result<Vec<Resource>, &'static str> {
    if !valid_id(id) {
        return Err("Некорректный ID профиля");
    }
    if !Path::new(ROOT).join(id).exists() {
        return Ok(Vec::new());
    }
    let dir = root(id, false)?;
    let mut resources = Vec::new();
    for entry in at::Dir::read_from(&dir).map_err(|_| ERROR)? {
        let entry = entry.map_err(|_| ERROR)?;
        let name = entry.file_name().to_str().map_err(|_| ERROR)?;
        if matches!(name, "." | "..") || name.starts_with(".stage-") {
            continue;
        }
        let meta = file(&dir, name)?.metadata().map_err(|_| ERROR)?;
        resources.push(Resource {
            id: name.into(),
            size: meta.len(),
            format: name.rsplit('.').next().unwrap_or("").into(),
        });
        if resources.len() > 32 {
            return Err("Слишком много ресурсов профиля");
        }
    }
    resources.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(resources)
}
pub fn read(id: &str, name: &str) -> Result<Vec<u8>, &'static str> {
    let dir = root(id, false)?;
    let mut bytes = Vec::new();
    file(&dir, name)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR)?;
    if bytes.len() > LIMIT {
        return Err("Ресурс превышает лимит размера");
    }
    Ok(bytes)
}
pub fn upload(
    store: &ConfigStore, id: &str, revision: &str, name: &str, bytes: &[u8],
) -> Result<Resource, &'static str> {
    if !valid_file(name) || bytes.is_empty() || bytes.len() > LIMIT {
        return Err("Недопустимое имя или размер ресурса");
    }
    let format = name.rsplit('.').next().ok_or(ERROR)?;
    match format {
        "mrs" => {
            crate::rule_resources::read_mrs(bytes)?;
        }
        "dat" => {
            if crate::rule_resources::dat_categories(bytes, "example.invalid", false).is_err()
                && crate::rule_resources::dat_categories(bytes, "192.0.2.1", true).is_err()
            {
                return Err("DAT не соответствует GeoSite/GeoIP");
            }
        }
        _ => {
            if bytes.len() > 2 * MAX_PROFILE_BYTES || std::str::from_utf8(bytes).is_err() {
                return Err("Некорректный текстовый ресурс");
            }
        }
    }
    let digest = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let name = format!(
        "{}-{}.{}",
        name.rsplit_once('.')
            .map_or(name, |(s, _)| s)
            .chars()
            .take(60)
            .collect::<String>(),
        &digest[..16],
        format
    );
    store
        .with_revision(id, revision, || {
            let dir = root(id, true)?;
            let existing = list(id)?;
            if let Some(item) = existing.iter().find(|item| item.id == name) {
                if read(id, &name)? != bytes {
                    return Err(ERROR);
                }
                return Ok(Resource {
                    id: name.clone(),
                    size: item.size,
                    format: format.into(),
                });
            }
            if existing.len() >= 32
                || existing
                    .iter()
                    .map(|item| item.size)
                    .sum::<u64>()
                    .saturating_add(bytes.len() as u64)
                    > LIMIT as u64
            {
                return Err("Достигнут лимит 32 ресурсов / 8 MiB на профиль");
            }
            let space = at::fstatvfs(&dir).map_err(|_| ERROR)?;
            if space.f_bavail.saturating_mul(space.f_frsize) < bytes.len() as u64 + 32 * 1024 * 1024 {
                return Err("Недостаточно места с сохранением резерва");
            }
            let temp = format!(".stage-{}", uuid::Uuid::new_v4());
            let result = (|| {
                let mut output = at::openat(
                    &dir,
                    temp.as_str(),
                    OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map(File::from)
                .map_err(|_| ERROR)?;
                output
                    .write_all(bytes)
                    .and_then(|()| output.sync_all())
                    .map_err(|_| ERROR)?;
                at::renameat_with(&dir, temp.as_str(), &dir, name.as_str(), RenameFlags::NOREPLACE)
                    .map_err(|_| ERROR)?;
                dir.sync_all().map_err(|_| ERROR)?;
                Ok(Resource {
                    id: name,
                    size: bytes.len() as u64,
                    format: format.into(),
                })
            })();
            if result.is_err() {
                let _ = at::unlinkat(&dir, temp.as_str(), AtFlags::empty());
            }
            result
        })
        .map_err(|_| "Профиль изменился: обновите его перед загрузкой ресурса")?
}

/// Restore only content-addressed, immutable resource names. A pre-existing
/// different file is a conflict, never an overwrite of an active source.
pub fn restore(id: &str, name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    verify_snapshot_resource(name, bytes)?;
    let dir = root(id, true)?;
    let existing = list(id)?;
    if existing.iter().any(|item| item.id == name) {
        return if read(id, name)? == bytes { Ok(()) } else { Err(ERROR) };
    }
    if existing.len() >= 32 || existing.iter().map(|item| item.size).sum::<u64>() + bytes.len() as u64 > LIMIT as u64 {
        return Err("Достигнут лимит ресурсов профиля");
    }
    let space = at::fstatvfs(&dir).map_err(|_| ERROR)?;
    if space.f_bavail.saturating_mul(space.f_frsize) < bytes.len() as u64 + 32 * 1024 * 1024 {
        return Err("Недостаточно места для ресурсов");
    }
    let temp = format!(".stage-{}", uuid::Uuid::new_v4());
    let result = (|| {
        let mut output = at::openat(
            &dir,
            temp.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| ERROR)?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| ERROR)?;
        at::renameat_with(&dir, temp.as_str(), &dir, name, RenameFlags::NOREPLACE).map_err(|_| ERROR)?;
        dir.sync_all().map_err(|_| ERROR)
    })();
    if result.is_err() {
        let _ = at::unlinkat(&dir, temp.as_str(), AtFlags::empty());
    }
    result
}
pub fn verify_snapshot_resource(name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    if !valid_file(name) || bytes.is_empty() || bytes.len() > LIMIT {
        return Err("Недопустимый ресурс резервной копии");
    }
    let stem = name.rsplit_once('.').ok_or(ERROR)?.0;
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if stem.rsplit_once('-').map(|(_, h)| h) != Some(&hash[..16]) {
        return Err("Контрольная сумма ресурса не совпадает");
    }
    Ok(())
}
pub fn copy_profile(from: &str, to: &str) -> Result<(), &'static str> {
    for resource in list(from)? {
        restore(to, &resource.id, &read(from, &resource.id)?)?;
    }
    Ok(())
}
