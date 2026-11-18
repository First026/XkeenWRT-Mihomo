//! Retire the complete state of an explicitly finalized Remove. The caller
//! holds lifecycle locks and proves that services, cgroups and network are idle.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
fn invalid() -> io::Error {
    io::Error::other("finalized Remove archive proof unavailable")
}
fn private_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    Ok(file)
}
fn finalized_state(dir: &Path, owner: &str, request_id: &str) -> io::Result<File> {
    let root = private_directory(dir)?;
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
    crate::verify_remove_after_integrity_check(&pinned, owner, request_id)?;
    let owner_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(pinned.join("owner-id"))?;
    let m = owner_file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() != 36
    {
        return Err(invalid());
    }
    let mut actual_owner = String::new();
    owner_file.take(37).read_to_string(&mut actual_owner)?;
    if !crate::valid_owner(&actual_owner) || actual_owner != owner {
        return Err(invalid());
    }
    for entry in std::fs::read_dir(&pinned)? {
        let name = entry?.file_name();
        let name = name.to_str().ok_or_else(invalid)?;
        if name == "rescue"
            || name == "lifecycle.json"
            || name.starts_with("rescue-previous-")
            || name.starts_with(".rescue")
            || name.starts_with(".xkeenwrt-rescue")
        {
            return Err(invalid());
        }
    }
    Ok(root)
}
fn checked_parent(dir: &Path) -> io::Result<File> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir.parent().ok_or_else(invalid)?)?;
    let m = parent.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    Ok(parent)
}
/// Recognize an already committed archive without mutating any installation.
/// An existing source always takes precedence, including a new installation.
pub fn completed_archive(dir: &Path, request_id: &str) -> io::Result<Option<PathBuf>> {
    if !crate::valid_owner(request_id) || dir.file_name() != Some(std::ffi::OsStr::new("xkeenwrt"))
    {
        return Err(invalid());
    }
    match std::fs::symlink_metadata(dir) {
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let parent = checked_parent(dir)?;
    let target = dir.with_file_name(format!("xkeenwrt-retired-{request_id}"));
    let target_fd = private_directory(&target)?;
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", target_fd.as_raw_fd()));
    let receipt = crate::read_lifecycle_request(&pinned)?.ok_or_else(invalid)?;
    let _ = finalized_state(&target, &receipt.owner_id, request_id)?;
    parent.sync_all()?;
    Ok(Some(target))
}
/// Move the complete old installation, including its removal fence and YAML,
/// to a request-bound sibling. No file in the retired installation is deleted.
/// The CLI verifies stopped services, empty cgroups and absent network first.
pub fn archive_finalized_remove(dir: &Path, owner: &str, request_id: &str) -> io::Result<PathBuf> {
    if !crate::valid_owner(owner)
        || !crate::valid_owner(request_id)
        || dir.file_name() != Some(std::ffi::OsStr::new("xkeenwrt"))
    {
        return Err(invalid());
    }
    if let Some(target) = completed_archive(dir, request_id)? {
        let _ = finalized_state(&target, owner, request_id)?;
        return Ok(target);
    }
    let root = finalized_state(dir, owner, request_id)?;
    let parent_path = dir.parent().ok_or_else(invalid)?;
    let parent = checked_parent(dir)?;
    let by_name = std::fs::symlink_metadata(dir)?;
    let pinned_meta = root.metadata()?;
    if !by_name.is_dir() || by_name.dev() != pinned_meta.dev() || by_name.ino() != pinned_meta.ino()
    {
        return Err(invalid());
    }
    let target_name =
        std::ffi::CString::new(format!("xkeenwrt-retired-{request_id}")).map_err(|_| invalid())?;
    root.sync_all()?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            c"xkeenwrt".as_ptr(),
            parent.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()?;
    Ok(parent_path.join(target_name.to_str().map_err(|_| invalid())?))
}
