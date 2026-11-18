//! Single private, replaceable prepared-network plan. The transaction journal,
//! not this file, remains authoritative after apply has begun.
use super::planning::PreparedPlan;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const PATH: &str = "/etc/xkeenwrt/network-plan.json";
const LIMIT: u64 = 1_048_576;

fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

pub fn save(plan: &PreparedPlan) -> io::Result<()> {
    if !valid_id(&plan.plan_id) || plan.network.manifest().generation == 0 || plan.expires_unix == 0 {
        return Err(io::Error::other("invalid network plan"));
    }
    let bytes = serde_json::to_vec(plan).map_err(io::Error::other)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("network plan too large"));
    }
    let dir = Path::new("/etc/xkeenwrt");
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe network plan directory"));
    }
    match fs::symlink_metadata(PATH) {
        Ok(m)
            if m.is_file()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && m.mode() & 0o777 == 0o600
                && m.nlink() == 1 => {}
        Ok(_) => return Err(io::Error::other("unsafe network plan")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let temp = dir.join(format!(".network-plan-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, PATH)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn load(expected_id: &str) -> io::Result<PreparedPlan> {
    if !valid_id(expected_id) {
        return Err(io::Error::other("invalid network plan id"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(PATH)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 || meta.len() > LIMIT {
        return Err(io::Error::other("unsafe network plan"));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("network plan too large"));
    }
    let plan: PreparedPlan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if plan.plan_id != expected_id
        || !valid_id(&plan.plan_id)
        || plan.network.manifest().generation == 0
        || plan.expires_unix <= now
        || plan.expires_unix > now.saturating_add(300)
    {
        return Err(io::Error::other("network plan binding mismatch"));
    }
    Ok(plan)
}

/// Called under the mutation lock when the executable changes. A plan validated
/// with another core must never survive a version switch or runtime restart.
pub(crate) fn invalidate() -> io::Result<()> {
    use rustix::fs::{AtFlags, unlinkat};
    match fs::symlink_metadata(PATH) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Ok(m)
            if m.is_file()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && m.mode() & 0o777 == 0o600
                && m.nlink() == 1 => {}
        Ok(_) => return Err(io::Error::other("unsafe network plan")),
        Err(e) => return Err(e),
    }
    let dir = File::open("/etc/xkeenwrt")?;
    unlinkat(&dir, "network-plan.json", AtFlags::empty())?;
    dir.sync_all()
}
