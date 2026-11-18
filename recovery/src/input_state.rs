//! Accepted user input selection, independent of the current running state.
use profile_policy::ExplicitOverlay;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub explicit: Option<ExplicitOverlay>,
    pub gateway: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_commit: Option<String>,
}
fn bad() -> std::io::Error {
    std::io::Error::other("input selection state is unverifiable")
}
fn nonce() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
const FILE: &str = "/etc/xkeenwrt/selected-inputs.json";
pub fn load() -> std::io::Result<Selection> {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(FILE)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Selection::default()),
        Err(_) => return Err(bad()),
    };
    let m = f.metadata().map_err(|_| bad())?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > 16384
    {
        return Err(bad());
    }
    let mut b = Vec::new();
    f.take(16385).read_to_end(&mut b).map_err(|_| bad())?;
    let s: Selection = serde_json::from_slice(&b).map_err(|_| bad())?;
    if s.explicit.as_ref().is_some_and(|e| !e.valid())
        || s.network_commit
            .as_deref()
            .is_some_and(|id| !crate::valid_owner(id))
    {
        return Err(bad());
    }
    Ok(s)
}
pub fn save(s: &Selection) -> std::io::Result<()> {
    if s.explicit.as_ref().is_some_and(|e| !e.valid())
        || s.network_commit
            .as_deref()
            .is_some_and(|id| !crate::valid_owner(id))
    {
        return Err(bad());
    }
    let dir = Path::new("/etc/xkeenwrt");
    let m = std::fs::symlink_metadata(dir).map_err(|_| bad())?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(bad());
    }
    let tmp = dir.join(format!(".inputs-{}", nonce()?));
    let r = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec(s)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, FILE)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    r.map_err(|_| bad())
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Applying,
    Committed,
    RolledBack,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub version: u8,
    pub owner_id: String,
    pub generation: u64,
    pub runtime: crate::RuntimeIncarnationIdentity,
    pub previous_core: crate::CoreSnapshot,
    pub target_core: crate::CoreSnapshot,
    pub previous_selection: Selection,
    pub target_selection: Selection,
    pub phase: Phase,
}
impl Transition {
    pub fn valid(&self) -> bool {
        self.version == 1
            && crate::valid_owner(&self.owner_id)
            && self.generation > 0
            && crate::runtime_incarnation_path(&self.runtime).is_ok()
            && self.previous_core.valid()
            && self.target_core.valid()
            && self.previous_core.overlay.gateway().is_none()
            && self.target_core.overlay.gateway().is_none()
            && self
                .previous_selection
                .explicit
                .as_ref()
                .is_none_or(ExplicitOverlay::valid)
            && self
                .target_selection
                .explicit
                .as_ref()
                .is_none_or(ExplicitOverlay::valid)
            && self.target_core.overlay.explicit() == self.target_selection.explicit.as_ref()
            && !self.target_selection.gateway
    }
}
const TRANSITION: &str = "/etc/xkeenwrt/inputs-transition.json";
pub fn load_transition() -> std::io::Result<Option<Transition>> {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(TRANSITION)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > 65536
    {
        return Err(bad());
    }
    let mut bytes = Vec::new();
    f.take(65537).read_to_end(&mut bytes)?;
    let t: Transition = serde_json::from_slice(&bytes)?;
    if !t.valid() {
        return Err(bad());
    }
    Ok(Some(t))
}
pub fn save_transition(t: &Transition) -> std::io::Result<()> {
    if !t.valid() {
        return Err(bad());
    }
    let dir = Path::new("/etc/xkeenwrt");
    let m = std::fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(bad());
    }
    let tmp = dir.join(format!(".input-transition-{}", nonce()?));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec(t)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, TRANSITION)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}
/// Caller proves stopped core before invoking this lifecycle terminal receipt.
pub fn settle_stopped() -> std::io::Result<()> {
    if let Some(mut t) = load_transition()?
        && t.phase == Phase::Applying
    {
        save(&t.previous_selection)?;
        t.phase = Phase::RolledBack;
        save_transition(&t)?;
    }
    Ok(())
}

/// The ack travels in the same atomic file as user choices. Once acknowledged,
/// later Disable/explicit selections retain it and cannot be overwritten by a
/// replay of the historical network commit.
pub fn settled_selection(current: &Selection, j: &crate::Journal) -> Option<Selection> {
    j.profile_acceptance.as_ref()?;
    if current.network_commit.as_deref() == Some(&j.tx_id) {
        return None;
    }
    Some(Selection {
        explicit: j.current_core.overlay.explicit().cloned(),
        gateway: true,
        network_commit: Some(j.tx_id.clone()),
    })
}
pub fn settle_selection(j: &crate::Journal) -> std::io::Result<()> {
    if j.decision(&j.boot_id, j.created_boottime_ms, false) == crate::Decision::Invalid {
        return Err(bad());
    }
    if let Some(next) = settled_selection(&load()?, j) {
        save(&next)?;
    }
    Ok(())
}
