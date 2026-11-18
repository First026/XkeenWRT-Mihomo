//! Rescue-owned adapter. The guard is installed before any explicit listener.
use crate::commands::{self, InventoryQuery as Q};
use profile_policy::ExplicitOverlay;
use std::io;
use xkeenwrt_recovery::explicit::{self, Adapter, GuardState};
struct Native;
impl Adapter for Native {
    fn read_nft(&mut self) -> io::Result<Vec<u8>> {
        commands::inventory(Q::NftRuleset)
    }
    fn apply_nft(&mut self, batch: &str) -> io::Result<()> {
        if commands::nft(&["-j", "-f", "-"], Some(batch))?.success {
            Ok(())
        } else {
            Err(io::Error::other("explicit protection failed"))
        }
    }
    fn load(&mut self) -> io::Result<GuardState> {
        explicit::load_state()
    }
    fn persist(&mut self, state: &GuardState) -> io::Result<()> {
        explicit::persist_state(state)
    }
}
pub fn protect(target: Option<&ExplicitOverlay>) -> io::Result<()> {
    if let Some(e) = target {
        explicit::verify_binding(
            e,
            &commands::inventory(Q::Addresses)?,
            &commands::inventory(Q::NetworkStatus)?,
        )?;
    }
    explicit::reconcile(&mut Native, target)
}

/// Neighbour firewall reloads can remove the guard while leaving Mihomo alive.
/// Repair only the exact accepted binding; unsafe ownership/binding closes core.
pub fn monitor() -> io::Result<()> {
    use xkeenwrt_recovery::input_state::{self, Phase};
    if let Some(mut transition) = input_state::load_transition()?
        && transition.phase == Phase::Applying
    {
        if transition.owner_id != crate::read_owner()? {
            return Err(io::Error::other("input recovery owner mismatch"));
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let mut previous = transition.previous_core.clone();
        if boot.trim() != transition.runtime.boot_id {
            previous.running = false;
        }
        crate::core::restore(&previous)?;
        input_state::save(&transition.previous_selection)?;
        transition.phase = Phase::RolledBack;
        input_state::save_transition(&transition)?;
    }

    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/var/run/xkeenwrt/launch.json")
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 16384
    {
        return Err(io::Error::other("unsafe input launch state"));
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    let grant: xkeenwrt_recovery::LaunchGrant = serde_json::from_slice(&bytes)?;
    if !grant.valid() {
        return Err(io::Error::other("invalid input launch state"));
    }
    if !grant.desired_running {
        return Ok(());
    }
    if let Some(e) = grant.overlay.explicit()
        && protect(Some(e)).is_err()
    {
        // Keep the typed desired grant so the independent health protocol
        // can prove actual core death and remove its capture generation.
        let _ = crate::core::stop_confirm();
        if !commands::core_is_stopped()? {
            return Err(io::Error::other("unsafe explicit core did not close"));
        }
    }
    Ok(())
}
