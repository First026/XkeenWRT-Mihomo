//! Fixed native adapter for independent explicit input ownership.
use super::networking::read::{self, Query};
use crate::configuration::ActivationError;
use profile_policy::ExplicitOverlay;
use std::{fs::File, io};
use xkeenwrt_recovery::explicit::{self, Adapter, GuardState};
struct Native<'a> {
    group: &'a File,
}
impl Adapter for Native<'_> {
    fn read_nft(&mut self) -> io::Result<Vec<u8>> {
        read::query(Query::NftRuleset, self.group)
    }
    fn apply_nft(&mut self, batch: &str) -> io::Result<()> {
        let args = vec!["-j".into(), "-f".into(), "-".into()];
        if crate::network::executor::run(xkeenwrt_recovery::FixedProgram::Nft, &args, Some(batch), self.group) {
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
pub(crate) fn protect(target: Option<&ExplicitOverlay>, group: &File) -> Result<(), ActivationError> {
    if let Some(e) = target {
        explicit::verify_binding(
            e,
            &read::query(Query::Addresses, group).map_err(|_| ActivationError::Unavailable)?,
            &read::query(Query::NetworkStatus, group).map_err(|_| ActivationError::Unavailable)?,
        )
        .map_err(|_| ActivationError::Conflict)?;
    }
    explicit::reconcile(&mut Native { group }, target).map_err(|_| ActivationError::Conflict)
}

pub(crate) fn verify(target: &ExplicitOverlay, group: &File) -> Result<(), ActivationError> {
    use super::networking::helper;
    let fail = |_| ActivationError::Conflict;
    explicit::verify_binding(
        target,
        &read::query(Query::Addresses, group).map_err(fail)?,
        &read::query(Query::NetworkStatus, group).map_err(fail)?,
    )
    .map_err(fail)?;
    explicit::verify(target, &read::query(Query::NftRuleset, group).map_err(fail)?).map_err(fail)?;
    let before = helper::core_identity(group).map_err(fail)?;
    let inodes = helper::process_socket_inodes(before.0).map_err(fail)?;
    let tables: Vec<_> = ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"]
        .iter()
        .map(std::fs::read)
        .collect::<Result<_, _>>()
        .map_err(fail)?;
    if !explicit::socket_proof(
        [&tables[0], &tables[1], &tables[2], &tables[3]],
        Some(target),
        &inodes,
        true,
    )
    .map_err(fail)?
        || helper::core_identity(group).map_err(fail)? != before
    {
        return Err(ActivationError::Conflict);
    }
    Ok(())
}
pub(crate) fn port_free(_group: &File) -> bool {
    let data: Result<Vec<_>, _> = ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"]
        .iter()
        .map(std::fs::read)
        .collect();
    data.is_ok_and(|t| explicit::socket_proof([&t[0], &t[1], &t[2], &t[3]], None, &[], false).unwrap_or(false))
}
