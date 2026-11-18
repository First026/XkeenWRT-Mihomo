//! Coordinator-only apply sequence; rollback is performed by the independent helper.
use super::{NetworkPlan, RoutingPlan};
use nix::libc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    CheckNft,
    RemoveRule,
    RemoveRoute,
    Route,
    Rule,
    Nft,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ApplyError {
    pub stage: Stage,
    pub may_have_mutated: bool,
}
/// The real adapter uses fixed commands; the coordinator owns readiness and the shared lock.
pub trait NetworkIo {
    fn check_nft(&mut self, batch: &str) -> bool;
    fn remove_route(&mut self, _: &xkeenwrt_recovery::Manifest) -> bool {
        false
    }
    fn remove_rule(&mut self, _: &xkeenwrt_recovery::Manifest) -> bool {
        false
    }
    fn add_route(&mut self, route: &RoutingPlan) -> bool;
    fn add_rule(&mut self, route: &RoutingPlan) -> bool;
    fn install_nft(&mut self, batch: &str) -> bool;
}
/// Call only under the mutation lock after the independent helper has acknowledged
/// the same transaction and the coordinator has revalidated the inventory.
pub fn apply(plan: &NetworkPlan, io: &mut impl NetworkIo) -> Result<(), ApplyError> {
    apply_transition(plan, None, io)
}

/// Replace one exact, previously journaled generation with the candidate.
/// Helper rollback restores `previous` if any step after removal fails.
pub fn apply_transition(
    plan: &NetworkPlan, previous: Option<&xkeenwrt_recovery::Manifest>, io: &mut impl NetworkIo,
) -> Result<(), ApplyError> {
    if !io.check_nft(plan.nft_batch()) {
        return Err(ApplyError {
            stage: Stage::CheckNft,
            may_have_mutated: false,
        });
    }
    if let Some(previous) = previous {
        if previous.owner_id != plan.manifest().owner_id || previous.generation >= plan.manifest().generation {
            return Err(ApplyError {
                stage: Stage::RemoveRule,
                may_have_mutated: false,
            });
        }
        if !io.remove_rule(previous) {
            return Err(ApplyError {
                stage: Stage::RemoveRule,
                may_have_mutated: true,
            });
        }
        if !io.remove_route(previous) {
            return Err(ApplyError {
                stage: Stage::RemoveRoute,
                may_have_mutated: true,
            });
        }
    }
    if !io.add_route(plan.routing()) {
        return Err(ApplyError {
            stage: Stage::Route,
            may_have_mutated: true,
        });
    }
    if !io.add_rule(plan.routing()) {
        return Err(ApplyError {
            stage: Stage::Rule,
            may_have_mutated: true,
        });
    }
    if !io.install_nft(plan.nft_batch()) {
        return Err(ApplyError {
            stage: Stage::Nft,
            may_have_mutated: true,
        });
    }
    Ok(())
}

/// OpenWrt adapter. The caller must hold the shared lock and a verified READY.
// The standalone network-plan contract imports this module without the runtime
// dispatcher, so this production adapter is intentionally unused in that test.
#[cfg_attr(test, allow(dead_code))]
pub struct OpenWrtNetworkIo {
    cgroup_dir: std::fs::File,
    generation: u64,
}
#[cfg_attr(test, allow(dead_code))]
impl OpenWrtNetworkIo {
    /// Directory must be the verified operation cgroup for this transaction.
    pub fn new(cgroup_dir: std::fs::File, generation: u64) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self { cgroup_dir, generation })
    }
    fn unrevoked(&self) -> bool {
        let path = format!("/var/run/xkeenwrt/revoked-{}", self.generation);
        matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }
    fn checked_run(&self, program: xkeenwrt_recovery::FixedProgram, args: &[String], input: Option<&str>) -> bool {
        if !self.unrevoked() {
            return false;
        }
        let success = run(program, args, input, &self.cgroup_dir);
        let unrevoked = self.unrevoked();
        success && unrevoked
    }
}
impl NetworkIo for OpenWrtNetworkIo {
    fn check_nft(&mut self, batch: &str) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Nft,
            &["-j".into(), "-c".into(), "-f".into(), "-".into()],
            Some(batch),
        )
    }
    fn add_route(&mut self, r: &RoutingPlan) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Ip,
            &[
                "-4".into(),
                "route".into(),
                "add".into(),
                "local".into(),
                "0.0.0.0/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                r.table.to_string(),
            ],
            None,
        )
    }
    fn remove_route(&mut self, m: &xkeenwrt_recovery::Manifest) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Ip,
            &[
                "-4".into(),
                "route".into(),
                "del".into(),
                "local".into(),
                "0.0.0.0/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                m.route_table.to_string(),
            ],
            None,
        )
    }
    fn add_rule(&mut self, r: &RoutingPlan) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Ip,
            &[
                "-4".into(),
                "rule".into(),
                "add".into(),
                "priority".into(),
                r.rule_priority.to_string(),
                "fwmark".into(),
                format!("{:#x}/{:#x}", r.mark, r.mask),
                "table".into(),
                r.table.to_string(),
            ],
            None,
        )
    }
    fn remove_rule(&mut self, m: &xkeenwrt_recovery::Manifest) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Ip,
            &[
                "-4".into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                m.priority.to_string(),
                "fwmark".into(),
                format!("{:#x}/{:#x}", m.mark, m.mask),
                "table".into(),
                m.route_table.to_string(),
            ],
            None,
        )
    }
    fn install_nft(&mut self, batch: &str) -> bool {
        self.checked_run(
            xkeenwrt_recovery::FixedProgram::Nft,
            &["-j".into(), "-f".into(), "-".into()],
            Some(batch),
        )
    }
}
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn run(
    program: xkeenwrt_recovery::FixedProgram, args: &[String], input: Option<&str>, cgroup_dir: &std::fs::File,
) -> bool {
    use std::{
        io::{Seek, SeekFrom, Write},
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut temp = None;
    let result = (|| -> std::io::Result<bool> {
        let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
        let input_file = if let Some(text) = input {
            if text.len() > 1_048_576 {
                return Err(std::io::Error::other("nft plan too large"));
            }
            let path = format!(
                "/var/run/xkeenwrt/.apply-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            temp = Some(path);
            file.write_all(text.as_bytes())?;
            file.seek(SeekFrom::Start(0))?;
            file
        } else {
            null.try_clone()?
        };
        xkeenwrt_recovery::run_fixed_in_cgroup(
            program,
            args,
            cgroup_dir.as_raw_fd(),
            input_file.as_raw_fd(),
            null.as_raw_fd(),
            null.as_raw_fd(),
            Duration::from_secs(3),
        )
    })();
    if let Some(path) = temp {
        let _ = std::fs::remove_file(path);
    }
    result.unwrap_or(false)
}
