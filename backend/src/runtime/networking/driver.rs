//! First-pilot OpenWrt adapter. Not exposed by HTTP until recovery and nft AST
//! have passed the independent VM gates. Never accepts shell commands or paths.
use super::{
    cgroup, collector, helper, identity, key,
    planning::PreparedPlan,
    read::{self, Query},
    status,
    transaction::{self, Driver, Error, Pending, Request},
};
use crate::{
    configuration::{Activation, ManualCore, Validator},
    network,
    runtime::core::ProcdCore,
};
use std::{
    io::{self, Read},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use xkeenwrt_recovery::{Journal, Manifest, MutationLock, Operation, State};

const CONFIG: &str = "/etc/xkeenwrt";
const RUN: &str = "/var/run/xkeenwrt";

/// One locked archive observation. An identical lease may appear in several
/// journals; verify its files once, while rejecting conflicting bindings of the
/// same private path. Nothing is reused by a later operation.
#[derive(Default)]
struct ArchiveVerification {
    verified: std::collections::BTreeMap<String, Vec<u8>>,
}
impl ArchiveVerification {
    fn verify(
        &mut self, snapshot: &xkeenwrt_recovery::CoreSnapshot,
        check: impl FnOnce(&xkeenwrt_recovery::CoreSnapshot) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let binding = serde_json::to_vec(snapshot).map_err(|_| Error::Storage)?;
        if let Some(prior) = self.verified.get(&snapshot.snapshot_id) {
            return if prior == &binding { Ok(()) } else { Err(Error::Storage) };
        }
        check(snapshot)?;
        self.verified.insert(snapshot.snapshot_id.clone(), binding);
        Ok(())
    }
}

/// Integrity of one archived snapshot. Recovery closes a journal
/// `RollbackDirect` when a snapshot it needed was missing or corrupt: no
/// generation is active and nothing restores from that journal again, so an
/// unusable snapshot there is history, not a reason to refuse every later
/// Start (decision 023). Every usable snapshot is still fully verified.
fn archive_snapshot_result(terminal_direct: bool, result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(Error::Storage) if terminal_direct => Ok(()),
        other => other,
    }
}

pub(crate) struct OpenWrtDriver<'a, V: Validator> {
    pub activation: &'a mut Activation<V>,
    pub core: &'a mut ProcdCore,
    pub plan: PreparedPlan,
    cgroup: Option<std::fs::File>,
    incarnation: xkeenwrt_recovery::RuntimeIncarnationIdentity,
    supervisor: Option<helper::SupervisorIdentity>,
    consume_marker: bool,
}
impl<'a, V: Validator> OpenWrtDriver<'a, V> {
    pub fn new(
        activation: &'a mut Activation<V>, core: &'a mut ProcdCore, plan: PreparedPlan,
        incarnation: xkeenwrt_recovery::RuntimeIncarnationIdentity,
    ) -> Self {
        Self {
            activation,
            core,
            plan,
            cgroup: None,
            incarnation,
            supervisor: None,
            consume_marker: false,
        }
    }
    pub(crate) fn attach_pending(&mut self, pending: &Pending) -> Result<(), Error> {
        let manifest = self.plan.network.manifest();
        if pending.request.plan_id != self.plan.plan_id
            || pending.request.candidate_id != self.plan.candidate_id
            || pending.request.generation != manifest.generation
        {
            return Err(Error::Conflict);
        }
        let fd = cgroup::open(
            &self.incarnation,
            &manifest.owner_id,
            pending.request.generation,
            &pending.transaction_id,
        )
        .map_err(|_| Error::NotReady)?;
        self.core
            .set_operation_cgroup(
                fd.try_clone().map_err(|_| Error::Storage)?,
                &self.incarnation,
                &manifest.owner_id,
                pending.request.generation,
                &pending.transaction_id,
            )
            .map_err(|_| Error::Storage)?;
        let id = helper::read_registration(&Path::new(RUN).join("supervisor.json")).map_err(|_| Error::NotReady)?;
        helper::verify_supervisor(&id, &manifest.owner_id, &pending.boot_id, &fd).map_err(|_| Error::NotReady)?;
        if !helper::ready_matches(
            &Path::new(RUN).join("recovery.ready"),
            &pending.transaction_id,
            pending.request.generation,
            &id,
        )
        .map_err(|_| Error::NotReady)?
        {
            return Err(Error::NotReady);
        }
        self.supervisor = Some(id);
        self.cgroup = Some(fd);
        Ok(())
    }
    fn manifest(&self) -> Result<Manifest, Error> {
        let m = self.plan.network.manifest();
        let mut result = Manifest {
            owner_id: m.owner_id.clone(),
            generation: m.generation,
            nft_semantic_sha256: "0".repeat(64),
            lan_interface: m.lan_interface.clone(),
            lan_address: m.lan_address,
            lan_scope: m.lan_scope.clone(),
            capture_version: m.capture_version,
            selected_mac: m.selected_mac.clone(),
            management_macs: m.management_macs.clone(),
            source_ipv4: m.source_ipv4,
            management_ipv4: m.management_ipv4,
            management_ipv6: m.management_ipv6.clone(),
            local_ipv4: m.local_ipv4.clone(),
            selected_ipv6: m.selected_ipv6.clone(),
            local_ipv6: m.local_ipv6.clone(),
            route_table: m.route_table,
            mark: m.mark,
            mask: m.mask,
            priority: m.priority,
            failure_policy: match m.failure_policy {
                network::FailurePolicy::DirectOnFailure => xkeenwrt_recovery::FailurePolicy::DirectOnFailure,
                network::FailurePolicy::BlockSelectedOnFailure => {
                    xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure
                }
            },
        };
        let ast = result.expected_nft_ast().map_err(|_| Error::NotReady)?;
        result.nft_semantic_sha256 =
            xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&ast).map_err(|_| Error::Storage)?)
                .map_err(|_| Error::NotReady)?;
        Ok(result)
    }
    pub(crate) fn secure_journal() -> Result<Option<Journal>, Error> {
        super::compatibility::network_journal(Path::new(CONFIG)).map_err(|_| Error::Storage)
    }
    fn matches_live(plan: &PreparedPlan, live: &collector::Observed) -> bool {
        let m = plan.network.manifest();
        if live.dns != plan.dns_facts || live.management_ipv6 != m.management_ipv6 {
            return false;
        }
        let p = network::TrafficPolicy {
            table: m.route_table,
            mark: m.mark,
            mark_mask: m.mask,
            priority: m.priority,
            lan_ifname: m.lan_interface.clone(),
            lan_address: m.lan_address,
            lan_scope: m.lan_scope.clone(),
            capture_version: m.capture_version,
            selected_mac: m.selected_mac.clone(),
            client_ipv4: m.source_ipv4,
            management_ipv4: m.management_ipv4,
            local_ipv4: m.local_ipv4.clone(),
            selected_ipv6: m.selected_ipv6.clone(),
            management_ipv6: Some(m.management_ipv6.clone()),
            local_ipv6: m.local_ipv6.clone(),
            candidate_id: m.candidate_id.clone(),
            previous_table: plan
                .previous
                .as_ref()
                .map(|previous| (previous.generation, previous.nft_semantic_sha256.clone())),
            owner_id: m.owner_id.clone(),
            generation: m.generation,
            failure_policy: Some(m.failure_policy),
            dns: Some(network::dns::DnsInventory {
                dnsmasq_instances: 1,
                incompatible_manager: false,
                local_names: live.dns.local_zones.clone(),
                upstreams: live
                    .dns
                    .upstreams
                    .iter()
                    .map(|v| format!("{}#{}", v.address, v.port))
                    .collect(),
                split_upstreams: live
                    .dns
                    .split_upstreams
                    .iter()
                    .map(|(zone, endpoint)| {
                        (
                            zone.clone(),
                            endpoint.as_ref().map(|v| format!("{}#{}", v.address, v.port)),
                        )
                    })
                    .collect(),
                verified_loopback_chain_sha256: live.dns.verified_loopback_chain_sha256.clone(),
                bootstrap: plan.overlay.bootstrap.clone(),
            }),
        };
        network::Network::plan(&live.network, &p).is_ok_and(|actual| actual == plan.network)
    }
    fn archive_settled(&self, journal: &Journal, next_key: &str) -> Result<(), Error> {
        use std::io::Read;
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        // Large, valid provider snapshots need about 0.5s each on the ARM64
        // guest. This remains bounded inside the transaction's original 120s;
        // the coordinator rechecks that deadline before any capture mutation.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut verification = ArchiveVerification::default();
        for snapshot in [&journal.current_core, &journal.previous_core, &journal.baseline_core] {
            archive_snapshot_result(
                journal.rollback_direct_complete(),
                verification.verify(snapshot, |snapshot| {
                    self.core.verify_pinned(snapshot).map_err(|_| Error::Storage)
                }),
            )?;
            if Instant::now() >= deadline {
                return Err(Error::NotReady);
            }
        }
        let dir = Path::new(CONFIG).join("network-history");
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => std::fs::File::open(CONFIG)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error::Storage)?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(Error::Storage),
        }
        let meta = std::fs::symlink_metadata(&dir).map_err(|_| Error::Storage)?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
            return Err(Error::Storage);
        }
        if journal.idempotency_key == next_key {
            return Err(Error::Conflict);
        }
        let bytes = serde_json::to_vec(journal).map_err(|_| Error::Storage)?;
        if bytes.len() > 1_048_576 {
            return Err(Error::Storage);
        }
        let target = dir.join(format!("{}.json", journal.tx_id));
        match std::fs::symlink_metadata(&target) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                xkeenwrt_recovery::resources::admit_history_append(
                    Path::new(CONFIG),
                    bytes.len() as u64,
                    xkeenwrt_recovery::resources::HistoryArea::Network,
                )
                .map_err(|_| Error::Storage)?;
            }
            Ok(_) => (),
            Err(_) => return Err(Error::Storage),
        }
        let mut count = 0usize;
        for entry in std::fs::read_dir(&dir).map_err(|_| Error::Storage)? {
            if Instant::now() >= deadline {
                return Err(Error::NotReady);
            }
            let entry = entry.map_err(|_| Error::Storage)?;
            count += 1;
            if count > 128 {
                return Err(Error::Storage);
            }
            let name = entry.file_name().into_string().map_err(|_| Error::Storage)?;
            let id = name.strip_suffix(".json").ok_or(Error::Storage)?;
            let parsed = uuid::Uuid::parse_str(id).map_err(|_| Error::Storage)?;
            if parsed.to_string() != id {
                return Err(Error::Storage);
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
                .open(entry.path())
                .map_err(|_| Error::Storage)?;
            let m = file.metadata().map_err(|_| Error::Storage)?;
            if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 1_048_576 {
                return Err(Error::Storage);
            }
            let mut data = Vec::new();
            file.take(1_048_577)
                .read_to_end(&mut data)
                .map_err(|_| Error::Storage)?;
            let old: Journal = serde_json::from_slice(&data).map_err(|_| Error::Storage)?;
            if old.tx_id != id
                || old.current.owner_id != journal.current.owner_id
                || old.decision(&old.boot_id, old.created_boottime_ms, false) != xkeenwrt_recovery::Decision::Settled
            {
                return Err(Error::Storage);
            }
            for snapshot in [&old.current_core, &old.previous_core, &old.baseline_core] {
                verification.verify(snapshot, |snapshot| {
                    self.core.verify_pinned(snapshot).map_err(|_| Error::Storage)
                })?;
                if Instant::now() >= deadline {
                    return Err(Error::NotReady);
                }
            }
            if old.idempotency_key == next_key {
                return Err(Error::Conflict);
            }
        }
        match crate::private_file::publish_private(&target, &bytes) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
                    .open(target)
                    .map_err(|_| Error::Storage)?;
                let m = file.metadata().map_err(|_| Error::Storage)?;
                if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > 1_048_576 {
                    return Err(Error::Storage);
                }
                let mut existing = Vec::new();
                file.take(1_048_577)
                    .read_to_end(&mut existing)
                    .map_err(|_| Error::Storage)?;
                if existing != bytes {
                    return Err(Error::Conflict);
                }
                Ok(())
            }
            Err(_) => Err(Error::Storage),
        }
    }
    fn settled_inactive(journal: &Journal) -> bool {
        journal.decision(&journal.boot_id, journal.created_boottime_ms, false) == xkeenwrt_recovery::Decision::Settled
            && (journal.state == State::RolledBack
                || journal.state == State::Disabled
                || (journal.state == State::Confirmed && journal.operation == Operation::Disable && journal.applied))
    }
    fn settled(journal: &Journal) -> bool {
        journal.decision(&journal.boot_id, journal.created_boottime_ms, false) == xkeenwrt_recovery::Decision::Settled
    }
    pub(crate) fn active_manifest(journal: &Journal) -> Option<&Manifest> {
        match (journal.state, journal.operation) {
            (State::Confirmed, Operation::Apply) if journal.applied => Some(&journal.current),
            (State::RolledBack, Operation::Apply) => journal.previous_good.as_ref(),
            _ => None,
        }
    }
    pub(crate) fn capability_manifest(journal: &Journal) -> Option<&Manifest> {
        if journal.state == State::Pending && journal.operation == Operation::Apply {
            if journal.applied {
                Some(&journal.current)
            } else {
                journal.previous_good.as_ref()
            }
        } else {
            Self::active_manifest(journal)
        }
    }
    pub(crate) fn active_core<'j>(
        journal: &'j Journal, manifest: &Manifest,
    ) -> Option<&'j xkeenwrt_recovery::CoreSnapshot> {
        if journal.state == State::Confirmed && journal.current.generation == manifest.generation {
            Some(&journal.current_core)
        } else if journal
            .previous_good
            .as_ref()
            .is_some_and(|v| v.generation == manifest.generation)
        {
            Some(&journal.previous_core)
        } else {
            None
        }
    }
    fn boot() -> Result<String, Error> {
        let mut s = String::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")
            .and_then(|f| f.take(128).read_to_string(&mut s))
            .map_err(|_| Error::Storage)?;
        let s = s.trim();
        let id = uuid::Uuid::parse_str(s).map_err(|_| Error::Storage)?;
        if id.to_string() != s {
            return Err(Error::Storage);
        }
        Ok(s.into())
    }
    fn revoke(&mut self, p: &Pending) {
        if let Ok(Some(mut journal)) = Self::secure_journal()
            && journal.tx_id == p.transaction_id
            && journal.revoke(p.request.generation)
        {
            let _ = xkeenwrt_recovery::write_journal(Path::new(CONFIG), &journal);
        }
    }
}

fn bound_previous_network_evidence(
    previous: Option<&Manifest>, evidence: Option<&xkeenwrt_recovery::evidence::NetworkEvidence>,
) -> Result<Option<xkeenwrt_recovery::evidence::NetworkEvidence>, Error> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let evidence = evidence.ok_or(Error::Conflict)?;
    if !evidence.matches_manifest(previous) {
        return Err(Error::Conflict);
    }
    Ok(Some(evidence.clone()))
}

impl<V: Validator> Driver for OpenWrtDriver<'_, V> {
    type Guard = MutationLock;
    fn idle_ready(&mut self, request: &Request, transaction_id: &str) -> Result<(), Error> {
        if !crate::runtime::core::deployment_allowed()
            || request.plan_id != self.plan.plan_id
            || request.candidate_id != self.plan.candidate_id
            || request.generation != self.plan.network.manifest().generation
        {
            return Err(Error::Conflict);
        }
        let fd = cgroup::create(
            &self.incarnation,
            &self.plan.network.manifest().owner_id,
            request.generation,
            transaction_id,
        )
        .map_err(|_| Error::NotReady)?;
        self.core
            .set_operation_cgroup(
                fd.try_clone().map_err(|_| Error::Storage)?,
                &self.incarnation,
                &self.plan.network.manifest().owner_id,
                request.generation,
                transaction_id,
            )
            .map_err(|_| Error::NotReady)?;
        self.cgroup = Some(fd);
        use std::os::fd::AsRawFd;
        let cgroup = self.cgroup.as_ref().ok_or(Error::NotReady)?;
        let (_, digest, build_id) =
            crate::platform::Platform::verified_recovery(cgroup.as_raw_fd()).ok_or(Error::NotReady)?;
        xkeenwrt_recovery::rescue::verify(&digest, build_id).map_err(|_| Error::NotReady)?;
        let response = read::query(Query::RecoveryService, cgroup).map_err(|_| Error::NotReady)?;
        let state: serde_json::Value = serde_json::from_slice(&response).map_err(|_| Error::NotReady)?;
        if state.as_object().is_some_and(|o| o.is_empty()) {
            helper::start(cgroup).map_err(|_| Error::NotReady)?;
        }
        let boot = Self::boot()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(identity) = helper::read_idle(&Path::new(RUN).join("recovery.idle"))
                && helper::verify_supervisor(&identity, &self.plan.network.manifest().owner_id, &boot, cgroup).is_ok()
            {
                self.supervisor = Some(identity);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::NotReady);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn lock(&mut self) -> Result<MutationLock, Error> {
        // A full healthy-core/topology observation held this same lock for
        // 2.25–2.94s in the ARM64 VM. Wait for one bounded observation; the
        // transaction rechecks its original deadline and revoke after locking.
        MutationLock::acquire(&Path::new(RUN).join("mutation.lock"), Duration::from_secs(8))
            .map_err(|_| Error::NotReady)
    }
    fn now_ms(&mut self) -> Result<u64, Error> {
        xkeenwrt_recovery::boottime_ms().map_err(|_| Error::Storage)
    }
    fn boot_id(&mut self) -> Result<String, Error> {
        Self::boot()
    }
    fn make_token(&mut self, tx: &str, request: &Request) -> Result<String, Error> {
        let allow = Self::secure_journal()?.is_none();
        let key = key::load(Path::new(CONFIG), allow).map_err(|_| Error::Storage)?;
        Ok(transaction::confirmation_token(
            &key,
            tx,
            request.generation,
            &request.plan_id,
            &request.idempotency_key,
        ))
    }
    fn load_pending(&mut self) -> Result<Option<Pending>, Error> {
        let Some(j) = Self::secure_journal()? else {
            return Ok(None);
        };
        if Self::settled_inactive(&j) || (Self::settled(&j) && j.state == State::Confirmed && j.applied) {
            return Ok(None);
        }
        if j.state != State::Pending {
            return Err(Error::Conflict);
        }
        let key = key::load(Path::new(CONFIG), false).map_err(|_| Error::Storage)?;
        transaction::pending_from_journal(
            &j,
            &key,
            &Self::boot()?,
            xkeenwrt_recovery::boottime_ms().map_err(|_| Error::Storage)?,
        )
        .map(Some)
    }
    fn attach_pending(&mut self, pending: &Pending) -> Result<(), Error> {
        OpenWrtDriver::attach_pending(self, pending)
    }
    fn prepare_pending(&mut self, p: &Pending) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        crate::runtime::core::ensure_no_lifecycle_request().map_err(|_| Error::Conflict)?;
        let prior = Self::secure_journal()?;
        let marker = identity::never_enabled_present(Path::new(CONFIG)).map_err(|_| Error::Storage)?;
        let previous_manifest = self.plan.previous.as_ref();
        // Read-only inputs first: Start reserves its whole history cost once,
        // before its first archive or snapshot write (decision 023).
        let candidate = self
            .activation
            .candidate_bundle(&self.plan.profile_id, &self.plan.revision, &self.plan.candidate_id)
            .map_err(|_| Error::Conflict)?;
        let source = self
            .activation
            .candidate_bundle(
                &self.plan.profile_id,
                &self.plan.revision,
                &self.plan.manual_candidate_id,
            )
            .map_err(|_| Error::Conflict)?;
        let baseline = self
            .activation
            .compose_bundle(
                &source,
                profile_policy::InputsOverlay {
                    explicit: self.plan.explicit.clone(),
                    gateway: None,
                },
            )
            .map_err(|_| Error::NotReady)?;
        if let Some(old) = prior.as_ref() {
            let active = Self::active_manifest(old);
            let active_matches = match (Self::active_manifest(old), previous_manifest) {
                (None, None) => true,
                (Some(a), Some(b)) => serde_json::to_vec(a).ok() == serde_json::to_vec(b).ok(),
                _ => false,
            };
            if !Self::settled(old)
                || old.current.owner_id != self.plan.network.manifest().owner_id
                || old.generation >= p.request.generation
                || !active_matches
                || (active.is_none() && !Self::settled_inactive(old))
            {
                return Err(Error::Conflict);
            }
            if !cgroup::old_operation_empty(old).map_err(|_| Error::Storage)? {
                return Err(Error::Conflict);
            }
            let m = self.plan.network.manifest();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::NotReady)?
                .as_secs();
            let live = collector::collect_for_generation(
                &m.lan_interface,
                m.source_ipv4,
                m.management_ipv4,
                now,
                previous_manifest,
                self.cgroup.as_ref().ok_or(Error::NotReady)?,
            )
            .map_err(|_| Error::Conflict)?;
            if !Self::matches_live(&self.plan, &live)
                || (previous_manifest.is_none() && !status::retired_resources_absent(old, &live.network))
            {
                return Err(Error::Conflict);
            }
            match std::fs::symlink_metadata(Path::new(CONFIG).join("reconcile.json")) {
                Ok(_) => return Err(Error::Conflict),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(_) => return Err(Error::Storage),
            }
            use xkeenwrt_recovery::resources::{HistoryArea, HistoryNeed};
            let archive = serde_json::to_vec(old).map_err(|_| Error::Storage)?.len() as u64;
            let mut need = HistoryNeed::archive(HistoryArea::Network, archive)
                .and(&crate::runtime::core::snapshot_need(&candidate))
                .and(&crate::runtime::core::snapshot_need(&baseline));
            if Path::new(CONFIG).join("active-reconcile.json").exists() {
                need = need.and(&HistoryNeed::archive(HistoryArea::ActiveEvents, 16_384));
            }
            // The new journal reuses the settled generation's snapshots.
            let protect = [&old.current_core, &old.previous_core, &old.baseline_core]
                .into_iter()
                .chain(old.next_baseline_core.as_ref())
                .map(|snapshot| snapshot.snapshot_id.clone())
                .collect();
            crate::runtime::resources::reserve_history(&need, &protect).map_err(|_| Error::Storage)?;
            super::active::retire_current(Path::new(CONFIG), old).map_err(|_| Error::Conflict)?;
            super::active::ensure_key_unused(Path::new(CONFIG), old, &p.request.idempotency_key)
                .map_err(|_| Error::Conflict)?;
            self.archive_settled(old, &p.request.idempotency_key)?;
        } else if !marker {
            return Err(Error::Conflict);
        }
        self.consume_marker = marker;
        let mut shared_baseline = None;
        let (previous_core, baseline_core, previous_good) =
            if let (Some(old), Some(manifest)) = (prior.as_ref(), previous_manifest) {
                let active_core = Self::active_core(old, manifest).ok_or(Error::Conflict)?;
                self.core.verify_pinned(active_core).map_err(|_| Error::Storage)?;
                self.core.health().map_err(|_| Error::Unhealthy)?;
                (active_core.clone(), old.baseline_core.clone(), Some(manifest.clone()))
            } else {
                let previous = self
                    .activation
                    .current_manual_bundle(Path::new(CONFIG))
                    .map_err(|_| Error::NotReady)?;
                let running = self.core.running().map_err(|_| Error::NotReady)?;
                if running {
                    self.core.health().map_err(|_| Error::Unhealthy)?;
                }
                let explicit = crate::runtime::grant::selected_explicit().map_err(|_| Error::Storage)?;
                let previous = self
                    .activation
                    .compose_bundle(
                        &previous,
                        profile_policy::InputsOverlay {
                            explicit,
                            gateway: None,
                        },
                    )
                    .map_err(|_| Error::NotReady)?;
                let baseline_running = self.plan.explicit.is_some();
                let shares = crate::runtime::core::same_contents(&previous, &baseline);
                let mut need = crate::runtime::core::snapshot_need(&previous)
                    .and(&crate::runtime::core::snapshot_need(&candidate));
                if !shares {
                    need = need.and(&crate::runtime::core::snapshot_need(&baseline));
                }
                crate::runtime::resources::reserve_history(&need, &Default::default()).map_err(|_| Error::Storage)?;
                let snapshot = self.core.snapshot_pin(&previous, running).map_err(|_| Error::Storage)?;
                if shares {
                    shared_baseline =
                        crate::runtime::core::reuse_snapshot(&snapshot, &previous, &baseline, baseline_running);
                }
                (snapshot.clone(), snapshot, None)
            };
        let current_core = self.core.snapshot_pin(&candidate, true).map_err(|_| Error::Storage)?;
        let next_baseline_core = Some(match shared_baseline {
            Some(shared) => shared,
            None => self
                .core
                .snapshot_pin(&baseline, self.plan.explicit.is_some())
                .map_err(|_| Error::Storage)?,
        });
        let (runtime_pid, runtime_starttime) = helper::current_runtime_identity().map_err(|_| Error::Storage)?;
        if runtime_pid != self.incarnation.pid
            || runtime_starttime != self.incarnation.starttime
            || p.boot_id != self.incarnation.boot_id
        {
            return Err(Error::Conflict);
        }
        let hash = Sha256::digest(p.confirm_token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let current = self.manifest()?;
        // The supervisor must still be the exact verified rescue build before
        // publishing a journal using the evidence-aware schema.
        helper::verify_supervisor(
            self.supervisor.as_ref().ok_or(Error::NotReady)?,
            &current.owner_id,
            &p.boot_id,
            self.cgroup.as_ref().ok_or(Error::NotReady)?,
        )
        .map_err(|_| Error::NotReady)?;
        let network_evidence = match previous_manifest {
            Some(previous) => collector::collect_replacement_evidence(
                previous,
                &current,
                self.cgroup.as_ref().ok_or(Error::NotReady)?,
            ),
            None => collector::collect_initial_evidence(&current, self.cgroup.as_ref().ok_or(Error::NotReady)?),
        }
        .map_err(|_| Error::Conflict)?;
        let active_failblock_semantic_sha256 =
            if current.failure_policy == xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure {
                let ast = current.expected_failblock_ast(&current).map_err(|_| Error::NotReady)?;
                Some(
                    xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&ast).map_err(|_| Error::Storage)?)
                        .map_err(|_| Error::NotReady)?,
                )
            } else {
                None
            };
        let failblock_semantic_sha256 = if let Some(previous) =
            previous_manifest.filter(|m| m.failure_policy == xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure)
        {
            let ast = previous.expected_failblock_ast(&current).map_err(|_| Error::NotReady)?;
            Some(
                xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&ast).map_err(|_| Error::Storage)?)
                    .map_err(|_| Error::NotReady)?,
            )
        } else {
            None
        };
        let j = Journal {
            version: 1,
            operation: Operation::Apply,
            tx_id: p.transaction_id.clone(),
            plan_id: p.request.plan_id.clone(),
            candidate_id: p.request.candidate_id.clone(),
            profile_id: self.plan.profile_id.clone(),
            revision: self.plan.revision.clone(),
            idempotency_key: p.request.idempotency_key.clone(),
            confirm_token_sha256: hash,
            applied: false,
            generation: p.request.generation,
            runtime_pid,
            runtime_starttime,
            runtime_nonce: self.incarnation.nonce.clone(),
            boot_id: p.boot_id.clone(),
            created_boottime_ms: p.created_ms,
            deadline_boottime_ms: p.deadline_ms,
            state: State::Pending,
            completion: None,
            current,
            previous_good: previous_good.clone(),
            previous_network_evidence: bound_previous_network_evidence(
                previous_manifest,
                prior.as_ref().and_then(xkeenwrt_recovery::active::active_evidence),
            )?,
            failblock_semantic_sha256,
            active_failblock_semantic_sha256,
            network_evidence: Some(network_evidence),
            current_core,
            previous_core,
            baseline_core,
            next_baseline_core,
            profile_acceptance: None,
            cancel_capture: false,
        };
        if j.decision(&p.boot_id, p.created_ms, false) != xkeenwrt_recovery::Decision::Wait {
            return Err(Error::Conflict);
        }
        helper::verify_supervisor(
            self.supervisor.as_ref().ok_or(Error::NotReady)?,
            &j.current.owner_id,
            &p.boot_id,
            self.cgroup.as_ref().ok_or(Error::NotReady)?,
        )
        .map_err(|_| Error::NotReady)?;
        xkeenwrt_recovery::write_journal(Path::new(CONFIG), &j).map_err(|_| Error::Storage)
    }
    fn await_ready(&mut self, p: &Pending) -> Result<(), Error> {
        loop {
            if self.ready(p)? {
                return Ok(());
            }
            if self.now_ms()? >= p.deadline_ms {
                return Err(Error::Expired);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn ready(&mut self, p: &Pending) -> Result<bool, Error> {
        let supervisor = self.supervisor.as_ref().ok_or(Error::NotReady)?;
        // Polling before READY must not populate the operation cgroup; the helper requires it empty.
        let ready = match helper::ready_matches(
            &Path::new(RUN).join("recovery.ready"),
            &p.transaction_id,
            p.request.generation,
            supervisor,
        ) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(Error::NotReady),
        };
        if !ready {
            return Ok(false);
        }
        let cgroup = self.cgroup.as_ref().ok_or(Error::NotReady)?;
        helper::verify_supervisor(supervisor, &self.plan.network.manifest().owner_id, &p.boot_id, cgroup)
            .map_err(|_| Error::NotReady)?;
        Ok(true)
    }
    fn revalidate(&mut self, p: &Pending) -> Result<(), Error> {
        crate::runtime::core::ensure_no_lifecycle_request().map_err(|_| Error::Conflict)?;
        let journal = Self::secure_journal()?.ok_or(Error::Conflict)?;
        if journal.tx_id != p.transaction_id || journal.generation != p.request.generation {
            return Err(Error::Conflict);
        }
        let expected = journal.network_evidence.as_ref().ok_or(Error::NotReady)?;
        let fresh = match self.plan.previous.as_ref() {
            Some(previous) => collector::collect_replacement_evidence(
                previous,
                &journal.current,
                self.cgroup.as_ref().ok_or(Error::NotReady)?,
            ),
            None => collector::collect_initial_evidence(&journal.current, self.cgroup.as_ref().ok_or(Error::NotReady)?),
        }
        .map_err(|_| Error::Conflict)?;
        if !fresh.compatible_with(expected) {
            return Err(Error::Conflict);
        }
        let m = self.plan.network.manifest();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::NotReady)?
            .as_secs();
        let live = collector::collect_for_generation(
            &m.lan_interface,
            m.source_ipv4,
            m.management_ipv4,
            now,
            self.plan.previous.as_ref(),
            self.cgroup.as_ref().ok_or(Error::NotReady)?,
        )
        .map_err(|_| Error::Conflict)?;
        if !Self::matches_live(&self.plan, &live) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn not_revoked(&mut self, p: &Pending) -> Result<bool, Error> {
        helper::generation_unfenced(p.request.generation).map_err(|_| Error::Storage)
    }
    fn apply(&mut self, p: &Pending) -> Result<(), Error> {
        let fd = self
            .cgroup
            .as_ref()
            .ok_or(Error::NotReady)?
            .try_clone()
            .map_err(|_| Error::Storage)?;
        let cgroup_for_reads = fd.try_clone().map_err(|_| Error::Storage)?;
        let mut io = network::executor::OpenWrtNetworkIo::new(fd, p.request.generation).ok_or(Error::NotReady)?;
        let supervisor = self.supervisor.clone().ok_or(Error::NotReady)?;
        let journal = Self::secure_journal()?.ok_or(Error::Conflict)?;
        if journal.tx_id != p.transaction_id || journal.generation != p.request.generation {
            return Err(Error::Conflict);
        }
        let expected_evidence = journal.network_evidence.clone().ok_or(Error::NotReady)?;
        let consume_marker = self.consume_marker;
        let core = &mut self.core;
        let prepared = &self.plan;
        let plan = &prepared.network;
        // Fixed stage names are useful diagnostics without exposing profiles,
        // controller credentials, addresses or command output.
        let mut stage = "candidate";
        let result = self.activation.with_candidate(
            &self.plan.profile_id,
            &self.plan.revision,
            &self.plan.candidate_id,
            |bundle| {
                crate::runtime::core::ensure_no_lifecycle_request()?;
                stage = "core-start";
                core.publish_transient(&bundle)?;
                if !helper::generation_unfenced(p.request.generation)
                    .map_err(|_| crate::configuration::ActivationError::Storage)?
                    || xkeenwrt_recovery::boottime_ms().map_err(|_| crate::configuration::ActivationError::Storage)?
                        >= p.deadline_ms
                {
                    return Err(crate::configuration::ActivationError::Conflict);
                }
                let m = plan.manifest();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?
                    .as_secs();
                stage = "post-start-inventory";
                let live = collector::collect_after_core(
                    &m.lan_interface,
                    m.source_ipv4,
                    m.management_ipv4,
                    now,
                    prepared.previous.as_ref(),
                    &cgroup_for_reads,
                )
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                stage = "inventory-match";
                if !Self::matches_live(prepared, &live) {
                    return Err(crate::configuration::ActivationError::Conflict);
                }
                stage = "network-evidence";
                let fresh = match prepared.previous.as_ref() {
                    Some(previous) => {
                        collector::collect_replacement_evidence(previous, &journal.current, &cgroup_for_reads)
                    }
                    None => collector::collect_initial_evidence(&journal.current, &cgroup_for_reads),
                }
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                stage = "evidence-match";
                if !fresh.compatible_with(&expected_evidence) {
                    return Err(crate::configuration::ActivationError::Conflict);
                }
                stage = "supervisor";
                helper::verify_supervisor(&supervisor, &plan.manifest().owner_id, &p.boot_id, &cgroup_for_reads)
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                stage = "ready";
                if !helper::ready_matches(
                    &Path::new(RUN).join("recovery.ready"),
                    &p.transaction_id,
                    p.request.generation,
                    &supervisor,
                )
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?
                {
                    return Err(crate::configuration::ActivationError::Unavailable);
                }
                if xkeenwrt_recovery::boottime_ms().map_err(|_| crate::configuration::ActivationError::Storage)?
                    >= p.deadline_ms
                {
                    return Err(crate::configuration::ActivationError::Conflict);
                }
                crate::runtime::core::ensure_no_lifecycle_request()?;
                if consume_marker {
                    identity::consume_never_enabled(Path::new(CONFIG))
                        .map_err(|_| crate::configuration::ActivationError::Storage)?;
                }
                stage = "network-transition";
                network::executor::apply_transition(plan, prepared.previous.as_ref(), &mut io)
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                stage = "offload-transition";
                let m = &journal.current;
                let q = |query| {
                    read::query(query, &cgroup_for_reads)
                        .map_err(|_| crate::configuration::ActivationError::Unavailable)
                };
                let links = q(Query::Links)?;
                let (nft, tables) =
                    xkeenwrt_recovery::flow_offload::capture_nft(|| read::query(Query::NftRuleset, &cgroup_for_reads))
                        .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                xkeenwrt_recovery::flow_offload::verify_for_lan(&nft, &tables, &links, &m.lan_interface)
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                if xkeenwrt_recovery::flow_offload::transition_required(&tables, &links, &m.lan_interface)
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?
                {
                    let addresses = q(Query::Addresses)?;
                    let rules = q(Query::Rules4)?;
                    let routes6 = q(Query::Routes6)?;
                    let scope =
                        xkeenwrt_recovery::flow_offload::Scope::prove(m, &addresses, &links, &nft, &rules, &routes6)
                            .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                    let remaining = p.deadline_ms.saturating_sub(
                        xkeenwrt_recovery::boottime_ms()
                            .map_err(|_| crate::configuration::ActivationError::Unavailable)?,
                    );
                    if remaining == 0 {
                        return Err(crate::configuration::ActivationError::Unavailable);
                    }
                    xkeenwrt_recovery::flow_offload::invalidate(
                        &scope,
                        std::time::Instant::now() + Duration::from_millis(remaining),
                    )
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                    let fresh = collector::collect_evidence(
                        m,
                        xkeenwrt_recovery::evidence::NftExpectation::Digest(&m.nft_semantic_sha256),
                        xkeenwrt_recovery::evidence::RoutingExpectation::Exact,
                        &cgroup_for_reads,
                    )
                    .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
                    if !fresh.compatible_with(&expected_evidence) {
                        return Err(crate::configuration::ActivationError::Conflict);
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            eprintln!("network apply failed at {stage}: {error:?}");
            self.revoke(p);
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn mark_applied(&mut self, p: &Pending) -> Result<(), Error> {
        let mut j = Self::secure_journal()?.ok_or(Error::Conflict)?;
        if j.tx_id != p.transaction_id || j.state != State::Pending {
            return Err(Error::Conflict);
        }
        j.applied = true;
        helper::verify_supervisor(
            self.supervisor.as_ref().ok_or(Error::NotReady)?,
            &j.current.owner_id,
            &p.boot_id,
            self.cgroup.as_ref().ok_or(Error::NotReady)?,
        )
        .map_err(|_| Error::NotReady)?;
        xkeenwrt_recovery::write_journal(Path::new(CONFIG), &j).map_err(|_| Error::Storage)
    }
    fn is_applied(&mut self, p: &Pending) -> Result<bool, Error> {
        Ok(Self::secure_journal()?
            .is_some_and(|j| j.tx_id == p.transaction_id && j.state == State::Pending && j.applied))
    }
    fn verify_active(&mut self, _: &Pending) -> Result<bool, Error> {
        let j = Self::secure_journal()?.ok_or(Error::Conflict)?;
        let actual =
            read::query(Query::NftOwned, self.cgroup.as_ref().ok_or(Error::NotReady)?).map_err(|_| Error::NotReady)?;
        let digest = xkeenwrt_recovery::nft_semantic_digest(&actual).map_err(|_| Error::Conflict)?;
        let rules =
            read::query(Query::Rules4, self.cgroup.as_ref().ok_or(Error::NotReady)?).map_err(|_| Error::NotReady)?;
        let routes =
            read::query(Query::Routes4, self.cgroup.as_ref().ok_or(Error::NotReady)?).map_err(|_| Error::NotReady)?;
        Ok(digest == j.current.nft_semantic_sha256
            && status::routing_matches(&j.current, &rules, &routes).map_err(|_| Error::Conflict)?)
    }
    fn health(&mut self, _: &Pending) -> Result<bool, Error> {
        Ok(self.core.health().is_ok())
    }
    fn confirmed_for(&mut self, request: &Request) -> Result<Option<String>, Error> {
        let Some(journal) = Self::secure_journal()? else {
            return Ok(None);
        };
        if journal.state != State::Confirmed {
            return Ok(None);
        }
        if journal.operation == Operation::Disable && journal.idempotency_key != request.idempotency_key {
            return Ok(None);
        }
        if journal.operation == Operation::Apply && !transaction::confirmed_request_is_replay(&journal, request)? {
            return Ok(None);
        }
        if journal.plan_id != request.plan_id
            || journal.candidate_id != request.candidate_id
            || journal.idempotency_key != request.idempotency_key
            || journal.generation != request.generation
            || journal.profile_id != self.plan.profile_id
            || journal.revision != self.plan.revision
            || journal.current.owner_id != self.plan.network.manifest().owner_id
            || !journal.applied
            || journal.boot_id != Self::boot()?
            || !helper::generation_unfenced(journal.generation).map_err(|_| Error::Storage)?
            || journal.decision(&journal.boot_id, journal.created_boottime_ms, false)
                != xkeenwrt_recovery::Decision::Settled
        {
            return Err(Error::Conflict);
        }
        Ok(Some(journal.tx_id))
    }
    fn already_confirmed(&mut self, transaction_id: &str, token: &str) -> Result<bool, Error> {
        let Some(journal) = Self::secure_journal()? else {
            return Ok(false);
        };
        if journal.state != State::Confirmed {
            return Ok(false);
        }
        if Self::boot()? != journal.boot_id {
            return Err(Error::Conflict);
        }
        let key = key::load(Path::new(CONFIG), false).map_err(|_| Error::Storage)?;
        let unfenced = helper::generation_unfenced(journal.generation).map_err(|_| Error::Storage)?;
        if transaction::confirmed_token_matches(&journal, &key, transaction_id, token, unfenced) {
            Ok(true)
        } else {
            Err(Error::Conflict)
        }
    }
    fn confirm(&mut self, p: &Pending) -> Result<(), Error> {
        crate::runtime::core::ensure_no_lifecycle_request().map_err(|_| Error::Conflict)?;
        let mut j = Self::secure_journal()?.ok_or(Error::Conflict)?;
        if j.tx_id != p.transaction_id || j.state != State::Pending || !j.applied {
            return Err(Error::Conflict);
        }
        let source = self
            .activation
            .candidate_bundle(
                &self.plan.profile_id,
                &self.plan.revision,
                &self.plan.manual_candidate_id,
            )
            .map_err(|_| Error::Conflict)?;
        self.activation
            .stage_network_acceptance(Path::new(CONFIG), &source, &j.tx_id, &j.idempotency_key)
            .map_err(|_| Error::Storage)?;
        j.state = State::Confirmed;
        j.profile_acceptance = Some(xkeenwrt_recovery::ProfileAcceptance {
            candidate_id: source.meta.candidate_id.clone(),
        });
        if let Some(baseline) = j.next_baseline_core.take() {
            j.baseline_core = baseline;
        }
        helper::verify_supervisor(
            self.supervisor.as_ref().ok_or(Error::NotReady)?,
            &j.current.owner_id,
            &p.boot_id,
            self.cgroup.as_ref().ok_or(Error::NotReady)?,
        )
        .map_err(|_| Error::NotReady)?;
        xkeenwrt_recovery::write_journal(Path::new(CONFIG), &j).map_err(|_| Error::Storage)?;
        self.activation
            .finish_network_acceptance(Path::new(CONFIG), &j.tx_id)
            .map_err(|_| Error::Storage)?;
        crate::runtime::inputs::settle_for(&j).map_err(|_| Error::Storage)
    }
}

impl<V: Validator> Drop for OpenWrtDriver<'_, V> {
    fn drop(&mut self) {
        self.core.clear_operation_cgroup();
    }
}

#[cfg(test)]
mod tests {
    use super::{ArchiveVerification, archive_snapshot_result, bound_previous_network_evidence};
    use crate::runtime::networking::transaction::Error;
    use std::net::Ipv4Addr;
    use xkeenwrt_recovery::{
        FailurePolicy, Manifest,
        evidence::{DnsEvidence, Endpoint, NetworkEvidence, Scope},
    };

    fn manifest() -> Manifest {
        Manifest {
            failure_policy: FailurePolicy::DirectOnFailure,
            owner_id: "00000000-0000-4000-8000-000000000001".into(),
            generation: 1,
            nft_semantic_sha256: "a".repeat(64),
            lan_interface: "br-test".into(),
            lan_address: Ipv4Addr::new(192, 0, 2, 1),
            lan_scope: None,
            capture_version: None,
            selected_mac: "02:00:00:00:00:02".into(),
            management_macs: vec!["02:00:00:00:00:03".into()],
            source_ipv4: Ipv4Addr::new(192, 0, 2, 2),
            management_ipv4: Ipv4Addr::new(192, 0, 2, 3),
            management_ipv6: vec!["2001:db8::3".parse().unwrap()],
            local_ipv4: vec!["192.0.2.0/24".into()],
            selected_ipv6: vec![],
            local_ipv6: vec!["2001:db8::/64".into()],
            route_table: 100,
            mark: 0x100,
            mask: 0x100,
            priority: 10_000,
        }
    }

    fn evidence_for(manifest: &Manifest) -> NetworkEvidence {
        NetworkEvidence {
            flowtables: None,
            version: 1,
            scope: Scope {
                lan_ifname: manifest.lan_interface.clone(),
                lan_ipv4: manifest.lan_address,
                lan_cidrs: vec!["192.0.2.0/24".into()],
                selected_ipv4: manifest.source_ipv4,
                lan_scope: None,
                capture_version: None,
                selected_mac: manifest.selected_mac.clone(),
                management_ipv4: manifest.management_ipv4,
                management_macs: manifest.management_macs.clone(),
                management_ipv6: manifest.management_ipv6.clone(),
                local_ipv4: manifest.local_ipv4.clone(),
                local_ipv6: manifest.local_ipv6.clone(),
            },
            dns: DnsEvidence {
                configuration_sha256: "b".repeat(64),
                default_upstreams: vec![Endpoint {
                    address: "198.51.100.53".parse().unwrap(),
                    port: 53,
                }],
                split_upstreams: vec![],
                local_zones: vec!["+.lan".into()],
                verified_loopback_chain_sha256: None,
            },
            links_sha256: "c".repeat(64),
            addresses_sha256: "d".repeat(64),
            foreign_nft_sha256: "e".repeat(64),
            foreign_rules4_sha256: "f".repeat(64),
            foreign_rules6_sha256: "1".repeat(64),
            foreign_routes4_sha256: "2".repeat(64),
            foreign_routes6_sha256: "3".repeat(64),
        }
    }

    #[test]
    fn archive_verification_reuses_only_identical_leases_in_one_observation() {
        let snapshot = xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000001".into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: "a".repeat(64),
            running: false,
            controller_port: 9090,
            controller_secret_sha256: "b".repeat(64),
            assets: vec![xkeenwrt_recovery::SnapshotAsset {
                relative_path: "providers/rules/0.yaml".into(),
                sha256: "c".repeat(64),
                size: 949_509,
            }],
        };
        let mut calls = 0;
        let mut checks = ArchiveVerification::default();
        for _ in 0..3 {
            checks
                .verify(&snapshot, |_| {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(calls, 1);

        // Even a change outside the YAML digest changes the path's binding.
        let mut conflicting = snapshot.clone();
        conflicting.assets[0].size += 1;
        assert_eq!(
            checks.verify(&conflicting, |_| panic!("conflicting lease")),
            Err(Error::Storage)
        );
        conflicting = snapshot.clone();
        conflicting.running = true;
        assert_eq!(
            checks.verify(&conflicting, |_| panic!("conflicting lease")),
            Err(Error::Storage)
        );

        let mut distinct = snapshot.clone();
        distinct.snapshot_id = "00000000-0000-4000-8000-000000000002".into();
        checks
            .verify(&distinct, |_| {
                calls += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 2);
        ArchiveVerification::default()
            .verify(&snapshot, |_| {
                calls += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 3); // No reuse across operations.
    }

    #[test]
    fn only_a_terminal_direct_journal_archives_past_an_unusable_snapshot() {
        // C3 in the ARM64 VM: recovery closed a rollback RollbackDirect because
        // its snapshot was gone; the next Start must archive that journal.
        assert_eq!(archive_snapshot_result(true, Err(Error::Storage)), Ok(()));
        assert_eq!(archive_snapshot_result(false, Err(Error::Storage)), Err(Error::Storage));
        assert_eq!(
            archive_snapshot_result(true, Err(Error::NotReady)),
            Err(Error::NotReady)
        );
        assert_eq!(archive_snapshot_result(false, Ok(())), Ok(()));
    }

    #[test]
    fn archive_verification_does_not_remember_failed_file_checks() {
        let snapshot = xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000001".into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: "a".repeat(64),
            running: false,
            controller_port: 9090,
            controller_secret_sha256: "b".repeat(64),
            assets: vec![],
        };
        let mut checks = ArchiveVerification::default();
        assert_eq!(checks.verify(&snapshot, |_| Err(Error::Storage)), Err(Error::Storage));
        assert_eq!(checks.verify(&snapshot, |_| Err(Error::Conflict)), Err(Error::Conflict));
    }

    #[test]
    fn fresh_apply_drops_historical_evidence_and_checks_replacement_binding() {
        let prior_manifest = manifest();
        let historical_evidence = evidence_for(&prior_manifest);
        assert!(historical_evidence.matches_manifest(&prior_manifest));

        // A settled Disabled Apply can expose its current evidence through the
        // active-evidence helper even though it has no previous-good generation.
        assert_eq!(
            bound_previous_network_evidence(None, Some(&historical_evidence)),
            Ok(None)
        );

        assert_eq!(
            bound_previous_network_evidence(Some(&prior_manifest), Some(&historical_evidence)),
            Ok(Some(historical_evidence.clone()))
        );
        let mut different_manifest = prior_manifest.clone();
        different_manifest.source_ipv4 = Ipv4Addr::new(192, 0, 2, 4);
        assert_eq!(
            bound_previous_network_evidence(Some(&different_manifest), Some(&historical_evidence)),
            Err(Error::Conflict)
        );
        assert_eq!(
            bound_previous_network_evidence(Some(&prior_manifest), None),
            Err(Error::Conflict)
        );
    }
}
