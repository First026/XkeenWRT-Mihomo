//! Fixed operations for the helper-owned active reconciliation protocol.
use crate::{core, rollback};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
use xkeenwrt_recovery::{
    Journal, State,
    active::{self, Action, ActiveRecord, Adapter, Code, CoreHealth},
    write_journal,
};
const PATH: &str = "/etc/xkeenwrt/active-reconcile.json";

pub fn load() -> io::Result<Option<ActiveRecord>> {
    load_at(Path::new(PATH))
}
fn load_at(path: &Path) -> io::Result<Option<ActiveRecord>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > 16384
    {
        return Err(io::Error::other("unsafe active record"));
    }
    let mut data = Vec::new();
    file.take(16385).read_to_end(&mut data)?;
    active::decode(&data)
        .map(Some)
        .map_err(|_| io::Error::other("invalid active record"))
}
pub fn persist_record(record: &ActiveRecord) -> io::Result<()> {
    let data = active::encode(record).map_err(|_| io::Error::other("invalid active record"))?;
    let tmp = format!("/etc/xkeenwrt/.active-{}", core::fresh_nonce()?);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
        fs::rename(&tmp, PATH)?;
        fs::File::open("/etc/xkeenwrt")?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub fn archive_completed(j: &Journal, record: &ActiveRecord) -> io::Result<()> {
    archive_completed_at(Path::new("/etc/xkeenwrt"), j, record)
}

fn archive_completed_at(root: &Path, j: &Journal, record: &ActiveRecord) -> io::Result<()> {
    if !active::archiveable(record, j) {
        return Err(io::Error::other("invalid active archive binding"));
    }
    write_archive_at(root, record)
}

/// Archive before changing the journal. If interrupted, the same bytes are
/// checked on replay before unlinking; unfinished actions retain their phase.
pub fn retire_for_boot(root: &Path, j: &Journal, boot: &str) -> io::Result<()> {
    if !j.needs_boot_cleanup(boot) {
        return Err(io::Error::other("boot cleanup not required"));
    }
    archive_cleanup_event(root, j, false)?;
    unlink_cleanup_event(root)
}

/// Only the lifecycle owner may migrate legacy Disabled journals. Native
/// callers prove stopped core and absent network before entering this function.
pub fn complete_lifecycle_cleanup(
    root: &Path,
    j: &mut Journal,
    boot: &str,
    request: &xkeenwrt_recovery::LifecycleRequest,
) -> io::Result<()> {
    if request.version != 1
        || request.owner_id != j.current.owner_id
        || request.request_id.as_deref().is_none_or(|id| {
            xkeenwrt_recovery::supervisor_cgroup_path(&request.owner_id, id).is_err()
        })
    {
        return Err(io::Error::other("lifecycle event owner mismatch"));
    }
    let generation = archive_cleanup_event(
        root,
        j,
        j.state == State::Disabled && j.completion.is_none(),
    )?;
    j.finish_lifecycle_cleanup(boot, request, generation)?;
    // Persist the generation inferred from a legacy event before unlinking it.
    // Both sides of this write/unlink window are safely replayable.
    write_journal(root, j)?;
    unlink_cleanup_event(root)
}

fn unlink_cleanup_event(root: &Path) -> io::Result<()> {
    match fs::remove_file(root.join("active-reconcile.json")) {
        Ok(()) => fs::File::open(root)?.sync_all(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn archive_cleanup_event(root: &Path, j: &Journal, legacy: bool) -> io::Result<Option<u64>> {
    let path = root.join("active-reconcile.json");
    let Some(mut record) = load_at(&path)? else {
        return Ok(active::active_manifest(j).map(|m| m.generation));
    };
    let mut binding = j.clone();
    if legacy {
        binding.state = if record.generation == j.current.generation {
            State::Confirmed
        } else if j
            .previous_good
            .as_ref()
            .is_some_and(|m| m.generation == record.generation)
        {
            State::RolledBack
        } else {
            return Err(io::Error::other("unknown legacy event generation"));
        };
    }
    if !(if legacy || j.lifecycle_cleanup_complete() {
        record.valid_binding(&binding)
    } else {
        record.valid_for(j)
    }) {
        return Err(io::Error::other("cleanup event binding mismatch"));
    }
    // Network absence and stopped core have already been proved. Finish
    // the split Disable write; preserve pre-existing errors without rewriting.
    if record.kind == active::Kind::DisableRequested && record.phase == active::Phase::Verified {
        record.phase = active::Phase::Completed;
        record.outcome = Some(active::Outcome::Disabled);
    } else if !matches!(
        record.phase,
        active::Phase::Completed | active::Phase::Error
    ) {
        record.failed_phase = Some(record.phase);
        record.phase = active::Phase::Error;
        record.error_code = Some(Code::Unavailable.as_str().into());
        record.outcome = None;
    }
    write_archive_at(root, &record)?;
    Ok(Some(record.generation))
}

fn write_archive_at(root: &Path, record: &ActiveRecord) -> io::Result<()> {
    let dir = root.join("active-event-history");
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => fs::File::open(root)?.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let meta = fs::symlink_metadata(&dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
    {
        return Err(io::Error::other("unsafe active history"));
    }
    let target = dir.join(format!("{}.json", record.event_id));
    let bytes = active::encode(record).map_err(|_| io::Error::other("invalid active record"))?;
    if !target.exists() {
        xkeenwrt_recovery::resources::admit_history_append(
            root,
            bytes.len() as u64,
            xkeenwrt_recovery::resources::HistoryArea::ActiveEvents,
        )?;
    }
    let tmp = dir.join(format!(".active-{}", core::fresh_nonce()?));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        if !xkeenwrt_recovery::publish_noreplace(&tmp, &target)? {
            fs::remove_file(&tmp)?;
            let old = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&target)?;
            let m = old.metadata()?;
            if !m.is_file()
                || m.uid() != 0
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len() > 16384
            {
                return Err(io::Error::other("unsafe active archive"));
            }
            let mut previous = Vec::new();
            old.take(16385).read_to_end(&mut previous)?;
            if previous != bytes {
                return Err(io::Error::other("active archive conflict"));
            }
        }
        fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn active_view(j: &Journal) -> Result<Journal, Code> {
    if xkeenwrt_recovery::active::active_manifest(j).is_some_and(|m| {
        j.previous_good
            .as_ref()
            .is_some_and(|p| p.generation == m.generation)
    }) {
        let mut view = j.clone();
        view.current = j.previous_good.clone().ok_or(Code::Invalid)?;
        view.generation = view.current.generation;
        view.current_core = j.previous_core.clone();
        view.active_failblock_semantic_sha256 = if view.current.failure_policy
            == xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure
        {
            let ast = view
                .current
                .expected_failblock_ast(&view.current)
                .map_err(|_| Code::Invalid)?;
            Some(
                xkeenwrt_recovery::nft_semantic_digest(
                    &serde_json::to_vec(&ast).map_err(|_| Code::Invalid)?,
                )
                .map_err(|_| Code::Invalid)?,
            )
        } else {
            None
        };
        view.completion = None;
        view.network_evidence = j.previous_network_evidence.clone();
        view.previous_good = None;
        view.previous_network_evidence = None;
        view.state = State::Confirmed;
        view.operation = xkeenwrt_recovery::Operation::Apply;
        view.applied = true;
        Ok(view)
    } else {
        Ok(j.clone())
    }
}
fn verify_restore(j: &Journal, required: Option<(bool, bool)>) -> Result<(), Code> {
    let view = active_view(j)?;
    let j = &view;
    if crate::health::observe(&j.current_core)? != CoreHealth::Healthy {
        return Err(Code::Health);
    }
    let state = recovery(rollback::active_nft_state(j))?;
    let routing = recovery(rollback::active_routing_state(j))?;
    verify_observed_topology(j, state, routing, required)
}
fn verify_observed_topology(
    j: &Journal,
    state: rollback::ActiveNftState,
    routing: (bool, bool),
    required: Option<(bool, bool)>,
) -> Result<(), Code> {
    let evidence = j.network_evidence.as_ref().ok_or(Code::Unavailable)?;
    let digest = match state {
        rollback::ActiveNftState::Missing => None,
        rollback::ActiveNftState::Failblock => Some(
            j.active_failblock_semantic_sha256
                .as_deref()
                .ok_or(Code::Invalid)?,
        ),
        rollback::ActiveNftState::Current => Some(j.current.nft_semantic_sha256.as_str()),
    };
    if required.is_some_and(|v| v != routing) {
        return Err(Code::Drift);
    }
    crate::active_inventory::verify_failure_topology(&j.current, evidence, digest, routing)
        .map_err(|_| Code::Drift)
}
/// Detect only drift that can be repaired by the helper's exact, journal-owned
/// restore path. Unknown ownership or core evidence remains an error and never
/// schedules a mutation.
pub fn observe_active(
    j: &Journal,
    prior: Option<&ActiveRecord>,
) -> Result<(CoreHealth, bool), Code> {
    // One journal/current-or-previous view, under the supervisor mutation lock.
    // This readonly observation is never reused by a restore or mutation.
    let completed_direct = prior.is_some_and(|r| {
        r.valid_for(j)
            && r.kind == active::Kind::ReconcileRequested
            && r.phase == active::Phase::Completed
            && r.action == Some(Action::Direct)
            && r.outcome == Some(active::Outcome::Direct)
    });
    let view = active_view(j)?;
    let health = crate::health::observe(&view.current_core)?;
    if health != CoreHealth::Healthy || prior.is_some_and(|r| r.phase != active::Phase::Completed) {
        return Ok((health, false));
    }
    network_drift_healthy(&view, completed_direct).map(|drift| (health, drift))
}
fn network_drift_healthy(j: &Journal, completed_direct: bool) -> Result<bool, Code> {
    if xkeenwrt_recovery::active::active_manifest(j).is_none() {
        return Ok(false);
    }
    use rollback::ActiveNftState;
    let nft = recovery(rollback::active_nft_state(j))?;
    let routes = recovery(rollback::active_routing_state(j))?;
    // A completed safe fallback is stable while a fresh inventory still
    // refuses capture. Missing/partial/foreign ownership cannot enter this
    // fast path. A compatible reload makes verify_restore succeed and the
    // ordinary restore path runs again.
    if nft == ActiveNftState::Missing && routes == (false, false) && completed_direct {
        return match verify_observed_topology(j, nft, routes, Some((false, false))) {
            Err(Code::Drift) => Ok(false),
            Err(code) => Err(code),
            Ok(()) => Ok(true),
        };
    }
    if nft != ActiveNftState::Current || routes != (true, true) {
        return Ok(true);
    }
    verify_observed_topology(j, nft, routes, Some((true, true))).map_or_else(
        |code| {
            if code == Code::Drift {
                Ok(true)
            } else {
                Err(code)
            }
        },
        |_| Ok(false),
    )
}
pub struct Native<'a> {
    pub boot: &'a str,
}
fn recovery<T>(v: io::Result<T>) -> Result<T, Code> {
    v.map_err(|_| Code::Recovery)
}
impl Adapter for Native<'_> {
    fn restore_admissible(&mut self, j: &Journal) -> Result<bool, Code> {
        match verify_restore(j, None) {
            Ok(()) => Ok(true),
            Err(Code::Drift) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn same_boot(&mut self, j: &Journal) -> Result<bool, Code> {
        Ok(j.boot_id == self.boot)
    }
    fn observe_core(&mut self, j: &Journal) -> Result<CoreHealth, Code> {
        let view = active_view(j)?;
        crate::health::observe(&view.current_core)
    }
    fn secure_nft(&mut self, j: &Journal, a: Action) -> Result<(), Code> {
        let view = active_view(j)?;
        match a {
            Action::Direct | Action::Disable => recovery(rollback::active_remove_nft(&view)),
            Action::Block => recovery(rollback::active_block_nft(&view)),
            Action::Restore => verify_restore(j, None),
        }
    }
    fn reconcile_routes(&mut self, j: &Journal, a: Action) -> Result<(), Code> {
        let view = active_view(j)?;
        match a {
            Action::Direct | Action::Block | Action::Disable => {
                recovery(rollback::active_remove_routes(&view))
            }
            Action::Restore => {
                // On replay the route phase may already have completed.
                verify_restore(j, None)?;
                recovery(rollback::active_restore_route(&view))?;
                verify_restore(j, None)?;
                recovery(rollback::active_restore_rule(&view))
            }
        }
    }
    fn finish_interception(&mut self, j: &Journal, action: Action) -> Result<(), Code> {
        if action != Action::Restore {
            return Err(Code::Invalid);
        }
        verify_restore(j, Some((true, true)))?;
        recovery(rollback::active_restore_nft(&active_view(j)?))
    }
    fn restore_baseline(&mut self, j: &Journal) -> Result<(), Code> {
        recovery(core::restore(&j.baseline_core))
    }
    fn verify_final(&mut self, j: &Journal, a: Action) -> Result<(), Code> {
        use rollback::ActiveNftState::*;
        let view = active_view(j)?;
        match a {
            Action::Direct => recovery(rollback::active_verify(&view, Missing, false)),
            // Baseline contents and instance identity must be revalidated even
            // when resuming after a crash, before issuing a durable receipt.
            Action::Disable => {
                recovery(rollback::active_verify(&view, Missing, false))?;
                let matches = if j.baseline_core.running {
                    crate::health::observe(&j.baseline_core)? == CoreHealth::Healthy
                } else {
                    crate::health::stopped(&j.baseline_core)?
                };
                if matches { Ok(()) } else { Err(Code::Health) }
            }
            Action::Block => recovery(rollback::active_verify(&view, Failblock, false)),
            Action::Restore => {
                verify_restore(j, Some((true, true)))?;
                recovery(rollback::active_verify(&view, Current, true))
            }
        }
    }
    fn mark_disabled(&mut self, j: &mut Journal) -> Result<(), Code> {
        j.finish_disable();
        recovery(write_journal(Path::new("/etc/xkeenwrt"), j))
    }
    fn persist(&mut self, r: &ActiveRecord) -> Result<(), Code> {
        persist_record(r).map_err(|_| Code::Storage)
    }
}

#[cfg(test)]
pub(crate) mod history_tests {
    use super::*;
    use xkeenwrt_recovery::{CoreSnapshot, FailurePolicy, Manifest, Operation, active::Outcome};

    fn id(seed: u64) -> String {
        format!("00000000-0000-4000-8000-{seed:012x}")
    }

    pub(crate) fn journal() -> Journal {
        Journal {
            version: 1,
            operation: Operation::Apply,
            tx_id: id(1),
            plan_id: id(2),
            candidate_id: "candidate".into(),
            profile_id: "profile".into(),
            revision: id(9),
            idempotency_key: "synthetic-key".into(),
            confirm_token_sha256: "b".repeat(64),
            applied: true,
            generation: 2,
            runtime_pid: 123,
            runtime_starttime: 456,
            runtime_nonce: id(3),
            boot_id: id(4),
            created_boottime_ms: 1_000,
            deadline_boottime_ms: 121_000,
            state: State::Confirmed,
            completion: None,
            network_evidence: None,
            previous_network_evidence: None,
            current: Manifest {
                failure_policy: FailurePolicy::DirectOnFailure,
                owner_id: id(5),
                generation: 2,
                nft_semantic_sha256: "c".repeat(64),
                lan_interface: "br-test".into(),
                lan_address: "192.0.2.1".parse().unwrap(),
                lan_scope: None,
                capture_version: None,
                selected_mac: "02:00:00:00:00:02".into(),
                management_macs: vec!["02:00:00:00:00:03".into()],
                source_ipv4: "192.0.2.2".parse().unwrap(),
                management_ipv4: "192.0.2.3".parse().unwrap(),
                management_ipv6: vec!["2001:db8::3".parse().unwrap()],
                local_ipv4: vec!["192.0.2.0/24".into()],
                selected_ipv6: vec!["2001:db8::2/128".into()],
                local_ipv6: vec!["2001:db8::/64".into()],
                route_table: 100,
                mark: 0x100,
                mask: 0x100,
                priority: 10_000,
            },
            previous_good: None,
            failblock_semantic_sha256: None,
            active_failblock_semantic_sha256: None,
            current_core: CoreSnapshot {
                snapshot_id: id(6),
                overlay: profile_policy::ManagedOverlay::Network(profile_policy::NetworkOverlay {
                    lan_ifname: "br-test".into(),
                    lan_ipv4: "192.0.2.1".parse().unwrap(),
                    selected_ipv4: "192.0.2.2".parse().unwrap(),
                    tproxy_port: 7893,
                    dns_port: 1053,
                    nameservers: vec!["127.0.0.1".parse().unwrap()],
                    bootstrap: vec!["1.1.1.1".parse().unwrap()],
                    local_zones: vec!["+.lan".into()],
                }),
                sha256: "d".repeat(64),
                running: false,
                controller_port: 9090,
                controller_secret_sha256: "e".repeat(64),
                assets: vec![],
            },
            previous_core: CoreSnapshot {
                snapshot_id: id(7),
                overlay: profile_policy::ManagedOverlay::Manual,
                sha256: "f".repeat(64),
                running: false,
                controller_port: 9090,
                controller_secret_sha256: "1".repeat(64),
                assets: vec![],
            },
            next_baseline_core: None,
            profile_acceptance: None,
            cancel_capture: false,
            baseline_core: CoreSnapshot {
                snapshot_id: id(8),
                overlay: profile_policy::ManagedOverlay::Manual,
                sha256: "2".repeat(64),
                running: false,
                controller_port: 9090,
                controller_secret_sha256: "3".repeat(64),
                assets: vec![],
            },
        }
    }

    #[test]
    fn active_archive_writer_prunes_at_128_before_rejecting_append() {
        use std::os::unix::fs::PermissionsExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "xkeen-active-writer-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = journal();
        write_journal(&root, &journal).unwrap();

        for index in 0..130 {
            let mut record =
                ActiveRecord::new(&journal, &id(100 + index), ActionKind::CoreFailed, None)
                    .unwrap();
            record.phase = active::Phase::Completed;
            record.action = Some(active::Action::Direct);
            record.outcome = Some(Outcome::Direct);
            archive_completed_at(&root, &journal, &record).unwrap();
        }

        let history = root.join("active-event-history");
        assert_eq!(fs::read_dir(&history).unwrap().count(), 128);
        assert!(!history.join(format!("{}.json", id(100))).exists());
        assert!(!history.join(format!("{}.json", id(101))).exists());
        assert!(history.join(format!("{}.json", id(229))).exists());
        fs::remove_dir_all(root).unwrap();
    }

    use xkeenwrt_recovery::active::Kind as ActionKind;

    #[test]
    fn restored_generation_uses_its_own_failblock_comment_and_digest() {
        let mut j = journal();
        let mut previous = j.current.clone();
        previous.generation = 1;
        previous.failure_policy = FailurePolicy::BlockSelectedOnFailure;
        previous.route_table = 101;
        previous.priority = 10001;
        previous.mark = 0x200;
        previous.mask = 0x200;
        j.previous_core = j.current_core.clone();
        j.previous_good = Some(previous.clone());
        let transition =
            serde_json::to_vec(&previous.expected_failblock_ast(&j.current).unwrap()).unwrap();
        let active =
            serde_json::to_vec(&previous.expected_failblock_ast(&previous).unwrap()).unwrap();
        let active_digest = xkeenwrt_recovery::nft_semantic_digest(&active).unwrap();
        j.failblock_semantic_sha256 =
            Some(xkeenwrt_recovery::nft_semantic_digest(&transition).unwrap());
        assert_ne!(
            j.failblock_semantic_sha256.as_deref(),
            Some(active_digest.as_str())
        );
        j.finish_rollback(&j.boot_id.clone());
        let view = active_view(&j).unwrap();
        assert_eq!(view.current.generation, 1);
        assert_eq!(
            view.active_failblock_semantic_sha256.as_deref(),
            Some(active_digest.as_str())
        );
    }

    #[test]
    fn boot_cleanup_archives_bound_events_before_disabling_and_replays() {
        use std::os::unix::fs::PermissionsExt;
        for completed in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "xkeen-boot-{}-{completed}",
                core::fresh_nonce().unwrap()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let mut journal = journal();
            write_journal(&root, &journal).unwrap();
            let mut record =
                ActiveRecord::new(&journal, &id(100), ActionKind::CoreFailed, None).unwrap();
            if completed {
                record.phase = active::Phase::Completed;
                record.action = Some(Action::Direct);
                record.outcome = Some(Outcome::Direct);
            }
            let path = root.join("active-reconcile.json");
            fs::write(&path, active::encode(&record).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            retire_for_boot(&root, &journal, &id(200)).unwrap();
            // Crash before the terminal journal write: old boot cleanup replays.
            retire_for_boot(&root, &journal, &id(200)).unwrap();
            journal.finish_boot_cleanup(&id(200));
            write_journal(&root, &journal).unwrap();
            let archived = load_at(&root.join(format!("active-event-history/{}.json", id(100))))
                .unwrap()
                .unwrap();
            assert!(archived.valid_binding(&journal));
            assert_eq!(
                archived.phase,
                if completed {
                    active::Phase::Completed
                } else {
                    active::Phase::Error
                }
            );
            assert!(!path.exists());
            assert!(journal.boot_cleanup_complete());
            assert!(journal.needs_runtime_resume(&id(200)));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn lifecycle_cleanup_migrates_legacy_event_and_consumes_only_bound_receipt() {
        use std::os::unix::fs::PermissionsExt;
        use xkeenwrt_recovery::{LifecycleKind, LifecycleRequest, LifecycleState};
        for kind in [LifecycleKind::Remove, LifecycleKind::Upgrade] {
            for state in [State::Confirmed, State::RolledBack, State::Disabled] {
                let root = std::env::temp_dir()
                    .join(format!("xkeen-lifecycle-{}", core::fresh_nonce().unwrap()));
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                let mut j = journal();
                let mut previous = j.current.clone();
                previous.generation = 1;
                previous.route_table = 101;
                previous.priority = 10001;
                previous.mark = 0x200;
                previous.mask = 0x200;
                j.previous_good = Some(previous);
                j.previous_core = j.current_core.clone();
                if state == State::RolledBack {
                    j.state = state;
                }
                let mut event =
                    ActiveRecord::new(&j, &id(100), ActionKind::CoreFailed, None).unwrap();
                event.phase = active::Phase::Error;
                event.failed_phase = Some(active::Phase::Intent);
                event.action = Some(Action::Direct);
                event.error_code = Some(Code::Recovery.as_str().into());
                let original_error = active::encode(&event).unwrap();
                j.state = state; // r10/r11 legacy Disabled had no completion.
                write_journal(&root, &j).unwrap();
                let mut request = LifecycleRequest {
                    version: 1,
                    owner_id: j.current.owner_id.clone(),
                    request_id: Some(id(201)),
                    kind,
                    state: LifecycleState::CleanupComplete,
                };
                for (name, bytes) in [
                    ("active-reconcile.json", original_error.clone()),
                    ("removal.json", serde_json::to_vec(&request).unwrap()),
                ] {
                    let path = root.join(name);
                    fs::write(&path, bytes).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                let finish = match kind {
                    LifecycleKind::Remove => xkeenwrt_recovery::finish_remove_after_integrity_check,
                    LifecycleKind::Upgrade => {
                        xkeenwrt_recovery::finish_upgrade_after_integrity_check
                    }
                };
                assert!(finish(&root, &request.owner_id, &id(201)).is_err());
                request.owner_id = id(999);
                assert!(complete_lifecycle_cleanup(&root, &mut j, &id(200), &request).is_err());
                request.owner_id = j.current.owner_id.clone();
                // Persist the real middle state, then replay after a helper crash.
                let generation =
                    archive_cleanup_event(&root, &j, state == State::Disabled).unwrap();
                j.finish_lifecycle_cleanup(&id(200), &request, generation)
                    .unwrap();
                write_journal(&root, &j).unwrap();
                assert!(
                    finish(&root, &request.owner_id, &id(201)).is_err(),
                    "active record still needs retirement"
                );
                j = xkeenwrt_recovery::read_journal(&root).unwrap();
                complete_lifecycle_cleanup(&root, &mut j, &id(200), &request).unwrap();
                assert!(j.lifecycle_cleanup_matches(&request));
                assert!(!j.needs_runtime_resume(&id(200)));
                assert!(!root.join("active-reconcile.json").exists());
                let archive = root.join(format!("active-event-history/{}.json", id(100)));
                assert_eq!(
                    fs::read(&archive).unwrap(),
                    original_error,
                    "original failure is preserved"
                );
                assert!(load_at(&archive).unwrap().unwrap().valid_binding(&j));
                assert!(finish(&root, &request.owner_id, &id(202)).is_err());
                finish(&root, &request.owner_id, &id(201)).unwrap();
                assert!(!root.join("removal.json").exists());
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn boot_finishes_split_disable_write_after_cleanup_proof() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "xkeen-split-disable-{}",
            core::fresh_nonce().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut j = journal();
        let mut event = ActiveRecord::new(
            &j,
            &id(100),
            ActionKind::DisableRequested,
            Some("disable".into()),
        )
        .unwrap();
        event.phase = active::Phase::Verified;
        event.action = Some(Action::Disable);
        j.finish_disable();
        write_journal(&root, &j).unwrap();
        let path = root.join("active-reconcile.json");
        fs::write(&path, active::encode(&event).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut j = xkeenwrt_recovery::read_journal(&root).unwrap();
        retire_for_boot(&root, &j, &id(200)).unwrap();
        retire_for_boot(&root, &j, &id(200)).unwrap();
        j.finish_boot_cleanup(&id(200));
        let archived = load_at(&root.join(format!("active-event-history/{}.json", id(100))))
            .unwrap()
            .unwrap();
        assert_eq!(archived.outcome, Some(Outcome::Disabled));
        assert_eq!(archived.phase, active::Phase::Completed);
        assert!(archived.valid_binding(&j));
        assert!(j.boot_cleanup_complete());
        fs::remove_dir_all(root).unwrap();
    }
}
