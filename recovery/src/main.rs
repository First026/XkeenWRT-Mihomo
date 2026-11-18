//! Independent recovery supervisor. Fixed paths and commands only.
mod active_driver;
mod active_inventory;
mod commands;
mod core;
mod fence;
mod health;
mod input_guard;
mod removal;
mod retire;
mod rollback;
mod supervisor;

use std::{fs, io, path::Path, time::Duration};
use xkeenwrt_recovery::{
    Decision, Journal, MutationLock, State, boottime_ms, read_journal, write_journal,
};
const DIR: &str = "/etc/xkeenwrt";
const LOCK: &str = "/var/run/xkeenwrt/mutation.lock";
const READY: &str = "/var/run/xkeenwrt/recovery.ready";
const IDLE: &str = "/var/run/xkeenwrt/recovery.idle";
const LIFECYCLE_READY: &str = "/var/run/xkeenwrt/recovery.lifecycle-ready";
const REMOVE_RESUME_READY: &str = "/var/run/xkeenwrt/recovery.remove-ready";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => supervise(),
        [arg] if arg == "supervise" => supervise(),
        [arg] if arg == "--prepare-remove" => {
            prepare_lifecycle(xkeenwrt_recovery::LifecycleKind::Remove)
        }
        [arg] if arg == "--prepare-upgrade" => {
            prepare_lifecycle(xkeenwrt_recovery::LifecycleKind::Upgrade)
        }
        [arg] if arg == "--remove-status" => remove_status(),
        [arg, request_id] if arg == "--finalize-remove" => finalize_remove(request_id),
        [arg, request_id] if arg == "--archive-finalized-remove" => retire::run(request_id),
        _ => Err(io::Error::other("unsupported recovery operation")),
    };
    if let Err(e) = result {
        let operation = args.first().map_or("supervise", String::as_str);
        eprintln!("recovery stopped: operation={operation}: {e}");
        std::process::exit(1);
    }
}
const NOTICE: &str = "/var/run/xkeenwrt/recovery-notice.json";
/// Log and publish (best effort, volatile) why recovery ended Direct. The
/// journal format is unchanged so an installed r25 rescue can still read it.
fn report_snapshot_missing(operation: &str, tx_id: &str, snapshot_id: &str) {
    eprintln!(
        "recovery direct: SNAPSHOT_MISSING operation={operation} tx={tx_id} snapshot={snapshot_id}"
    );
    let notice = serde_json::json!({
        "version": 1,
        "code": "SNAPSHOT_MISSING",
        "operation": operation,
        "tx_id": tx_id,
        "snapshot_id": snapshot_id,
    });
    let _ = write_marker(NOTICE, &notice);
}
/// Close the journal for a finished rollback. A missing snapshot ends Direct
/// like any terminal fallback; the runtime is then resumed as usual.
fn finish_restore(journal: &mut Journal, outcome: rollback::RestoreOutcome, boot: &str) {
    match outcome {
        rollback::RestoreOutcome::Previous => journal.finish_rollback(boot),
        rollback::RestoreOutcome::Direct => journal.finish_rollback_direct(boot),
        rollback::RestoreOutcome::SnapshotMissing { snapshot_id } => {
            report_snapshot_missing("rollback", &journal.tx_id, &snapshot_id);
            journal.finish_rollback_direct(boot);
        }
    }
}
fn lock_contention_should_stop(
    state: State,
    decision: &Decision,
    fence_present: bool,
    remove_requested: bool,
) -> bool {
    decision == &Decision::Revoke
        || (matches!(state, State::Pending | State::Confirmed) && fence_present)
        || remove_requested
}
fn prepare_lifecycle(kind: xkeenwrt_recovery::LifecycleKind) -> io::Result<()> {
    persistent_guard()?;
    let _ = xkeenwrt_recovery::rescue::verify_self()?;
    let owner = read_owner()?;
    let _ = removal::ensure_requested(&owner, kind)?;
    let until = std::time::Instant::now() + Duration::from_secs(10);
    let _ = start_rescue_if_possible(&owner);
    loop {
        if removal::load()?.is_some_and(|r| {
            r.owner_id == owner
                && r.kind == kind
                && r.state == removal::RemovalState::CleanupComplete
        }) {
            return Ok(());
        }
        if std::time::Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "removal cleanup pending",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn ensure_volatile_state() -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let parent = fs::metadata("/var/run")?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe volatile parent"));
    }
    match fs::DirBuilder::new()
        .mode(0o700)
        .create("/var/run/xkeenwrt")
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    validate_directory(Path::new("/var/run/xkeenwrt"))?;
    for path in [
        "/var/run/xkeenwrt/mutation.lock",
        "/var/run/xkeenwrt/recovery.lock",
    ] {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        validate_private_file(Path::new(path))?;
    }
    fs::File::open("/var/run/xkeenwrt")?.sync_all()
}
fn start_rescue_if_possible(owner: &str) -> io::Result<()> {
    xkeenwrt_recovery::rescue::verify_init_template()?;
    ensure_volatile_state()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    // If another supervisor is alive it will observe the durable request; a
    // failed start is not a cleanup receipt and the request remains persistent.
    let (lock, group, _identity) = match supervisor::acquire(owner, &boot) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    commands::set_cgroup(group.try_clone()?)?;
    let result = commands::start_rescue();
    supervisor::ensure_quiescent(&group)?;
    supervisor::retire_current()?;
    drop(lock);
    result
}
fn remove_status() -> io::Result<()> {
    persistent_guard()?;
    let _ = xkeenwrt_recovery::rescue::verify_self()?;
    match removal::load()? {
        Some(status) => {
            if status.owner_id != read_owner()? {
                return Err(io::Error::other("removal owner mismatch"));
            }
            println!(
                "{}",
                serde_json::to_string(&status).map_err(io::Error::other)?
            );
        }
        None => println!("{{\"state\":\"not_requested\"}}"),
    }
    Ok(())
}
fn finalize_remove(request_id: &str) -> io::Result<()> {
    persistent_guard()?;
    let _ = xkeenwrt_recovery::rescue::verify_self()?;
    ensure_volatile_state()?;
    let owner = read_owner()?;
    let _ = xkeenwrt_recovery::supervisor_cgroup_path(&owner, request_id)
        .map_err(|_| io::Error::other("invalid Remove request id"))?;
    let request = removal::load()?.ok_or_else(|| io::Error::other("missing Remove receipt"))?;
    if request.owner_id != owner
        || request.kind != xkeenwrt_recovery::LifecycleKind::Remove
        || request.state != removal::RemovalState::CleanupComplete
        || request.request_id.as_deref() != Some(request_id)
    {
        return Err(io::Error::other("Remove receipt mismatch"));
    }
    xkeenwrt_recovery::verify_remove_after_integrity_check(Path::new(DIR), &owner, request_id)?;

    // This one-shot command group owns only the fixed ubus service deletion
    // needed to retire the live rescue before its persistent executable is
    // removed. The operation is separate from ordinary package Remove.
    let command_group = supervisor::command_group(&owner)?;
    commands::set_cgroup(command_group.try_clone()?)?;
    commands::stop_rescue()?;
    commands::stop_package_recovery()?;
    let until = std::time::Instant::now() + Duration::from_secs(3);
    while !commands::rescue_is_stopped()? || !commands::package_recovery_is_stopped()? {
        if std::time::Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "recovery service did not stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !commands::runtime_is_stopped()?
        || !commands::core_is_stopped()?
        || !commands::ui_is_stopped()?
    {
        return Err(io::Error::other("project service still running"));
    }

    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let (supervisor_lock, recovery_group, _) = supervisor::acquire(&owner, &boot)?;
    commands::set_cgroup(recovery_group.try_clone()?)?;
    let result = (|| {
        let _mutation = MutationLock::acquire(Path::new(LOCK), Duration::from_secs(3))?;
        if !commands::runtime_is_stopped()?
            || !commands::core_is_stopped()?
            || !commands::ui_is_stopped()?
            || !commands::rescue_is_stopped()?
            || !commands::package_recovery_is_stopped()?
        {
            return Err(io::Error::other("project service state changed"));
        }
        let request = removal::load()?.ok_or_else(|| io::Error::other("missing Remove receipt"))?;
        if request.owner_id != owner
            || request.kind != xkeenwrt_recovery::LifecycleKind::Remove
            || request.state != removal::RemovalState::CleanupComplete
            || request.request_id.as_deref() != Some(request_id)
        {
            return Err(io::Error::other("Remove receipt changed"));
        }
        xkeenwrt_recovery::verify_remove_after_integrity_check(Path::new(DIR), &owner, request_id)?;
        if !rollback::no_project_table()? {
            return Err(io::Error::other("project network table remains"));
        }
        xkeenwrt_recovery::rescue::finalize_remove_assets(&owner, request_id)
    })();
    let retired = supervisor::retire_current();
    drop(supervisor_lock);
    result?;
    retired
}
fn supervise() -> io::Result<()> {
    persistent_guard()?;
    let _ = xkeenwrt_recovery::rescue::verify_self()?;
    ensure_volatile_state()?;
    deployment_guard()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if boot.is_empty() {
        return Err(io::Error::other("missing boot id"));
    }
    let owner = read_owner()?;
    let (_supervisor_lock, recovery_group, supervisor_id) = supervisor::acquire(&owner, &boot)?;
    commands::set_cgroup(recovery_group)?;
    remove_marker(READY)?;
    remove_marker(IDLE)?;
    remove_marker(LIFECYCLE_READY)?;
    remove_marker(REMOVE_RESUME_READY)?;
    let mut lifecycle_ready: Option<String> = None;
    let mut remove_resume_ready: Option<String> = None;
    let mut last_input_guard: Option<std::time::Instant> = None;
    let mut last_health: Option<std::time::Instant> = None;
    let mut startup = true;
    let mut idle_published = false;
    let mut ready_key: Option<(String, u64, String)> = None;
    let mut lock_blocked_since: Option<std::time::Instant> = None;
    loop {
        let lock = match MutationLock::acquire(Path::new(LOCK), Duration::from_millis(100)) {
            Ok(lock) => {
                lock_blocked_since = None;
                lock
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                let first = lock_blocked_since.get_or_insert_with(std::time::Instant::now);
                if first.elapsed() >= Duration::from_secs(3) {
                    let lifecycle = removal::load()?;
                    if let Some(request) = lifecycle
                        .as_ref()
                        .filter(|r| r.state == removal::RemovalState::Requested)
                    {
                        if request.owner_id != read_owner()? {
                            return Err(io::Error::other("removal owner mismatch"));
                        }
                        stop_current_incarnation(&boot)?;
                    } else if let Ok(j) = read_journal(Path::new(DIR)) {
                        validate_private_file(Path::new(DIR).join("recovery.json").as_path())?;
                        validate_owner(&j)?;
                        let decision = j.decision(&boot, boottime_ms()?, startup);
                        if decision == Decision::Invalid {
                            return Err(io::Error::other("invalid recovery journal"));
                        }
                        let remove_requested = removal::load()?.is_some_and(|r| {
                            r.state == removal::RemovalState::Requested
                                && r.owner_id == j.current.owner_id
                        });
                        let fenced_active_transaction =
                            matches!(j.state, State::Pending | State::Confirmed)
                                && decision != Decision::Revoke
                                && !remove_requested
                                && fence::present(&j)?;
                        if lock_contention_should_stop(
                            j.state,
                            &decision,
                            fenced_active_transaction,
                            remove_requested,
                        ) {
                            fence::publish(&j)?;
                            let _ = core::publish_launch(&j.previous_core, false)?;
                            stop_runtime_confirm(&j, &boot)?;
                            fence::quiesce(&j, &boot)?;
                            core::stop_confirm()?;
                        }
                    }
                    lock_blocked_since = None;
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        };
        validate_directory(Path::new(DIR))?;
        let removal = removal::load()?;
        if let Some(ref request) = removal
            && request.owner_id != read_owner()?
        {
            return Err(io::Error::other("removal owner mismatch"));
        }
        if removal
            .as_ref()
            .is_some_and(|r| r.state == removal::RemovalState::CleanupComplete)
        {
            remove_marker(READY)?;
            remove_marker(IDLE)?;
            ready_key = None;
            idle_published = false;
            let request = removal
                .as_ref()
                .ok_or_else(|| io::Error::other("missing lifecycle request"))?;
            // Old helpers wrote Disabled without a terminal network receipt.
            // Migrate only while the exact completed lifecycle is still present,
            // before publishing readiness or allowing its receipt to be consumed.
            match read_journal(Path::new(DIR)) {
                Ok(mut j) => {
                    validate_private_file(&Path::new(DIR).join("recovery.json"))?;
                    validate_owner(&j)?;
                    if j.state != State::Disabled
                        || j.decision(&boot, boottime_ms()?, false) == Decision::Invalid
                    {
                        return Err(io::Error::other(
                            "invalid completed lifecycle network journal",
                        ));
                    }
                    if !j.lifecycle_cleanup_matches(request) || active_driver::load()?.is_some() {
                        core::stop_confirm()?;
                        rollback::verify_removed(&j)?;
                        active_driver::complete_lifecycle_cleanup(
                            Path::new(DIR),
                            &mut j,
                            &boot,
                            request,
                        )?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
            if request.kind == xkeenwrt_recovery::LifecycleKind::Upgrade {
                remove_marker(REMOVE_RESUME_READY)?;
                remove_resume_ready = None;
                let request_id = request
                    .request_id
                    .as_deref()
                    .ok_or_else(|| io::Error::other("missing upgrade request identity"))?;
                if lifecycle_ready.as_deref() != Some(request_id) {
                    write_marker(
                        LIFECYCLE_READY,
                        &serde_json::json!({
                            "version": 1, "request_id": request_id, "supervisor": supervisor_id,
                        }),
                    )?;
                    lifecycle_ready = Some(request_id.to_owned());
                }
            } else {
                if lifecycle_ready.take().is_some() {
                    remove_marker(LIFECYCLE_READY)?;
                }
                let request_id = request
                    .request_id
                    .as_deref()
                    .ok_or_else(|| io::Error::other("missing Remove request identity"))?;
                if remove_resume_ready.as_deref() != Some(request_id) {
                    let ready = xkeenwrt_recovery::RemoveResumeReady {
                        version: 1,
                        request_id: request_id.to_owned(),
                        supervisor: supervisor_id.clone(),
                    };
                    write_marker(
                        REMOVE_RESUME_READY,
                        &serde_json::to_value(ready).map_err(io::Error::other)?,
                    )?;
                    remove_resume_ready = Some(request_id.to_owned());
                }
            }
            drop(lock);
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        if remove_resume_ready.take().is_some() {
            remove_marker(REMOVE_RESUME_READY)?;
        }
        // Finalizing survives receipt consumption. Preserve a request-bound
        // readiness marker until the durable replacement fence is cleared.
        if removal.is_none()
            && let Some(intent) = xkeenwrt_recovery::rescue::upgrade_status_for_supervisor()?
        {
            let request_id = finalizing_request(&intent, &supervisor_id)?;
            if lifecycle_ready.as_deref() != Some(request_id) {
                write_marker(
                    LIFECYCLE_READY,
                    &serde_json::json!({
                        "version": 1, "request_id": request_id,
                        "supervisor": supervisor_id,
                    }),
                )?;
                lifecycle_ready = Some(request_id.to_owned());
            }
            drop(lock);
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        if lifecycle_ready.take().is_some() {
            remove_marker(LIFECYCLE_READY)?;
        }
        if last_input_guard.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            last_input_guard = Some(std::time::Instant::now());
            // A transient observation error never disables the recovery loop.
            let _ = input_guard::monitor();
        }
        let mut journal = match read_journal(Path::new(DIR)) {
            Ok(j) => j,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if let Some(mut request) = removal {
                    cleanup_never_enabled(&request.owner_id)?;
                    request.state = removal::RemovalState::CleanupComplete;
                    removal::store(&request)?;
                    drop(lock);
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                if ready_key.is_some() {
                    remove_marker(READY)?;
                    return Err(io::Error::other("pending journal disappeared"));
                }
                if !idle_published {
                    publish_idle(&supervisor_id)?;
                    idle_published = true;
                }
                startup = false;
                drop(lock);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        };
        validate_private_file(Path::new(DIR).join("recovery.json").as_path())?;
        validate_owner(&journal)?;
        if let Some(mut request) = removal {
            if request.owner_id != journal.current.owner_id {
                return Err(io::Error::other("removal owner mismatch"));
            }
            let valid = journal.decision(&boot, boottime_ms()?, startup);
            if valid == Decision::Invalid {
                return Err(io::Error::other("invalid recovery journal"));
            }
            remove_marker(READY)?;
            remove_marker(IDLE)?;
            ready_key = None;
            idle_published = false;
            fence::publish(&journal)?;
            stop_current_incarnation(&boot)?;
            fence::quiesce(&journal, &boot)?;
            rollback::remove_for_uninstall(&journal)?;
            rollback::verify_removed(&journal)?;
            xkeenwrt_recovery::input_state::settle_stopped()?;
            stop_ui_confirm()?;
            active_driver::complete_lifecycle_cleanup(
                Path::new(DIR),
                &mut journal,
                &boot,
                &request,
            )?;
            request.state = removal::RemovalState::CleanupComplete;
            removal::store(&request)?;
            drop(lock);
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let validated = journal.decision(&boot, boottime_ms()?, startup);
        if validated == Decision::Invalid {
            return Err(io::Error::other("invalid recovery journal"));
        }
        if journal.needs_boot_cleanup(&boot) {
            remove_marker(READY)?;
            remove_marker(IDLE)?;
            ready_key = None;
            idle_published = false;
            stop_current_incarnation(&boot)?;
            fence::quiesce(&journal, &boot)?;
            rollback::remove_for_uninstall(&journal)?;
            rollback::verify_removed(&journal)?;
            xkeenwrt_recovery::input_state::settle_stopped()?;
            let mut baseline = journal.baseline_core.clone();
            baseline.running = false;
            if let Some(snapshot_id) = core::restore_or_stop(&baseline)? {
                report_snapshot_missing("boot-cleanup", &journal.tx_id, &snapshot_id);
            }
            active_driver::retire_for_boot(Path::new(DIR), &journal, &boot)?;
            journal.finish_boot_cleanup(&boot);
            write_journal(Path::new(DIR), &journal)?;
            drop(lock);
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let fenced = fence::present(&journal)?;
        let decision = if fenced && matches!(journal.state, State::Pending | State::Confirmed) {
            Decision::Revoke
        } else {
            validated
        };
        match decision {
            Decision::Invalid => return Err(io::Error::other("invalid recovery journal")),
            Decision::Settled => {
                let has_active_network = journal.state == State::Confirmed
                    || (journal.state == State::RolledBack && journal.previous_good.is_some());
                if has_active_network || journal.state == State::Disabled {
                    if has_active_network
                        && last_health.is_none_or(|t| t.elapsed() >= Duration::from_secs(5))
                    {
                        last_health = Some(std::time::Instant::now());
                        let prior = active_driver::load()?;
                        let can_replace = prior.as_ref().is_none_or(|event| {
                            xkeenwrt_recovery::active::may_replace_for_health_event(event, &journal)
                        });
                        let event_kind = if can_replace {
                            match active_driver::observe_active(&journal, prior.as_ref()) {
                                Ok((xkeenwrt_recovery::active::CoreHealth::Failed, _))
                                    if xkeenwrt_recovery::active::may_start_core_failed(
                                        prior.as_ref(),
                                        &journal,
                                    ) =>
                                {
                                    Some(xkeenwrt_recovery::active::Kind::CoreFailed)
                                }
                                Ok((xkeenwrt_recovery::active::CoreHealth::Healthy, true)) => {
                                    Some(xkeenwrt_recovery::active::Kind::ReconcileRequested)
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        if let Some(kind) = event_kind {
                            if let Some(event) = prior.as_ref() {
                                active_driver::archive_completed(&journal, event)?;
                            }
                            let mut event = xkeenwrt_recovery::active::ActiveRecord::new(
                                &journal,
                                &core::fresh_nonce()?,
                                kind,
                                None,
                            )
                            .map_err(|_| io::Error::other("invalid health event"))?;
                            event.retry_of =
                                prior.as_ref().map(|previous| previous.event_id.clone());
                            if !event.valid_for(&journal) {
                                return Err(io::Error::other("invalid health event lineage"));
                            }
                            active_driver::persist_record(&event)?;
                        }
                    }
                    if let Some(mut event) = active_driver::load()? {
                        if !event.valid_for(&journal) {
                            return Err(io::Error::other("active record does not match journal"));
                        }
                        let mut adapter = active_driver::Native { boot: &boot };
                        let _ = xkeenwrt_recovery::active::process(
                            &mut journal,
                            &mut event,
                            &mut adapter,
                        );
                    }
                }
                remove_marker(READY)?;
                ready_key = None;
                if !idle_published {
                    publish_idle(&supervisor_id)?;
                    idle_published = true;
                }
            }
            Decision::Wait => {
                remove_marker(IDLE)?;
                idle_published = false;
                let key = (
                    journal.tx_id.clone(),
                    journal.generation,
                    journal_fingerprint(&journal)?,
                );
                if let Some(existing) = ready_key.as_ref() {
                    if existing != &key {
                        remove_marker(READY)?;
                        return Err(io::Error::other("pending transaction changed"));
                    }
                } else if publish_ready(&journal, &supervisor_id)? {
                    ready_key = Some(key);
                }
            }
            Decision::Revoke => {
                remove_marker(READY)?;
                ready_key = None;
                remove_marker(IDLE)?;
                idle_published = false;
                fence::publish(&journal)?;
                let _ = core::publish_launch(&journal.previous_core, false)?;
                stop_runtime_confirm(&journal, &boot)?;
                fence::quiesce(&journal, &boot)?;
                core::stop_confirm()?;
                if matches!(journal.state, State::Pending | State::Confirmed) {
                    let generation = journal.generation;
                    if !journal.revoke_fenced(generation) {
                        return Err(io::Error::other("generation changed"));
                    }
                    write_journal(Path::new(DIR), &journal)?;
                }
                let outcome = rollback::restore(&journal)?;
                finish_restore(&mut journal, outcome, &boot);
                write_journal(Path::new(DIR), &journal)?;
            }
        }
        // Runtime restoration must not pause health/failure handling for the
        // previous-good network, even if the runtime package is unavailable.
        let mut resume_runtime = journal.needs_runtime_resume(&boot);
        if resume_runtime && runtime_returned(&journal, &boot)? {
            journal
                .completion
                .as_mut()
                .expect("validated completion")
                .runtime_resumed = true;
            write_journal(Path::new(DIR), &journal)?;
            resume_runtime = false;
        }
        startup = false;
        drop(lock);
        // Start only after durable cleanup and lock release. Repeating the fixed
        // command cannot extend a network deadline or enable interception.
        if resume_runtime
            && commands::runtime_is_stopped()?
            && removal::load()?.is_none()
            && xkeenwrt_recovery::rescue::upgrade_status_for_supervisor()?.is_none()
        {
            let _ = commands::start_runtime();
        }
        std::thread::sleep(Duration::from_millis(if resume_runtime {
            1000
        } else {
            100
        }));
    }
}
fn runtime_returned(j: &Journal, boot: &str) -> io::Result<bool> {
    let Some(pid) = commands::runtime_pid()? else {
        return Ok(false);
    };
    let Some(identity) = read_runtime_incarnation()? else {
        return Ok(false);
    };
    Ok(identity.boot_id == boot
        && identity.pid == pid
        && identity != j.runtime_identity()
        && process_identity(pid)?
            .is_some_and(|(state, start)| state != "Z" && start == identity.starttime)
        && old_runtime_gone(j, boot)?)
}
fn process_identity(pid: u32) -> io::Result<Option<(String, u64)>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let (_, rest) = text
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other("invalid process stat"))?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    let state = fields
        .first()
        .ok_or_else(|| io::Error::other("missing process state"))?
        .to_string();
    let start = fields
        .get(19)
        .ok_or_else(|| io::Error::other("missing process starttime"))?
        .parse()
        .map_err(io::Error::other)?;
    Ok(Some((state, start)))
}
fn old_runtime_gone(j: &Journal, boot: &str) -> io::Result<bool> {
    if boot != j.boot_id {
        return Ok(true);
    }
    Ok(process_identity(j.runtime_pid)?
        .is_none_or(|(state, start)| start != j.runtime_starttime || state == "Z"))
}
fn read_runtime_incarnation() -> io::Result<Option<xkeenwrt_recovery::RuntimeIncarnationIdentity>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let path = Path::new("/var/run/xkeenwrt/incarnation.json");
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    validate_private_file(path)?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("incarnation too large"));
    }
    let identity: xkeenwrt_recovery::RuntimeIncarnationIdentity =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let _ = xkeenwrt_recovery::runtime_incarnation_path(&identity)?;
    Ok(Some(identity))
}
fn stop_current_incarnation(boot: &str) -> io::Result<()> {
    let identity = read_runtime_incarnation()?;
    let live_pid = commands::runtime_pid()?;
    if let Some(pid) = live_pid
        && identity
            .as_ref()
            .is_none_or(|id| id.boot_id != boot || id.pid != pid)
    {
        return Err(io::Error::other("unidentified runtime process"));
    }
    core::revoke_existing_launch()?;
    commands::stop_runtime()?;
    if let Some(id) = &identity {
        kill_exact_runtime(id, boot)?;
    }
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let gone = match &identity {
            Some(id) if id.boot_id == boot => process_identity(id.pid)?
                .is_none_or(|(state, start)| state == "Z" || start != id.starttime),
            _ => true,
        };
        if commands::runtime_is_stopped()? && gone {
            break;
        }
        if std::time::Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime did not stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Some(id) = identity {
        fence::quiesce_identity(&id, boot)?;
    }
    core::stop_confirm()
}
fn cleanup_never_enabled(owner: &str) -> io::Result<()> {
    let marker = Path::new("/etc/xkeenwrt/network-never-enabled");
    validate_private_file(marker)?;
    if fs::read_to_string(marker)? != "xkeenwrt-no-network-v1\n" {
        return Err(io::Error::other("unknown network history"));
    }
    let _ = owner;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    stop_current_incarnation(&boot)?;
    if !rollback::no_project_table()? {
        return Err(io::Error::other("unexpected network table"));
    }
    core::revoke_existing_launch()?;
    core::stop_confirm()?;
    xkeenwrt_recovery::input_state::settle_stopped()?;
    stop_ui_confirm()?;
    Ok(())
}

fn kill_exact_pid(pid: u32, expected_start: u64) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let Some((state, start)) = process_identity(pid)? else {
        return Ok(());
    };
    if state == "Z" || start != expected_start {
        return Ok(());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(e);
    }
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
    let Some((state, start)) = process_identity(pid)? else {
        return Ok(());
    };
    if state == "Z" || start != expected_start {
        return Ok(());
    }
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e);
        }
    }
    Ok(())
}
fn kill_exact_runtime(
    identity: &xkeenwrt_recovery::RuntimeIncarnationIdentity,
    boot: &str,
) -> io::Result<()> {
    if identity.boot_id != boot {
        return Ok(());
    }
    kill_exact_pid(identity.pid, identity.starttime)
}
fn stop_ui_confirm() -> io::Result<()> {
    let original = match commands::ui_pid()? {
        Some(pid) => process_identity(pid)?.map(|(_, start)| (pid, start)),
        None => None,
    };
    commands::stop_ui()?;
    if let Some((pid, start)) = original {
        kill_exact_pid(pid, start)?;
    }
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let gone = match original {
            Some((pid, start)) => process_identity(pid)?
                .is_none_or(|(state, current)| state == "Z" || current != start),
            None => true,
        };
        if commands::ui_is_stopped()? && gone {
            return Ok(());
        }
        if std::time::Instant::now() >= until {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "UI did not stop"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn stop_runtime_confirm(j: &Journal, boot: &str) -> io::Result<()> {
    commands::stop_runtime()?;
    kill_exact_runtime(&j.runtime_identity(), boot)?;
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if commands::runtime_is_stopped()? && old_runtime_gone(j, boot)? {
            return Ok(());
        }
        if std::time::Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime did not stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn journal_fingerprint(journal: &Journal) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut immutable = journal.clone();
    immutable.applied = false;
    let bytes = serde_json::to_vec(&immutable).map_err(io::Error::other)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn remove_marker(path: &str) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
fn persistent_guard() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("recovery requires root"));
    }
    use std::os::unix::fs::MetadataExt;
    let release_meta = fs::symlink_metadata("/etc/openwrt_release")?;
    if !release_meta.is_file() || release_meta.uid() != 0 || release_meta.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe release identity"));
    }
    let release = fs::read_to_string("/etc/openwrt_release")?;
    if !release.lines().any(|line| line == "DISTRIB_ID='OpenWrt'") {
        return Err(io::Error::other("not an OpenWrt deployment"));
    }
    validate_directory(Path::new("/etc/xkeenwrt"))?;
    for path in ["/etc/xkeenwrt/recovery-enabled", "/etc/xkeenwrt/owner-id"] {
        validate_private_file(Path::new(path))?;
    }
    if fs::read_to_string("/etc/xkeenwrt/recovery-enabled")? != "xkeenwrt-recovery-v1\n" {
        return Err(io::Error::other("recovery deployment disabled"));
    }
    Ok(())
}
fn deployment_guard() -> io::Result<()> {
    persistent_guard()?;
    validate_directory(Path::new("/var/run/xkeenwrt"))?;
    for path in [
        "/var/run/xkeenwrt/mutation.lock",
        "/var/run/xkeenwrt/recovery.lock",
    ] {
        validate_private_file(Path::new(path))?;
    }
    Ok(())
}
fn finalizing_request<'a>(
    intent: &'a xkeenwrt_recovery::rescue::UpgradeIntent,
    supervisor: &xkeenwrt_recovery::SupervisorIdentity,
) -> io::Result<&'a str> {
    if intent.version != 1
        || !intent.spec.valid()
        || !supervisor.valid()
        || intent.phase != xkeenwrt_recovery::rescue::UpgradePhase::Finalizing
        || intent.spec.owner_id != supervisor.owner_id
        || intent.spec.new_sha256 != supervisor.exe_sha256
    {
        return Err(io::Error::other("invalid replacement finalizing state"));
    }
    Ok(&intent.spec.request_id)
}
fn publish_idle(identity: &xkeenwrt_recovery::SupervisorIdentity) -> io::Result<()> {
    write_marker(
        IDLE,
        &serde_json::to_value(identity).map_err(io::Error::other)?,
    )
}
fn write_marker(path: &str, data: &serde_json::Value) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = format!("{}.{}", path, std::process::id());
    let _ = fs::remove_file(&temp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    serde_json::to_writer(&mut file, data).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    fs::File::open("/var/run/xkeenwrt")?.sync_all()
}
fn validate_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe journal directory"));
    }
    Ok(())
}
fn validate_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err(io::Error::other("unsafe journal file"));
    }
    Ok(())
}
fn read_owner() -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/etc/xkeenwrt/owner-id")?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
        return Err(io::Error::other("unsafe owner identity"));
    }
    let mut owner = String::new();
    file.by_ref().take(128).read_to_string(&mut owner)?;
    Ok(owner.trim().to_owned())
}
fn validate_owner(journal: &Journal) -> io::Result<()> {
    if read_owner()? != journal.current.owner_id {
        return Err(io::Error::other("owner identity mismatch"));
    }
    Ok(())
}

fn publish_ready(
    journal: &Journal,
    identity: &xkeenwrt_recovery::SupervisorIdentity,
) -> io::Result<bool> {
    fence::check_ready(journal)?;
    let _ = fence::ensure_core_group()?;
    core::preflight(&journal.current_core)?;
    core::preflight(&journal.previous_core)?;
    core::preflight(&journal.baseline_core)?;
    rollback::preflight(journal)?;
    if boottime_ms()? >= journal.deadline_boottime_ms {
        return Ok(false);
    }
    let mut marker = serde_json::to_value(identity).map_err(io::Error::other)?;
    let object = marker
        .as_object_mut()
        .ok_or_else(|| io::Error::other("invalid supervisor identity"))?;
    object.insert("tx_id".into(), serde_json::json!(journal.tx_id));
    object.insert("generation".into(), serde_json::json!(journal.generation));
    write_marker(READY, &marker)?;
    Ok(true)
}

#[cfg(test)]
mod replacement_readiness_tests {
    use super::*;
    #[test]
    fn finalizing_marker_is_bound_to_exact_owner_and_new_binary() {
        use xkeenwrt_recovery::rescue::{UpgradeIntent, UpgradePhase, UpgradeSpec};
        let owner = "00000000-0000-4000-8000-000000000001";
        let request = "00000000-0000-4000-8000-000000000002";
        let mut intent = UpgradeIntent {
            version: 1,
            phase: UpgradePhase::Finalizing,
            spec: UpgradeSpec {
                owner_id: owner.into(),
                request_id: request.into(),
                old_sha256: "a".repeat(64),
                old_build_id: "b".repeat(64),
                new_sha256: "c".repeat(64),
                new_build_id: "d".repeat(64),
            },
        };
        let mut id = xkeenwrt_recovery::SupervisorIdentity {
            version: 1,
            owner_id: owner.into(),
            nonce: "00000000-0000-4000-8000-000000000003".into(),
            pid: 123,
            starttime: 4,
            boot_id: "00000000-0000-4000-8000-000000000004".into(),
            exe_sha256: "c".repeat(64),
        };
        assert_eq!(finalizing_request(&intent, &id).unwrap(), request);
        intent.phase = UpgradePhase::Exchanged;
        assert!(finalizing_request(&intent, &id).is_err());
        intent.phase = UpgradePhase::Finalizing;
        id.exe_sha256 = "a".repeat(64);
        assert!(finalizing_request(&intent, &id).is_err());
        id.exe_sha256 = "c".repeat(64);
        id.owner_id = "00000000-0000-4000-8000-000000000005".into();
        assert!(finalizing_request(&intent, &id).is_err());
    }
}

#[cfg(test)]
mod lock_contention_fence_tests {
    use super::*;

    #[test]
    fn stale_terminal_fence_cannot_stop_a_new_runtime_incarnation() {
        assert!(!lock_contention_should_stop(
            State::RolledBack,
            &Decision::Settled,
            true,
            false,
        ));
        assert!(!lock_contention_should_stop(
            State::Disabled,
            &Decision::Settled,
            true,
            false,
        ));
        assert!(lock_contention_should_stop(
            State::Pending,
            &Decision::Wait,
            true,
            false,
        ));
        assert!(lock_contention_should_stop(
            State::Confirmed,
            &Decision::Settled,
            true,
            false,
        ));
        assert!(lock_contention_should_stop(
            State::Revoked,
            &Decision::Revoke,
            false,
            false,
        ));
        assert!(lock_contention_should_stop(
            State::Disabled,
            &Decision::Settled,
            false,
            true,
        ));
    }
}

#[cfg(test)]
mod rollback_snapshot_missing_tests {
    use super::*;

    #[test]
    fn missing_rollback_snapshot_closes_direct_and_returns_runtime() {
        let boot = "00000000-0000-4000-8000-000000000099";
        let mut journal = crate::active_driver::history_tests::journal();
        journal.state = State::Revoked;
        finish_restore(
            &mut journal,
            rollback::RestoreOutcome::SnapshotMissing {
                snapshot_id: "00000000-0000-4000-8000-000000000042".into(),
            },
            boot,
        );
        assert_eq!(journal.state, State::Disabled);
        assert!(journal.rollback_direct_complete());
        assert!(journal.needs_runtime_resume(boot));
        assert!(journal.next_baseline_core.is_none());
    }
}
