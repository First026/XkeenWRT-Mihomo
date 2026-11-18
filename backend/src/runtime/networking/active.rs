//! Durable runtime requests to the sole persistent rescue supervisor.
//! Paths are internal fixed state locations, never HTTP inputs.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use xkeenwrt_recovery::{
    Decision, Journal, MutationLock, State,
    active::{self, ActiveRecord, Kind, Phase},
};

fn private_bytes(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 || m.len() > limit {
        return Err(io::Error::other("unsafe active state file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("oversized active state file"));
    }
    Ok(Some(bytes))
}
/// Why recovery ended `journal` Direct, from its volatile notice. Only a
/// notice bound to this exact transaction, closed Direct, is reported.
pub(crate) fn recovery_notice(path: &Path, journal: &Journal) -> Option<&'static str> {
    if !journal.rollback_direct_complete() && !journal.boot_cleanup_complete() {
        return None;
    }
    let bytes = private_bytes(path, 4096).ok()??;
    let notice: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    (notice["version"] == 1
        && notice["tx_id"].as_str() == Some(journal.tx_id.as_str())
        && notice["code"] == "SNAPSHOT_MISSING")
        .then_some("SNAPSHOT_MISSING")
}
fn settled(j: &Journal) -> bool {
    j.decision(&j.boot_id, j.created_boottime_ms, false) == Decision::Settled
}
fn can_start_active_request(journal: &Journal) -> bool {
    matches!(
        (journal.state, journal.operation),
        (State::Confirmed, xkeenwrt_recovery::Operation::Apply) if journal.applied
    ) || (journal.state == State::RolledBack && journal.previous_good.is_some())
}
fn journal_for(dir: &Path, current: &Journal, record: &ActiveRecord) -> io::Result<Journal> {
    if record.journal_tx_id == current.tx_id {
        return Ok(current.clone());
    }
    let id = uuid::Uuid::parse_str(&record.journal_tx_id).map_err(io::Error::other)?;
    if id.to_string() != record.journal_tx_id {
        return Err(io::Error::other("invalid archived transaction"));
    }
    let bytes = private_bytes(
        &dir.join("network-history")
            .join(format!("{}.json", record.journal_tx_id)),
        1_048_576,
    )?
    .ok_or_else(|| io::Error::other("missing archived journal"))?;
    let old: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if old.tx_id != record.journal_tx_id
        || old.current.owner_id != current.current.owner_id
        || old.generation >= current.generation
        || !settled(&old)
    {
        return Err(io::Error::other("invalid archived journal"));
    }
    Ok(old)
}
fn read_record(path: &Path) -> io::Result<Option<ActiveRecord>> {
    private_bytes(path, 16_384)?
        .map(|b| active::decode(&b).map_err(|_| io::Error::other("invalid active record")))
        .transpose()
}
pub(crate) fn settled_disable(journal: &Journal, dir: &Path) -> io::Result<bool> {
    if journal.state != State::Disabled {
        return Ok(false);
    }
    if journal.boot_cleanup_complete() || journal.lifecycle_cleanup_complete() || journal.rollback_direct_complete() {
        return Ok(read_record(&dir.join("active-reconcile.json"))?.is_none());
    }
    let Some(record) = read_record(&dir.join("active-reconcile.json"))? else {
        return Ok(false);
    };
    Ok(record.valid_for(journal)
        && record.kind == Kind::DisableRequested
        && record.phase == Phase::Completed
        && record.outcome == Some(xkeenwrt_recovery::active::Outcome::Disabled))
}
fn history_dir(dir: &Path, create: bool) -> io::Result<Option<PathBuf>> {
    let path = dir.join("active-event-history");
    if create {
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => File::open(dir)?.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
    }
    let m = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("unsafe active history"));
    }
    Ok(Some(path))
}
fn archive(dir: &Path, record: &ActiveRecord) -> io::Result<()> {
    let history = history_dir(dir, true)?.ok_or_else(|| io::Error::other("missing active history"))?;
    let bytes = active::encode(record).map_err(|_| io::Error::other("invalid active record"))?;
    let target = history.join(format!("{}.json", record.event_id));
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            xkeenwrt_recovery::resources::admit_history_append(
                dir,
                bytes.len() as u64,
                xkeenwrt_recovery::resources::HistoryArea::ActiveEvents,
            )?;
        }
        Ok(_) => (),
        Err(error) => return Err(error),
    }
    match crate::private_file::publish_private(&target, &bytes) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if private_bytes(&target, 16_384)?.as_deref() != Some(bytes.as_slice()) {
                return Err(io::Error::other("active archive conflict"));
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}
/// Write a generation-CAS request. Retries return the durable record; a
/// different binding for a reused key fails. `retry_of` is required to replace
/// an error and must be an explicit user action, never an automatic tick.
pub fn request(
    dir: &Path, lock_path: &Path, owner: &str, generation: u64, kind: Kind, idempotency_key: Option<&str>,
    retry_of: Option<&str>,
) -> io::Result<ActiveRecord> {
    match (kind, idempotency_key) {
        (Kind::DisableRequested, Some(k))
            if !k.is_empty() && k.len() <= 128 && k.bytes().all(|b| b.is_ascii_graphic()) => {}
        (Kind::CoreFailed | Kind::ReconcileRequested, None) => (),
        _ => return Err(io::Error::other("invalid idempotency binding")),
    }
    if let Some(id) = retry_of {
        let parsed = uuid::Uuid::parse_str(id).map_err(io::Error::other)?;
        if parsed.to_string() != id {
            return Err(io::Error::other("invalid retry id"));
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
        || private_bytes(lock_path, 4096)?.is_none()
    {
        return Err(io::Error::other("unsafe active state directory"));
    }
    let _guard = MutationLock::acquire(lock_path, Duration::from_secs(2))?;
    xkeenwrt_recovery::resources::prepare_history_append(
        dir,
        0,
        xkeenwrt_recovery::resources::HistoryArea::ActiveEvents,
        0,
        0,
    )?;
    for lifecycle in ["removal.json", "lifecycle.json", "rescue-replacement.json"] {
        match fs::symlink_metadata(dir.join(lifecycle)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Ok(_) => return Err(io::Error::other("package lifecycle operation is in progress")),
            Err(error) => return Err(error),
        }
    }
    let bytes = private_bytes(&dir.join("recovery.json"), 1_048_576)?
        .ok_or_else(|| io::Error::other("missing recovery journal"))?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let active = active::active_manifest(&journal).ok_or_else(|| io::Error::other("network not active"))?;
    if active.owner_id != owner || active.generation != generation || !settled(&journal) {
        return Err(io::Error::other("network generation changed"));
    }
    let mut boot = String::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(128)
        .read_to_string(&mut boot)?;
    let boot = boot.trim();
    let parsed = uuid::Uuid::parse_str(boot).map_err(io::Error::other)?;
    if parsed.to_string() != boot || boot != journal.boot_id {
        return Err(io::Error::other("boot recovery pending"));
    }
    if let Some(history) = history_dir(dir, false)? {
        let mut count = 0usize;
        for entry in fs::read_dir(history)? {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "active history timeout"));
            }
            let entry = entry?;
            count += 1;
            if count > 128 {
                return Err(io::Error::other("active history limit"));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("invalid active archive"))?;
            let id = name
                .strip_suffix(".json")
                .ok_or_else(|| io::Error::other("invalid active archive"))?;
            let parsed = uuid::Uuid::parse_str(id).map_err(io::Error::other)?;
            if parsed.to_string() != id {
                return Err(io::Error::other("invalid active archive"));
            }
            let record = read_record(&entry.path())?.ok_or_else(|| io::Error::other("missing active archive"))?;
            let bound = journal_for(dir, &journal, &record)?;
            if record.event_id != id
                || !record.valid_binding(&bound)
                || !matches!(record.phase, Phase::Completed | Phase::Error)
            {
                return Err(io::Error::other("invalid active archive binding"));
            }
            if idempotency_key.is_some() && record.idempotency_key.as_deref() == idempotency_key {
                if record.kind == kind
                    && record.owner_id == owner
                    && record.generation == generation
                    && record.journal_tx_id == journal.tx_id
                {
                    return Ok(record);
                }
                return Err(io::Error::other("idempotency key conflict"));
            }
        }
    }
    let path = dir.join("active-reconcile.json");
    if let Some(prior) = read_record(&path)? {
        let bound = journal_for(dir, &journal, &prior)?;
        if !prior.valid_binding(&bound) {
            return Err(io::Error::other("invalid active record binding"));
        }
        if prior.journal_tx_id == journal.tx_id && !prior.valid_for(&journal) {
            return Err(io::Error::other("invalid active state"));
        }
        let same = prior.owner_id == owner
            && prior.generation == generation
            && prior.journal_tx_id == journal.tx_id
            && prior.kind == kind
            && prior.idempotency_key.as_deref() == idempotency_key;
        if same && retry_of.is_none() {
            return Ok(prior);
        }
        if !can_start_active_request(&journal) {
            return Err(io::Error::other("network not active"));
        }
        match prior.phase {
            Phase::Error
                if prior.owner_id == owner
                    && prior.generation == generation
                    && prior.journal_tx_id == journal.tx_id
                    && (retry_of == Some(prior.event_id.as_str())
                        || (kind == Kind::DisableRequested && retry_of.is_none())) => {}
            Phase::Completed if retry_of.is_none() => (),
            _ => return Err(io::Error::other("unfinished active operation")),
        }
        let mut candidate = ActiveRecord::new(
            &journal,
            &uuid::Uuid::new_v4().to_string(),
            kind,
            idempotency_key.map(str::to_owned),
        )
        .map_err(|_| io::Error::other("invalid active request"))?;
        candidate.retry_of = retry_of.map(str::to_owned);
        if !candidate.valid_for(&journal) {
            return Err(io::Error::other("invalid active request"));
        }
        if prior.idempotency_key.is_some() && prior.idempotency_key.as_deref() == idempotency_key {
            return Err(io::Error::other("idempotency key conflict"));
        }
        archive(dir, &prior)?;
    } else if retry_of.is_some() {
        return Err(io::Error::other("missing operation to retry"));
    }
    if !can_start_active_request(&journal) {
        return Err(io::Error::other("network not active"));
    }
    let mut record = ActiveRecord::new(
        &journal,
        &uuid::Uuid::new_v4().to_string(),
        kind,
        idempotency_key.map(str::to_owned),
    )
    .map_err(|_| io::Error::other("invalid active request"))?;
    record.retry_of = retry_of.map(str::to_owned);
    if !record.valid_for(&journal) {
        return Err(io::Error::other("invalid active request"));
    }
    let bytes = active::encode(&record).map_err(|_| io::Error::other("invalid active request"))?;
    let temp = dir.join(format!(".active-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        use std::io::Write;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&temp, &path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    Ok(record)
}

/// Caller holds mutation.lock and has verified journal pins and old object
/// absence. Preserve a completed receipt before replacing its journal.
pub(crate) fn retire_current(dir: &Path, journal: &Journal) -> io::Result<()> {
    let path = dir.join("active-reconcile.json");
    let Some(record) = read_record(&path)? else {
        return Ok(());
    };
    if record.phase != Phase::Completed || !record.valid_binding(journal) {
        return Err(io::Error::other("active operation is not settled"));
    }
    archive(dir, &record)?;
    fs::remove_file(path)?;
    File::open(dir)?.sync_all()
}

/// Apply idempotency keys cannot be reused for archived active actions.
pub(crate) fn ensure_key_unused(dir: &Path, current: &Journal, key: &str) -> io::Result<()> {
    let Some(history) = history_dir(dir, false)? else {
        return Ok(());
    };
    xkeenwrt_recovery::resources::prepare_history_append(
        dir,
        0,
        xkeenwrt_recovery::resources::HistoryArea::ActiveEvents,
        0,
        0,
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut count = 0usize;
    for entry in fs::read_dir(history)? {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "active history timeout"));
        }
        let entry = entry?;
        count += 1;
        if count > 128 {
            return Err(io::Error::other("active history limit"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("invalid active archive"))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| io::Error::other("invalid active archive"))?;
        let parsed = uuid::Uuid::parse_str(id).map_err(io::Error::other)?;
        if parsed.to_string() != id {
            return Err(io::Error::other("invalid active archive"));
        }
        let record = read_record(&entry.path())?.ok_or_else(|| io::Error::other("missing active archive"))?;
        let bound = journal_for(dir, current, &record)?;
        if record.event_id != id
            || !record.valid_binding(&bound)
            || !matches!(record.phase, Phase::Completed | Phase::Error)
        {
            return Err(io::Error::other("invalid active archive binding"));
        }
        if record.idempotency_key.as_deref() == Some(key) {
            return Err(io::Error::other("idempotency key conflict"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Pending,
    Completed,
    Error,
}
#[derive(Debug, serde::Serialize)]
pub struct Receipt {
    pub event_id: String,
    pub active_generation: u64,
    pub state: ReceiptState,
    pub outcome: Option<xkeenwrt_recovery::active::Outcome>,
    pub error_code: Option<String>,
}
/// Poll only a synced helper receipt. Disable is complete only when the journal
/// itself has durably reached Disabled as well as the matching receipt.
pub fn current_status(dir: &Path, lock_path: &Path, event_id: &str) -> io::Result<Receipt> {
    let id = uuid::Uuid::parse_str(event_id).map_err(io::Error::other)?;
    if id.to_string() != event_id {
        return Err(io::Error::other("invalid event id"));
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
        || private_bytes(lock_path, 4096)?.is_none()
    {
        return Err(io::Error::other("unsafe active state directory"));
    }
    let _guard = MutationLock::acquire(lock_path, Duration::from_secs(2))?;
    let bytes = private_bytes(&dir.join("recovery.json"), 1_048_576)?
        .ok_or_else(|| io::Error::other("missing recovery journal"))?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let record =
        read_record(&dir.join("active-reconcile.json"))?.ok_or_else(|| io::Error::other("missing active receipt"))?;
    if record.event_id != event_id || !record.valid_for(&journal) {
        return Err(io::Error::other("active receipt mismatch"));
    }
    receipt_for(&journal, record)
}

fn receipt_for(journal: &Journal, record: ActiveRecord) -> io::Result<Receipt> {
    if !record.valid_for(journal) {
        return Err(io::Error::other("active receipt mismatch"));
    }
    let state = match record.phase {
        Phase::Error => ReceiptState::Error,
        Phase::Completed if record.kind != Kind::DisableRequested || journal.state == State::Disabled => {
            ReceiptState::Completed
        }
        _ => ReceiptState::Pending,
    };
    Ok(Receipt {
        event_id: record.event_id,
        active_generation: record.generation,
        state,
        outcome: if state == ReceiptState::Completed {
            record.outcome
        } else {
            None
        },
        error_code: if state == ReceiptState::Error {
            record.error_code
        } else {
            None
        },
    })
}

/// Read the latest durable receipt without a client-held event ID (for reload).
pub fn latest_status(dir: &Path, lock_path: &Path) -> io::Result<Option<Receipt>> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o700
        || private_bytes(lock_path, 4096)?.is_none()
    {
        return Err(io::Error::other("unsafe active state directory"));
    }
    let _guard = MutationLock::acquire(lock_path, Duration::from_secs(2))?;
    latest_status_locked(dir)
}

pub(crate) fn latest_status_locked(dir: &Path) -> io::Result<Option<Receipt>> {
    let Some(record) = read_record(&dir.join("active-reconcile.json"))? else {
        return Ok(None);
    };
    let bytes = private_bytes(&dir.join("recovery.json"), 1_048_576)?
        .ok_or_else(|| io::Error::other("missing recovery journal"))?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    receipt_for(&journal, record).map(Some)
}
