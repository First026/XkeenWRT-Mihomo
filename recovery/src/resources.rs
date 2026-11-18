//! Shared storage admission for the three durable XkeenWRT history trees.
//! Callers hold `/var/run/xkeenwrt/mutation.lock` while checking and publishing.
use crate::{Journal, active};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::SystemTime,
};

const HISTORY_LIMIT: u64 = 64 * 1024 * 1024;
const ENTRY_LIMIT: usize = 512;
const TREE_ENTRY_LIMIT: usize = 128;
const SAFE_SCAN_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryArea {
    Snapshots,
    Network,
    ActiveEvents,
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    entries: usize,
    area_entries: BTreeMap<&'static str, usize>,
}
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn owner_id() -> u32 {
    unsafe { libc::geteuid() }
}
fn check_dir(path: &Path, root: bool) -> io::Result<Option<std::fs::Metadata>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != owner_id()
        || if root {
            meta.mode() & 0o022 != 0
        } else {
            meta.mode() & 0o077 != 0
        }
    {
        return Err(fail("unsafe history directory"));
    }
    Ok(Some(meta))
}
fn scan_dir(
    path: &Path,
    depth: usize,
    usage: &mut Usage,
    area: Option<&'static str>,
) -> io::Result<()> {
    if depth > 5 {
        return Err(fail("history nesting limit"));
    }
    if check_dir(path, false)?.is_none() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        usage.entries += 1;
        if usage.entries > SAFE_SCAN_LIMIT {
            return Err(fail("history scan limit"));
        }
        if depth == 0
            && let Some(area) = area
        {
            *usage.area_entries.entry(area).or_default() += 1;
        }
        let meta = std::fs::symlink_metadata(entry.path())?;
        if meta.file_type().is_symlink() || meta.uid() != owner_id() {
            return Err(fail("unsafe history entry"));
        }
        if meta.is_dir() {
            if meta.mode() & 0o077 != 0 {
                return Err(fail("unsafe history directory"));
            }
            scan_dir(&entry.path(), depth + 1, usage, None)?;
        } else if meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0 {
            usage.bytes = usage.bytes.saturating_add(meta.len());
        } else {
            return Err(fail("unsafe history file"));
        }
    }
    Ok(())
}
fn usage(root: &Path) -> io::Result<Usage> {
    check_dir(root, true)?.ok_or_else(|| fail("missing history root"))?;
    let mut usage = Usage::default();
    for name in [
        "history",
        "network-history",
        "active-event-history",
        "payloads",
    ] {
        scan_dir(&root.join(name), 0, &mut usage, Some(name))?;
    }
    Ok(usage)
}

/// Return the current accounted size of the shared history trees.
pub fn history_size(root: &Path) -> io::Result<u64> {
    let usage = usage(root)?;
    if usage.entries > ENTRY_LIMIT || usage.bytes > HISTORY_LIMIT {
        return Err(fail("history capacity exceeded"));
    }
    Ok(usage.bytes)
}

fn read_private(root: &Path, name: &str, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let path = root.join(name);
    let before = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner_id()
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() > limit
    {
        return Err(fail("unsafe history reference"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.uid() != before.uid()
        || opened.ino() != before.ino()
        || opened.len() > limit
    {
        return Err(fail("history reference changed"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(fail("oversized history reference"));
    }
    Ok(Some(bytes))
}
fn uuid_name(name: &str) -> io::Result<String> {
    if !crate::valid_owner(name) {
        return Err(fail("noncanonical history identity"));
    }
    Ok(name.to_owned())
}
fn parse_journal(bytes: &[u8], expected_id: Option<&str>, settled: bool) -> io::Result<Journal> {
    let journal: Journal = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if expected_id.is_some_and(|id| id != journal.tx_id)
        || uuid_name(&journal.tx_id).is_err()
        || journal.decision(&journal.boot_id, journal.created_boottime_ms, false)
            == crate::Decision::Invalid
        || (settled
            && journal.decision(&journal.boot_id, journal.created_boottime_ms, false)
                != crate::Decision::Settled)
    {
        return Err(fail("invalid history journal"));
    }
    Ok(journal)
}
fn journal_snapshots(journal: &Journal, pinned: &mut BTreeSet<String>) {
    pinned.insert(journal.current_core.snapshot_id.clone());
    pinned.insert(journal.previous_core.snapshot_id.clone());
    pinned.insert(journal.baseline_core.snapshot_id.clone());
    if let Some(next) = &journal.next_baseline_core {
        pinned.insert(next.snapshot_id.clone());
    }
}
fn scan_snapshot_links(value: &serde_json::Value, pinned: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if key.contains("snapshot")
                    && let Some(id) = value.as_str()
                    && crate::valid_owner(id)
                {
                    pinned.insert(id.to_owned());
                }
                scan_snapshot_links(value, pinned);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                scan_snapshot_links(value, pinned);
            }
        }
        _ => (),
    }
}

struct References {
    /// Snapshots pinned by the current journal and root operation files.
    snapshots: BTreeSet<String>,
    /// Snapshots pinned by each archived network journal; released with it.
    journal_snapshots: BTreeMap<String, BTreeSet<String>>,
    network_journals: BTreeMap<String, Journal>,
    active_records: BTreeMap<String, active::ActiveRecord>,
    pinned_network: BTreeSet<String>,
    pinned_events: BTreeSet<String>,
    pin_all: bool,
}
fn read_dir_names(path: &Path) -> io::Result<Vec<std::fs::DirEntry>> {
    if check_dir(path, false)?.is_none() {
        return Ok(Vec::new());
    }
    std::fs::read_dir(path)?.collect()
}
fn references(root: &Path) -> io::Result<References> {
    let mut refs = References {
        snapshots: BTreeSet::new(),
        journal_snapshots: BTreeMap::new(),
        network_journals: BTreeMap::new(),
        active_records: BTreeMap::new(),
        pinned_network: BTreeSet::new(),
        pinned_events: BTreeSet::new(),
        pin_all: false,
    };
    if let Some(bytes) = read_private(root, "recovery.json", 1_048_576)? {
        let journal = parse_journal(&bytes, None, false)?;
        journal_snapshots(&journal, &mut refs.snapshots);
        refs.network_journals.insert(journal.tx_id.clone(), journal);
    }
    for name in [
        "transaction.json",
        "inputs-transition.json",
        "removal.json",
        "lifecycle.json",
        "rescue-replacement.json",
    ] {
        if let Some(bytes) = read_private(root, name, 26 * 1024 * 1024)? {
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            scan_snapshot_links(&value, &mut refs.snapshots);
            if name == "transaction.json"
                && let Some(tx) = value["pending"]["network_tx_id"].as_str()
            {
                uuid_name(tx)?;
                refs.pinned_network.insert(tx.into());
            }
            if !["transaction.json", "inputs-transition.json"].contains(&name) {
                refs.pin_all = true;
            }
        }
    }
    let network_dir = root.join("network-history");
    for entry in read_dir_names(&network_dir)? {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| fail("invalid network history name"))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| fail("invalid network history name"))?;
        uuid_name(id)?;
        let bytes = read_private(&network_dir, &name, 1_048_576)?
            .ok_or_else(|| fail("network history disappeared"))?;
        let journal = parse_journal(&bytes, Some(id), true)?;
        let mut pinned = BTreeSet::new();
        journal_snapshots(&journal, &mut pinned);
        refs.journal_snapshots.insert(id.to_owned(), pinned);
        refs.network_journals.insert(id.to_owned(), journal);
    }
    let active_dir = root.join("active-event-history");
    for entry in read_dir_names(&active_dir)? {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| fail("invalid active history name"))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| fail("invalid active history name"))?;
        uuid_name(id)?;
        let bytes = read_private(&active_dir, &name, 16_384)?
            .ok_or_else(|| fail("active history disappeared"))?;
        let record = active::decode(&bytes).map_err(|_| fail("invalid active history record"))?;
        if record.event_id != id {
            return Err(fail("active history identity mismatch"));
        }
        refs.active_records.insert(id.to_owned(), record);
    }
    let current = read_private(root, "active-reconcile.json", 16_384)?
        .map(|bytes| active::decode(&bytes).map_err(|_| fail("invalid active record")))
        .transpose()?;
    if let Some(record) = current {
        refs.pinned_events.insert(record.event_id.clone());
        refs.pinned_network.insert(record.journal_tx_id.clone());
        let mut next = record.retry_of.clone();
        while let Some(id) = next {
            if !refs.pinned_events.insert(id.clone()) {
                break;
            }
            next = refs
                .active_records
                .get(&id)
                .ok_or_else(|| fail("missing active retry record"))?
                .retry_of
                .clone();
        }
    }
    for id in &refs.pinned_events {
        if let Some(record) = refs.active_records.get(id) {
            refs.pinned_network.insert(record.journal_tx_id.clone());
        }
    }
    for id in &refs.pinned_network {
        if !refs.network_journals.contains_key(id) {
            return Err(fail("active history references missing journal"));
        }
    }
    for (id, record) in &refs.active_records {
        if record
            .retry_of
            .as_ref()
            .is_some_and(|parent| !refs.active_records.contains_key(parent))
        {
            return Err(fail("active record references missing retry record"));
        }
        let journal = refs
            .network_journals
            .get(&record.journal_tx_id)
            .ok_or_else(|| fail("active record references missing journal"))?;
        if !record.valid_binding(journal) || record.event_id != *id {
            return Err(fail("invalid active history binding"));
        }
    }
    if let Some(bytes) = read_private(root, "active-reconcile.json", 16_384)? {
        let record = active::decode(&bytes).map_err(|_| fail("invalid active record"))?;
        let journal = refs
            .network_journals
            .get(&record.journal_tx_id)
            .ok_or_else(|| fail("active record references missing journal"))?;
        if !record.valid_binding(journal) {
            return Err(fail("invalid active record binding"));
        }
    }
    Ok(refs)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CandidateArea {
    Snapshots,
    Network,
    ActiveEvents,
}
impl CandidateArea {
    fn of(area: HistoryArea) -> Self {
        match area {
            HistoryArea::Snapshots => Self::Snapshots,
            HistoryArea::Network => Self::Network,
            HistoryArea::ActiveEvents => Self::ActiveEvents,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Snapshots => "history",
            Self::Network => "network-history",
            Self::ActiveEvents => "active-event-history",
        }
    }
}
struct Candidate {
    area: CandidateArea,
    id: String,
    path: PathBuf,
    modified: SystemTime,
    bytes: u64,
    entries: usize,
}
/// Every top-level history name that a cleanup could ever remove, with the
/// space it would release. Whether it is currently pinned is decided later.
fn candidates(root: &Path, refs: &References) -> io::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    if refs.pin_all {
        return Ok(candidates);
    }
    for area in [
        CandidateArea::Snapshots,
        CandidateArea::Network,
        CandidateArea::ActiveEvents,
    ] {
        let dir = root.join(area.name());
        for entry in read_dir_names(&dir)? {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| fail("invalid history name"))?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            let id = match area {
                CandidateArea::Snapshots => {
                    if let Some(id) = name.strip_prefix(".stage-") {
                        Some(uuid_name(id)?)
                    } else if let Some(id) = name.strip_prefix(".xkeenwrt-secret-") {
                        Some(uuid_name(id)?)
                    } else if let Some(id) = name
                        .strip_suffix(".json")
                        .or_else(|| name.strip_suffix(".yaml"))
                    {
                        Some(uuid_name(id)?)
                    } else {
                        crate::valid_owner(&name).then(|| name.clone())
                    }
                }
                CandidateArea::Network | CandidateArea::ActiveEvents => {
                    name.strip_suffix(".json").map(uuid_name).transpose()?
                }
            };
            let Some(id) = id else {
                continue;
            };
            let (bytes, entries) = if meta.is_dir() {
                let mut nested = Usage::default();
                scan_dir(&path, 1, &mut nested, None)?;
                (nested.bytes, nested.entries + 1)
            } else {
                (meta.len(), 1)
            };
            candidates.push(Candidate {
                area,
                id,
                path,
                modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                bytes,
                entries,
            });
        }
    }
    candidates.sort_by(|a, b| {
        a.modified
            .cmp(&b.modified)
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(candidates)
}
/// Pins are recomputed against what the plan has already released: dropping
/// an archived journal or event can release the snapshots or journal it named.
fn pinned(
    candidate: &Candidate,
    refs: &References,
    removed: &BTreeSet<(CandidateArea, String)>,
    protect: &BTreeSet<String>,
) -> bool {
    let alive = |area, id: &str| !removed.contains(&(area, id.to_owned()));
    protect.contains(&candidate.id)
        || match candidate.area {
            CandidateArea::Snapshots => {
                refs.snapshots.contains(&candidate.id)
                    || refs.journal_snapshots.iter().any(|(journal, ids)| {
                        alive(CandidateArea::Network, journal) && ids.contains(&candidate.id)
                    })
            }
            CandidateArea::Network => {
                refs.pinned_network.contains(&candidate.id)
                    || refs.active_records.iter().any(|(event, record)| {
                        alive(CandidateArea::ActiveEvents, event)
                            && record.journal_tx_id == candidate.id
                    })
            }
            CandidateArea::ActiveEvents => {
                refs.pinned_events.contains(&candidate.id)
                    || refs.active_records.iter().any(|(event, record)| {
                        alive(CandidateArea::ActiveEvents, event)
                            && record.retry_of.as_deref() == Some(candidate.id.as_str())
                    })
            }
        }
}
fn remove_path(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Everything one operation will append across the history trees. Reserve
/// the sum once, before the first write; later writers then never prune.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryNeed {
    pub bytes: u64,
    /// All new directory entries, including files nested in a snapshot.
    pub entries: usize,
    /// New top-level names per tree, bounded by the 128-name tree limit.
    pub snapshots: usize,
    pub network: usize,
    pub active_events: usize,
}
impl HistoryNeed {
    /// One core snapshot: its directory, `config.yaml` and, with providers,
    /// `assets/providers/{proxies,rules}` plus one file per asset.
    pub fn snapshot(bytes: u64, assets: usize) -> Self {
        Self {
            bytes,
            entries: if assets == 0 {
                2
            } else {
                assets.saturating_add(6)
            },
            snapshots: 1,
            ..Self::default()
        }
    }
    /// One archived journal or active event file.
    pub fn archive(area: HistoryArea, bytes: u64) -> Self {
        let mut need = Self {
            bytes,
            entries: 1,
            ..Self::default()
        };
        match area {
            HistoryArea::Snapshots => need.snapshots = 1,
            HistoryArea::Network => need.network = 1,
            HistoryArea::ActiveEvents => need.active_events = 1,
        }
        need
    }
    pub fn and(mut self, other: &Self) -> Self {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.entries = self.entries.saturating_add(other.entries);
        self.snapshots = self.snapshots.saturating_add(other.snapshots);
        self.network = self.network.saturating_add(other.network);
        self.active_events = self.active_events.saturating_add(other.active_events);
        self
    }
    fn in_area(&self, area: CandidateArea) -> usize {
        match area {
            CandidateArea::Snapshots => self.snapshots,
            CandidateArea::Network => self.network,
            CandidateArea::ActiveEvents => self.active_events,
        }
    }
}

/// The exact removals a reservation will perform, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPlan {
    pub removals: Vec<PathBuf>,
    pub used_bytes: u64,
    pub used_entries: usize,
    pub freed_bytes: u64,
    pub freed_entries: usize,
}

/// Not enough history space even after removing everything unpinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryFull {
    pub used_entries: usize,
    pub limit_entries: usize,
    pub needed_entries: usize,
    pub reclaimable_entries: usize,
    pub used_bytes: u64,
    pub limit_bytes: u64,
    pub needed_bytes: u64,
    pub reclaimable_bytes: u64,
}
impl std::fmt::Display for HistoryFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "history full: {} of {} entries used, {} needed, {} reclaimable",
            self.used_entries, self.limit_entries, self.needed_entries, self.reclaimable_entries
        )
    }
}
impl std::error::Error for HistoryFull {}
/// The typed shortage behind an admission error, if that was the cause.
pub fn history_full(error: &io::Error) -> Option<HistoryFull> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<HistoryFull>())
        .copied()
}

struct Projection {
    bytes: u64,
    entries: usize,
    area: BTreeMap<&'static str, usize>,
}
impl Projection {
    fn global_over(&self, need: &HistoryNeed) -> bool {
        self.bytes.saturating_add(need.bytes) > HISTORY_LIMIT
            || self.entries.saturating_add(need.entries) > ENTRY_LIMIT
    }
    fn area_over(&self, need: &HistoryNeed) -> Option<CandidateArea> {
        [
            CandidateArea::Snapshots,
            CandidateArea::Network,
            CandidateArea::ActiveEvents,
        ]
        .into_iter()
        .find(|area| {
            self.area
                .get(area.name())
                .copied()
                .unwrap_or(0)
                .saturating_add(need.in_area(*area))
                > TREE_ENTRY_LIMIT
        })
    }
    fn release(&mut self, candidate: &Candidate) {
        self.bytes = self.bytes.saturating_sub(candidate.bytes);
        self.entries = self.entries.saturating_sub(candidate.entries);
        if let Some(count) = self.area.get_mut(candidate.area.name()) {
            *count = count.saturating_sub(1);
        }
    }
}
fn next_removal(
    candidates: &[Candidate],
    taken: &[bool],
    refs: &References,
    removed: &BTreeSet<(CandidateArea, String)>,
    protect: &BTreeSet<String>,
    order: &[CandidateArea],
) -> Option<usize> {
    order.iter().find_map(|wanted| {
        candidates
            .iter()
            .enumerate()
            .position(|(index, candidate)| {
                !taken[index]
                    && candidate.area == *wanted
                    && !pinned(candidate, refs, removed, protect)
            })
    })
}
fn pressure_order(global: bool, area: Option<CandidateArea>) -> &'static [CandidateArea] {
    match (global, area) {
        (true, _) | (false, Some(CandidateArea::Snapshots)) => &[
            CandidateArea::Snapshots,
            CandidateArea::Network,
            CandidateArea::ActiveEvents,
        ],
        (false, Some(CandidateArea::Network)) => {
            &[CandidateArea::Network, CandidateArea::ActiveEvents]
        }
        (false, Some(CandidateArea::ActiveEvents)) => &[CandidateArea::ActiveEvents],
        (false, None) => &[],
    }
}

/// Compute, without touching the disk, the oldest-first unpinned removals
/// that make room for `need`. IDs in `protect` are never selected. Fails with
/// a typed [`HistoryFull`] when even removing everything unpinned is not enough.
pub fn plan_history_append(
    root: &Path,
    need: &HistoryNeed,
    protect: &BTreeSet<String>,
) -> io::Result<HistoryPlan> {
    check_dir(root, true)?.ok_or_else(|| fail("missing history root"))?;
    let current = usage(root)?;
    let mut projection = Projection {
        bytes: current.bytes,
        entries: current.entries,
        area: current.area_entries.clone(),
    };
    let mut plan = HistoryPlan {
        removals: Vec::new(),
        used_bytes: current.bytes,
        used_entries: current.entries,
        freed_bytes: 0,
        freed_entries: 0,
    };
    let global = projection.global_over(need);
    if !global && projection.area_over(need).is_none() {
        return Ok(plan);
    }
    let refs = references(root)?;
    let candidates = candidates(root, &refs)?;
    let mut taken = vec![false; candidates.len()];
    let mut removed = BTreeSet::new();
    let take = |index: usize,
                taken: &mut Vec<bool>,
                removed: &mut BTreeSet<(CandidateArea, String)>,
                projection: &mut Projection,
                plan: &mut HistoryPlan| {
        taken[index] = true;
        let candidate = &candidates[index];
        removed.insert((candidate.area, candidate.id.clone()));
        projection.release(candidate);
        plan.removals.push(candidate.path.clone());
        plan.freed_bytes = plan.freed_bytes.saturating_add(candidate.bytes);
        plan.freed_entries = plan.freed_entries.saturating_add(candidate.entries);
    };
    loop {
        let global = projection.global_over(need);
        let area = projection.area_over(need);
        if !global && area.is_none() {
            return Ok(plan);
        }
        let order = pressure_order(global, area);
        if let Some(index) = next_removal(&candidates, &taken, &refs, &removed, protect, order) {
            take(index, &mut taken, &mut removed, &mut projection, &mut plan);
            continue;
        }
        // Not satisfiable: learn how much an unrestricted cleanup could ever
        // release, for the shortage report only. Nothing is removed.
        while let Some(index) = next_removal(
            &candidates,
            &taken,
            &refs,
            &removed,
            protect,
            pressure_order(true, None),
        ) {
            take(index, &mut taken, &mut removed, &mut projection, &mut plan);
        }
        return Err(io::Error::other(HistoryFull {
            used_entries: current.entries,
            limit_entries: ENTRY_LIMIT,
            needed_entries: need.entries,
            reclaimable_entries: plan.freed_entries,
            used_bytes: current.bytes,
            limit_bytes: HISTORY_LIMIT,
            needed_bytes: need.bytes,
            reclaimable_bytes: plan.freed_bytes,
        }));
    }
}

/// Make room for a whole operation once, before its first write: perform
/// exactly [`plan_history_append`]'s removals and never touch `protect`.
pub fn reserve_history(
    root: &Path,
    need: &HistoryNeed,
    protect: &BTreeSet<String>,
) -> io::Result<HistoryPlan> {
    let plan = plan_history_append(root, need, protect)?;
    for path in &plan.removals {
        remove_path(path)?;
    }
    history_fits(root, need)?;
    Ok(plan)
}

/// Check, without removing anything, that a reserved write still fits.
pub fn history_fits(root: &Path, need: &HistoryNeed) -> io::Result<()> {
    check_dir(root, true)?.ok_or_else(|| fail("missing history root"))?;
    let current = usage(root)?;
    let projection = Projection {
        bytes: current.bytes,
        entries: current.entries,
        area: current.area_entries,
    };
    if projection.global_over(need) || projection.area_over(need).is_some() {
        return Err(fail("history reservation exceeded"));
    }
    Ok(())
}

/// Prune only unpinned history and reserve capacity for one exact writer.
/// `tree_entries` includes the staged files below a new core snapshot; `area_entries`
/// counts the top-level name used by the tree-specific admission limit.
pub fn prepare_history_append(
    root: &Path,
    bytes: u64,
    area: HistoryArea,
    tree_entries: usize,
    area_entries: usize,
) -> io::Result<()> {
    let mut need = HistoryNeed {
        bytes,
        entries: tree_entries,
        ..HistoryNeed::default()
    };
    match CandidateArea::of(area) {
        CandidateArea::Snapshots => need.snapshots = area_entries,
        CandidateArea::Network => need.network = area_entries,
        CandidateArea::ActiveEvents => need.active_events = area_entries,
    }
    reserve_history(root, &need, &BTreeSet::new()).map(|_| ())
}

/// Reserve capacity for one history append across every writer.
pub fn admit_history_append(root: &Path, bytes: u64, area: HistoryArea) -> io::Result<()> {
    prepare_history_append(root, bytes, area, 1, 1)
}
