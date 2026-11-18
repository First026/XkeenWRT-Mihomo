//! Typed, bounded active-network reconciliation. Call only while holding the
//! shared mutation lock; all side effects belong to the fixed native adapter.
use crate::{Decision, FailurePolicy, Journal, State, valid_digest, valid_name, valid_owner};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    CoreFailed,
    ReconcileRequested,
    DisableRequested,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Requested,
    Intent,
    NftDone,
    RoutingDone,
    BaselineDone,
    Verified,
    Completed,
    Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Direct,
    Block,
    Restore,
    Disable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Direct,
    Blocked,
    Restored,
    Disabled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Invalid,
    Drift,
    Unavailable,
    Health,
    Storage,
    Recovery,
}
impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::Drift => "DRIFT",
            Self::Unavailable => "UNAVAILABLE",
            Self::Health => "HEALTH",
            Self::Storage => "STORAGE",
            Self::Recovery => "RECOVERY",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryFailure {
    pub phase: Phase,
    pub code: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveRecord {
    pub version: u32,
    pub owner_id: String,
    pub generation: u64,
    pub journal_tx_id: String,
    pub journal_fingerprint: String,
    pub event_id: String,
    pub idempotency_key: Option<String>,
    pub retry_of: Option<String>,
    pub kind: Kind,
    pub expected_current_nft_sha256: String,
    pub current_snapshot_id: String,
    pub current_snapshot_sha256: String,
    pub current_snapshot_fingerprint: String,
    pub baseline_snapshot_id: String,
    pub baseline_snapshot_sha256: String,
    pub baseline_snapshot_fingerprint: String,
    pub phase: Phase,
    pub action: Option<Action>,
    pub outcome: Option<Outcome>,
    pub failed_phase: Option<Phase>,
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_failures: Vec<RetryFailure>,
}
/// A rolled-back replacement leaves its previous-good generation active. The
/// journal remains transaction-bound to the failed candidate, while active
/// actions bind to this helper-derived view of the restored generation.
pub fn active_manifest(j: &Journal) -> Option<&crate::Manifest> {
    if j.state == State::Disabled
        && let Some(completion) = &j.completion
    {
        return completion.active_generation.and_then(|g| {
            std::iter::once(&j.current)
                .chain(j.previous_good.iter())
                .find(|m| m.generation == g)
        });
    }
    if matches!(j.state, State::RolledBack)
        || (j.state == State::Disabled
            && j.operation == crate::Operation::Apply
            && j.previous_good.is_some())
    {
        j.previous_good.as_ref()
    } else if j.operation == crate::Operation::Apply
        && j.current_core.overlay != profile_policy::ManagedOverlay::Manual
    {
        Some(&j.current)
    } else {
        None
    }
}
pub fn active_core(j: &Journal) -> Option<&crate::CoreSnapshot> {
    if active_manifest(j).is_some_and(|m| {
        j.previous_good
            .as_ref()
            .is_some_and(|p| p.generation == m.generation)
    }) {
        Some(&j.previous_core)
    } else if active_manifest(j).is_some() {
        Some(&j.current_core)
    } else {
        None
    }
}
pub fn active_evidence(j: &Journal) -> Option<&crate::evidence::NetworkEvidence> {
    if active_manifest(j).is_some_and(|m| {
        j.previous_good
            .as_ref()
            .is_some_and(|p| p.generation == m.generation)
    }) {
        j.previous_network_evidence.as_ref()
    } else if active_manifest(j).is_some() {
        j.network_evidence.as_ref()
    } else {
        None
    }
}
impl ActiveRecord {
    pub fn new(
        j: &Journal,
        event_id: &str,
        kind: Kind,
        idempotency_key: Option<String>,
    ) -> Result<Self, Code> {
        let manifest = active_manifest(j).ok_or(Code::Invalid)?;
        let core = active_core(j).ok_or(Code::Invalid)?;
        let r = Self {
            version: 1,
            owner_id: manifest.owner_id.clone(),
            generation: manifest.generation,
            journal_tx_id: j.tx_id.clone(),
            journal_fingerprint: journal_fingerprint(j)?,
            event_id: event_id.into(),
            idempotency_key,
            retry_of: None,
            kind,
            expected_current_nft_sha256: manifest.nft_semantic_sha256.clone(),
            current_snapshot_id: core.snapshot_id.clone(),
            current_snapshot_sha256: core.sha256.clone(),
            current_snapshot_fingerprint: fingerprint(core)?,
            baseline_snapshot_id: j.baseline_core.snapshot_id.clone(),
            baseline_snapshot_sha256: j.baseline_core.sha256.clone(),
            baseline_snapshot_fingerprint: fingerprint(&j.baseline_core)?,
            phase: Phase::Requested,
            action: None,
            outcome: None,
            failed_phase: None,
            error_code: None,
            retry_failures: Vec::new(),
        };
        if r.valid_for(j) {
            Ok(r)
        } else {
            Err(Code::Invalid)
        }
    }
    pub fn valid_binding(&self, j: &Journal) -> bool {
        let Some(manifest) = active_manifest(j) else {
            return false;
        };
        let Some(core) = active_core(j) else {
            return false;
        };
        let journal_valid =
            j.decision(&j.boot_id, j.created_boottime_ms, false) != Decision::Invalid;
        let idem = match (&self.kind, &self.idempotency_key) {
            (Kind::DisableRequested, Some(k)) => {
                !k.is_empty() && k.len() <= 128 && k.bytes().all(|c| c.is_ascii_graphic())
            }
            (Kind::CoreFailed | Kind::ReconcileRequested, None) => true,
            _ => false,
        };
        let shape = match self.phase {
            Phase::Requested => {
                self.action.is_none()
                    && self.outcome.is_none()
                    && self.error_code.is_none()
                    && self.failed_phase.is_none()
            }
            Phase::Intent
            | Phase::NftDone
            | Phase::RoutingDone
            | Phase::BaselineDone
            | Phase::Verified => {
                self.action.is_some()
                    && self.outcome.is_none()
                    && self.error_code.is_none()
                    && self.failed_phase.is_none()
            }
            Phase::Completed => {
                self.action.is_some()
                    && self.outcome.is_some()
                    && self.error_code.is_none()
                    && self.failed_phase.is_none()
            }
            Phase::Error => {
                self.outcome.is_none()
                    && self.failed_phase.is_some_and(|p| {
                        matches!(
                            p,
                            Phase::Requested
                                | Phase::Intent
                                | Phase::NftDone
                                | Phase::RoutingDone
                                | Phase::BaselineDone
                                | Phase::Verified
                        )
                    })
                    && self.error_code.as_deref().is_some_and(|v| {
                        [
                            "INVALID",
                            "DRIFT",
                            "UNAVAILABLE",
                            "HEALTH",
                            "STORAGE",
                            "RECOVERY",
                        ]
                        .contains(&v)
                    })
            }
        };
        self.version == 1
            && self.retry_failures.len() <= 2
            && self.retry_failures.iter().all(|f| {
                f.code == Code::Recovery.as_str()
                    && matches!(
                        f.phase,
                        Phase::Intent
                            | Phase::NftDone
                            | Phase::RoutingDone
                            | Phase::BaselineDone
                            | Phase::Verified
                    )
            })
            && journal_valid
            && valid_owner(&self.owner_id)
            && valid_owner(&self.event_id)
            && self
                .retry_of
                .as_deref()
                .is_none_or(|v| valid_owner(v) && v != self.event_id)
            && self.owner_id == manifest.owner_id
            && self.generation == manifest.generation
            && self.journal_tx_id == j.tx_id
            && journal_fingerprint(j).is_ok_and(|v| v == self.journal_fingerprint)
            && self.expected_current_nft_sha256 == manifest.nft_semantic_sha256
            && valid_digest(&self.expected_current_nft_sha256)
            && self.current_snapshot_id == core.snapshot_id
            && valid_name(&self.current_snapshot_id)
            && self.current_snapshot_sha256 == core.sha256
            && valid_digest(&self.current_snapshot_sha256)
            && fingerprint(core).is_ok_and(|v| v == self.current_snapshot_fingerprint)
            && self.baseline_snapshot_id == j.baseline_core.snapshot_id
            && valid_name(&self.baseline_snapshot_id)
            && self.baseline_snapshot_sha256 == j.baseline_core.sha256
            && valid_digest(&self.baseline_snapshot_sha256)
            && fingerprint(&j.baseline_core).is_ok_and(|v| v == self.baseline_snapshot_fingerprint)
            && idem
            && shape
            && match (self.kind, self.action) {
                (Kind::DisableRequested, Some(Action::Disable))
                | (Kind::DisableRequested, None) => true,
                (Kind::CoreFailed, Some(Action::Direct)) => {
                    manifest.failure_policy == FailurePolicy::DirectOnFailure
                }
                (Kind::CoreFailed, Some(Action::Block)) => {
                    manifest.failure_policy == FailurePolicy::BlockSelectedOnFailure
                }
                (Kind::CoreFailed, None)
                | (Kind::ReconcileRequested, None | Some(Action::Restore | Action::Direct)) => true,
                _ => false,
            }
            && self.outcome.is_none_or(|o| {
                matches!(
                    (self.action, o),
                    (Some(Action::Direct), Outcome::Direct)
                        | (Some(Action::Block), Outcome::Blocked)
                        | (Some(Action::Restore), Outcome::Restored)
                        | (Some(Action::Disable), Outcome::Disabled)
                )
            })
    }
    pub fn valid_for(&self, j: &Journal) -> bool {
        if !self.valid_binding(j) {
            return false;
        }
        match j.state {
            State::Confirmed => {
                !(self.kind == Kind::DisableRequested && self.phase == Phase::Completed)
            }
            State::RolledBack => j.previous_good.is_some(),
            State::Disabled => {
                self.kind == Kind::DisableRequested
                    && (matches!(self.phase, Phase::Verified | Phase::Completed)
                        || (self.phase == Phase::Error
                            && self.failed_phase == Some(Phase::Verified)))
            }
            _ => false,
        }
    }
}

/// A failure policy may supersede a failed reconciliation. It still proves
/// object ownership at every step; an error never grants permission to restore.
fn failed_reconciliation(record: &ActiveRecord) -> bool {
    record.kind == Kind::ReconcileRequested
        && record.phase == Phase::Error
        && matches!(
            record.error_code.as_deref(),
            Some("DRIFT" | "RECOVERY" | "HEALTH")
        )
        && (record.action == Some(Action::Restore)
            || (record.action.is_none() && record.failed_phase == Some(Phase::Requested)))
}
pub fn may_replace_for_health_event(record: &ActiveRecord, journal: &Journal) -> bool {
    record.valid_for(journal) && (record.phase == Phase::Completed || failed_reconciliation(record))
}
pub fn archiveable(record: &ActiveRecord, journal: &Journal) -> bool {
    record.valid_binding(journal)
        && (record.phase == Phase::Completed || failed_reconciliation(record))
}
pub fn may_start_core_failed(record: Option<&ActiveRecord>, journal: &Journal) -> bool {
    match record {
        None => true,
        Some(record) if !may_replace_for_health_event(record, journal) => false,
        Some(record) => {
            (record.phase == Phase::Completed
                && record.outcome == Some(Outcome::Restored)
                && record.action == Some(Action::Restore))
                || failed_reconciliation(record)
        }
    }
}
fn journal_fingerprint(journal: &Journal) -> Result<String, Code> {
    use sha2::{Digest, Sha256};
    let mut immutable = journal.clone();
    immutable.state = State::Confirmed;
    immutable.completion = None;
    let bytes = serde_json::to_vec(&immutable).map_err(|_| Code::Invalid)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn fingerprint(snapshot: &crate::CoreSnapshot) -> Result<String, Code> {
    use sha2::{Digest, Sha256};
    let data = serde_json::to_vec(snapshot).map_err(|_| Code::Invalid)?;
    Ok(Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub fn encode(record: &ActiveRecord) -> Result<Vec<u8>, Code> {
    let b = serde_json::to_vec(record).map_err(|_| Code::Invalid)?;
    if b.len() > 16384 {
        Err(Code::Invalid)
    } else {
        Ok(b)
    }
}
pub fn decode(bytes: &[u8]) -> Result<ActiveRecord, Code> {
    if bytes.len() > 16384 {
        return Err(Code::Invalid);
    }
    serde_json::from_slice(bytes).map_err(|_| Code::Invalid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreHealth {
    Healthy,
    Failed,
}

/// Implementations are fixed privileged operations. Each mutation must accept
/// only its exact proven pre/post states and be idempotent after a crash.
pub trait Adapter {
    fn restore_admissible(&mut self, _journal: &Journal) -> Result<bool, Code> {
        Ok(true)
    }
    fn same_boot(&mut self, journal: &Journal) -> Result<bool, Code>;
    fn observe_core(&mut self, journal: &Journal) -> Result<CoreHealth, Code>;
    fn secure_nft(&mut self, journal: &Journal, action: Action) -> Result<(), Code>;
    fn reconcile_routes(&mut self, journal: &Journal, action: Action) -> Result<(), Code>;
    fn finish_interception(&mut self, journal: &Journal, action: Action) -> Result<(), Code>;
    fn restore_baseline(&mut self, journal: &Journal) -> Result<(), Code>;
    fn verify_final(&mut self, journal: &Journal, action: Action) -> Result<(), Code>;
    fn mark_disabled(&mut self, journal: &mut Journal) -> Result<(), Code>;
    fn persist(&mut self, record: &ActiveRecord) -> Result<(), Code>;
}
fn persist_phase(a: &mut impl Adapter, r: &mut ActiveRecord, phase: Phase) -> Result<(), Code> {
    let old = r.clone();
    r.phase = phase;
    if a.persist(r).is_err() {
        *r = old;
        return Err(Code::Storage);
    }
    Ok(())
}
fn fail(a: &mut impl Adapter, r: &mut ActiveRecord, code: Code) -> Result<Outcome, Code> {
    let old = r.clone();
    r.failed_phase = Some(r.phase);
    r.phase = Phase::Error;
    r.error_code = Some(code.as_str().into());
    if a.persist(r).is_err() {
        *r = old;
        return Err(Code::Storage);
    }
    Err(code)
}
/// A single durable operation. The caller holds the mutation lock throughout;
/// the adapter implements only typed, fixed operations, never caller commands.
pub fn process(
    j: &mut Journal,
    r: &mut ActiveRecord,
    a: &mut impl Adapter,
) -> Result<Outcome, Code> {
    if !r.valid_for(j) {
        return Err(Code::Invalid);
    }
    if r.phase == Phase::Completed {
        return r.outcome.ok_or(Code::Invalid);
    }
    // A RECOVERY code is a transient command or I/O failure of an owned step;
    // every kind resumes from that step, at most twice (decision 025). Without
    // this an owner Disable that failed once stayed in Error and Stop was BUSY.
    let retry = r.phase == Phase::Error
        && matches!(
            r.kind,
            Kind::CoreFailed | Kind::ReconcileRequested | Kind::DisableRequested
        )
        && r.error_code.as_deref() == Some(Code::Recovery.as_str())
        && r.retry_failures.len() < 2
        && r.failed_phase.is_some_and(|p| {
            matches!(
                p,
                Phase::Intent
                    | Phase::NftDone
                    | Phase::RoutingDone
                    | Phase::BaselineDone
                    | Phase::Verified
            )
        });
    if r.phase == Phase::Error && !retry {
        return Err(Code::Recovery);
    }
    match a.same_boot(j) {
        Ok(true) => (),
        Ok(false) if retry => return Err(Code::Unavailable),
        Err(e) if retry => return Err(e),
        Ok(false) => return fail(a, r, Code::Unavailable),
        Err(e) => return fail(a, r, e),
    }
    if retry {
        let old = r.clone();
        let phase = r.failed_phase.ok_or(Code::Invalid)?;
        r.retry_failures.push(RetryFailure {
            phase,
            code: Code::Recovery.as_str().into(),
        });
        r.phase = phase;
        r.failed_phase = None;
        r.error_code = None;
        if a.persist(r).is_err() {
            *r = old;
            return Err(Code::Storage);
        }
    }
    if r.phase == Phase::Requested {
        let action = match r.kind {
            Kind::DisableRequested => Action::Disable,
            Kind::CoreFailed => match a.observe_core(j) {
                Ok(CoreHealth::Failed) => {
                    match active_manifest(j).ok_or(Code::Invalid)?.failure_policy {
                        FailurePolicy::DirectOnFailure => Action::Direct,
                        FailurePolicy::BlockSelectedOnFailure => Action::Block,
                    }
                }
                Ok(CoreHealth::Healthy) => return fail(a, r, Code::Health),
                Err(e) => return fail(a, r, e),
            },
            Kind::ReconcileRequested => match a.observe_core(j) {
                Ok(CoreHealth::Healthy) => match a.restore_admissible(j) {
                    Ok(true) => Action::Restore,
                    Ok(false) => Action::Direct,
                    Err(e) => return fail(a, r, e),
                },
                Ok(CoreHealth::Failed) => return fail(a, r, Code::Health),
                Err(e) => return fail(a, r, e),
            },
        };
        r.action = Some(action);
        if let Err(e) = persist_phase(a, r, Phase::Intent) {
            r.action = None;
            return Err(e);
        }
    }
    let action = r.action.ok_or(Code::Invalid)?;
    if r.phase == Phase::Intent {
        if let Err(e) = a.secure_nft(j, action) {
            return fail(a, r, e);
        }
        persist_phase(a, r, Phase::NftDone)?;
    }
    if r.phase == Phase::NftDone {
        if let Err(e) = a.reconcile_routes(j, action) {
            return fail(a, r, e);
        }
        persist_phase(a, r, Phase::RoutingDone)?;
    }
    if r.phase == Phase::RoutingDone {
        let result = match action {
            Action::Restore => a.finish_interception(j, action),
            Action::Disable => a.restore_baseline(j),
            _ => Ok(()),
        };
        if let Err(e) = result {
            return fail(a, r, e);
        }
        persist_phase(a, r, Phase::BaselineDone)?;
    }
    if r.phase == Phase::BaselineDone {
        if let Err(e) = a.verify_final(j, action) {
            return fail(a, r, e);
        }
        persist_phase(a, r, Phase::Verified)?;
    }
    if r.phase == Phase::Verified {
        // Re-verify on replay: the previous proof can become stale after a crash.
        if let Err(e) = a.verify_final(j, action) {
            return fail(a, r, e);
        }
        if action == Action::Disable
            && let Err(e) = a.mark_disabled(j)
        {
            return fail(a, r, e);
        }
        let outcome = match action {
            Action::Direct => Outcome::Direct,
            Action::Block => Outcome::Blocked,
            Action::Restore => Outcome::Restored,
            Action::Disable => Outcome::Disabled,
        };
        let old = r.clone();
        r.phase = Phase::Completed;
        r.outcome = Some(outcome);
        if a.persist(r).is_err() {
            *r = old;
            return Err(Code::Storage);
        }
        return Ok(outcome);
    }
    Err(Code::Invalid)
}
