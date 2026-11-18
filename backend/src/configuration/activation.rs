//! A candidate is the exact prepared byte sequence validated for one profile revision.
use super::{ConfigError, ConfigStore, MAX_PROFILE_BYTES, PrepareError, prepare::activation_yaml};
use serde::Serialize;
mod payload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    Conflict,
    Invalid,
    Unavailable,
    Storage,
    CommitUncertain,
    CoreRejected,
    ValidatorUnavailable,
    CoreMissing,
    CoreIntegrity,
}

pub trait Validator {
    fn validate(&self, config: &str) -> Result<(), ActivationError>;
    fn validate_assets(&self, config: &str, assets: &[profile_policy::Asset]) -> Result<(), ActivationError> {
        if !assets.is_empty() {
            return Err(ActivationError::Unavailable);
        }
        self.validate(config)
    }
    fn validate_overlay(
        &self, config: &str, assets: &[profile_policy::Asset], overlay: &profile_policy::ManagedOverlay,
    ) -> Result<(), ActivationError> {
        if !matches!(overlay, profile_policy::ManagedOverlay::Manual) {
            return Err(ActivationError::Unavailable);
        }
        self.validate_assets(config, assets)
    }
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct ValidatedCandidate {
    pub candidate_id: String,
    pub profile_id: String,
    pub revision: String,
    pub status: String,
}
#[derive(Clone)]
struct Candidate {
    meta: ValidatedCandidate,
    bytes: String,
    assets: Vec<profile_policy::Asset>,
    overlay: profile_policy::ManagedOverlay,
    source: Option<Box<Candidate>>,
}
/// Validated bytes are held privately and are never serialized into HTTP responses.
#[derive(Clone)]
pub struct ValidatedBundle {
    pub(crate) meta: ValidatedCandidate,
    pub(crate) config: String,
    pub(crate) assets: Vec<profile_policy::Asset>,
    pub(crate) overlay: profile_policy::ManagedOverlay,
}
impl ValidatedBundle {
    /// Payload bytes and provider count the next snapshot of this bundle
    /// will hold; the same numbers whether the bundle is the applied
    /// profile or a validated candidate about to replace it.
    pub(crate) fn footprint(&self) -> (u64, usize) {
        let bytes = self.config.len() as u64 + self.assets.iter().map(|a| a.content.len() as u64).sum::<u64>();
        (
            bytes,
            crate::mihomo::providers::metadata::applied(&self.config, &self.assets).len(),
        )
    }
}
pub(crate) struct ManualApplyRequest {
    pub bundle: ValidatedBundle,
    pub profile_id: String,
    pub revision: String,
    pub candidate_id: String,
    pub idempotency_key: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct AppliedStatus {
    pub profile_id: String,
    pub revision: String,
    pub provider_metadata: Vec<crate::mihomo::providers::metadata::AppliedProvider>,
    pub payload_bytes: u64,
}
pub struct Activation<V> {
    store: ConfigStore,
    validator: V,
    secret: String,
    candidate: Option<Candidate>,
}
impl<V: Validator> Activation<V> {
    /// Display metadata only. A successful read does not authorize Start/restore.
    pub fn applied_status(&self, dir: &std::path::Path) -> Result<AppliedStatus, ActivationError> {
        let journal = journal_metadata(dir)?;
        if journal.pending.is_some() {
            return Err(ActivationError::Conflict);
        }
        let saved = journal.current.ok_or(ActivationError::Conflict)?;
        let payload_bytes = saved
            .payload
            .as_ref()
            .map(|p| p.files.iter().map(|f| f.bytes).sum())
            .unwrap_or(
                saved.config.len() as u64
                    + saved
                        .assets
                        .iter()
                        .map(|a| (a.content_base64.len() as u64).saturating_mul(3) / 4)
                        .sum::<u64>(),
            );
        let provider_metadata = match saved.provider_metadata {
            Some(metadata) => metadata,
            None => crate::mihomo::providers::metadata::applied(&saved.config, &[]),
        };
        Ok(AppliedStatus {
            profile_id: saved.profile_id,
            revision: saved.tx.revision,
            provider_metadata,
            payload_bytes,
        })
    }
    /// Call only under the mutation lock after verifying the package-compatible
    /// persistent supervisor incarnation. Never invoked from status or preflight.
    pub(crate) fn migrate_payloads_after_handoff(&self, dir: &std::path::Path) -> Result<(), ActivationError> {
        let mut journal = journal_read(dir)?;
        // History files are independently atomic: an interruption leaves each
        // legacy record or a complete new reference, while the root stays v1.
        let history = dir.join("history");
        if history.try_exists().map_err(|_| ActivationError::Storage)? {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(&history).map_err(|_| ActivationError::Storage)?;
            if !m.is_dir()
                || m.file_type().is_symlink()
                || m.uid() != unsafe { nix::libc::geteuid() }
                || m.mode() & 0o077 != 0
            {
                return Err(ActivationError::Storage);
            }
            for (i, entry) in std::fs::read_dir(&history)
                .map_err(|_| ActivationError::Storage)?
                .enumerate()
            {
                if i >= 128 {
                    return Err(ActivationError::Storage);
                }
                let entry = entry.map_err(|_| ActivationError::Storage)?;
                let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
                if !name
                    .strip_suffix(".json")
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id))
                {
                    continue;
                }
                let saved: Saved = serde_json::from_slice(&read_private(&entry.path(), JOURNAL_LIMIT)?)
                    .map_err(|_| ActivationError::Storage)?;
                if let Some(reference) = &saved.payload {
                    payload::read(dir, reference)?;
                    continue;
                }
                let compact = payload::compact(dir, &saved)?;
                atomic_replace(
                    dir,
                    &entry.path(),
                    &serde_json::to_vec(&compact).map_err(|_| ActivationError::Storage)?,
                )?;
            }
        }
        if journal.version == 1 {
            journal.version = 2;
            journal_write(dir, &journal)?;
        }
        payload::gc(dir)
    }
    /// Settle journal-only manual work after lifecycle cleanup. This discards
    /// interrupted intent without calling ManualCore or honoring restore_running.
    pub(crate) fn settle_stopped_manual(&self, dir: &std::path::Path) -> Result<(), ActivationError> {
        let mut journal = journal_read(dir)?;
        if journal.pending.is_some() {
            journal.pending = None;
            journal_write(dir, &journal)?;
        }
        Ok(())
    }
    /// Upgrade wrapper keeps its existing lifecycle-specific call site.
    pub(crate) fn settle_after_upgrade(&self, dir: &std::path::Path) -> Result<(), ActivationError> {
        self.settle_stopped_manual(dir)
    }
    pub(crate) fn repeated_transaction(
        &self, dir: &std::path::Path, id: &str, revision: &str, candidate_id: &str, key: &str,
    ) -> Result<Option<ManualTransaction>, ActivationError> {
        let journal = journal_read(dir)?;
        if journal.pending.is_some() {
            return Err(ActivationError::Unavailable);
        }
        let Some(saved) = journal.current else {
            return Ok(None);
        };
        if saved.key != key {
            return Ok(None);
        }
        if saved.profile_id != id || saved.tx.revision != revision || saved.candidate_id != candidate_id {
            return Err(ActivationError::Conflict);
        }
        Ok(Some(saved.tx))
    }
    /// Stop only the fixed core without reading or repairing a damaged journal.
    pub fn emergency_stop(&self, core: &mut impl ManualCore) -> Result<(), ActivationError> {
        core.emergency_stop()
    }
    pub(crate) fn current_manual_bundle(&self, dir: &std::path::Path) -> Result<ValidatedBundle, ActivationError> {
        let journal = journal_read(dir)?;
        if journal.pending.is_some() {
            return Err(ActivationError::Conflict);
        }
        let saved = journal.current.ok_or(ActivationError::Conflict)?;
        let assets = saved.bundle()?;
        Ok(ValidatedBundle {
            meta: ValidatedCandidate {
                candidate_id: saved.candidate_id,
                profile_id: saved.profile_id,
                revision: saved.tx.revision,
                status: "valid".into(),
            },
            config: saved.config,
            assets,
            overlay: profile_policy::ManagedOverlay::Manual,
        })
    }
    pub(crate) fn current_provider_asset(
        &self, dir: &std::path::Path, id: &str, revision: &str, provider_id: &str,
    ) -> Result<String, ActivationError> {
        let bundle = self.current_manual_bundle(dir)?;
        if bundle.meta.profile_id != id
            || bundle.meta.revision != revision
            || self.store.read(id).map_err(map_config)?.revision != revision
        {
            return Err(ActivationError::Conflict);
        }
        let path = provider_asset_path(provider_id)?;
        let asset = bundle
            .assets
            .iter()
            .find(|asset| asset.path == path)
            .ok_or(ActivationError::Conflict)?;
        String::from_utf8(asset.content.clone()).map_err(|_| ActivationError::Invalid)
    }
    pub fn new(store: ConfigStore, validator: V, secret: String) -> Self {
        Self {
            store,
            validator,
            secret,
            candidate: None,
        }
    }
    /// Drop an in-memory validation result when its editor session is cancelled or superseded.
    pub fn discard_candidate(&mut self) {
        self.candidate = None;
    }
    pub fn cancel_candidate(&mut self, id: &str, revision: &str, candidate_id: &str) {
        let belongs = self.candidate.as_ref().is_some_and(|candidate| {
            let matches = |meta: &ValidatedCandidate| {
                meta.profile_id == id && meta.revision == revision && meta.candidate_id == candidate_id
            };
            matches(&candidate.meta) || candidate.source.as_deref().is_some_and(|source| matches(&source.meta))
        });
        if belongs {
            self.candidate = None;
        }
    }
    pub fn validate(&mut self, id: &str, revision: &str) -> Result<ValidatedCandidate, ActivationError> {
        self.validate_with_loader(id, revision, |_| Err(ActivationError::Unavailable))
    }
    pub fn validate_with_loader(
        &mut self, id: &str, revision: &str,
        loader: impl FnOnce(&str) -> Result<(String, Vec<profile_policy::Asset>), ActivationError>,
    ) -> Result<ValidatedCandidate, ActivationError> {
        self.candidate = None;
        let preview = self.store.prepare(id, revision).map_err(map_prepare)?;
        if preview.diagnostics.iter().any(|d| d.code != "PROVIDER_UNRESOLVED") {
            return Err(ActivationError::Invalid);
        }
        let raw = activation_yaml(&preview, &self.secret).map_err(map_prepare)?;
        let (bytes, assets) = if preview.diagnostics.is_empty() {
            (raw, Vec::new())
        } else {
            loader(&raw)?
        };
        if bytes.len() > MAX_PROFILE_BYTES || !profile_policy::complete(&bytes, &assets) {
            return Err(ActivationError::Invalid);
        }
        self.validator.validate_assets(&bytes, &assets)?;
        if self.store.read(id).map_err(map_config)?.revision != revision {
            return Err(ActivationError::Conflict);
        }
        let meta = ValidatedCandidate {
            candidate_id: uuid::Uuid::new_v4().to_string(),
            profile_id: id.into(),
            revision: revision.into(),
            status: "valid".into(),
        };
        self.candidate = Some(Candidate {
            meta: meta.clone(),
            bytes,
            assets,
            overlay: profile_policy::ManagedOverlay::Manual,
            source: None,
        });
        Ok(meta)
    }
    pub fn check_candidate(&self, id: &str, revision: &str, candidate_id: &str) -> Result<(), ActivationError> {
        let c = self.candidate.as_ref().ok_or(ActivationError::Conflict)?;
        if c.meta.profile_id != id
            || c.meta.revision != revision
            || c.meta.candidate_id != candidate_id
            || self.store.read(id).map_err(map_config)?.revision != revision
        {
            return Err(ActivationError::Conflict);
        }
        Ok(())
    }
    pub fn prior_assets(&self, id: &str, revision: &str) -> Result<Vec<profile_policy::Asset>, ActivationError> {
        let c = self
            .find_candidate_by_profile(id, revision)
            .ok_or(ActivationError::Conflict)?;
        if c.meta.profile_id != id
            || c.meta.revision != revision
            || self.store.read(id).map_err(map_config)?.revision != revision
            || !matches!(c.overlay, profile_policy::ManagedOverlay::Manual)
        {
            return Err(ActivationError::Conflict);
        }
        Ok(c.assets.clone())
    }
    pub fn candidate_bundle(
        &self, id: &str, revision: &str, candidate_id: &str,
    ) -> Result<ValidatedBundle, ActivationError> {
        let c = self.find_candidate(candidate_id).ok_or(ActivationError::Conflict)?;
        if c.meta.profile_id != id
            || c.meta.revision != revision
            || c.meta.candidate_id != candidate_id
            || self.store.read(id).map_err(map_config)?.revision != revision
        {
            return Err(ActivationError::Conflict);
        }
        Ok(ValidatedBundle {
            meta: c.meta.clone(),
            config: c.bytes.clone(),
            assets: c.assets.clone(),
            overlay: c.overlay.clone(),
        })
    }
    fn find_candidate(&self, candidate_id: &str) -> Option<&Candidate> {
        let candidate = self.candidate.as_ref()?;
        if candidate.meta.candidate_id == candidate_id {
            Some(candidate)
        } else {
            candidate
                .source
                .as_deref()
                .filter(|source| source.meta.candidate_id == candidate_id)
        }
    }
    fn find_candidate_by_profile(&self, id: &str, revision: &str) -> Option<&Candidate> {
        let candidate = self.candidate.as_ref()?;
        let manual = if matches!(candidate.overlay, profile_policy::ManagedOverlay::Manual) {
            candidate
        } else {
            candidate.source.as_deref()?
        };
        (manual.meta.profile_id == id && manual.meta.revision == revision).then_some(manual)
    }
    pub(crate) fn with_candidate<T>(
        &self, id: &str, revision: &str, candidate_id: &str,
        f: impl FnOnce(ValidatedBundle) -> Result<T, ActivationError>,
    ) -> Result<T, ActivationError> {
        let c = self.candidate.as_ref().ok_or(ActivationError::Conflict)?;
        if c.meta.profile_id != id || c.meta.revision != revision || c.meta.candidate_id != candidate_id {
            return Err(ActivationError::Conflict);
        }
        let bundle = ValidatedBundle {
            meta: c.meta.clone(),
            config: c.bytes.clone(),
            assets: c.assets.clone(),
            overlay: c.overlay.clone(),
        };
        self.store
            .with_revision(id, revision, || f(bundle))
            .map_err(map_config)?
    }
    /// Reuse the exact committed provider snapshot for service Start. Never
    /// redownload a subscription or apply an unsaved editor revision here.
    /// Explicit read-only compatibility check; unlike display status, verifies
    /// exact payload and the accepted editor revision on this observation.
    pub fn verified_applied_status(&self, dir: &std::path::Path) -> Result<AppliedStatus, ActivationError> {
        let bundle = self.preflight_bundle(dir)?;
        Ok(AppliedStatus {
            payload_bytes: bundle.footprint().0,
            provider_metadata: crate::mihomo::providers::metadata::applied(&bundle.config, &bundle.assets),
            profile_id: bundle.meta.profile_id,
            revision: bundle.meta.revision,
        })
    }
    pub(crate) fn preflight_bundle(&self, dir: &std::path::Path) -> Result<ValidatedBundle, ActivationError> {
        let bundle = self.current_manual_bundle(dir)?;
        if self.store.read(&bundle.meta.profile_id).map_err(map_config)?.revision != bundle.meta.revision {
            return Err(ActivationError::Conflict);
        }
        Ok(bundle)
    }
    pub(crate) fn stage_committed(&mut self, dir: &std::path::Path) -> Result<ValidatedCandidate, ActivationError> {
        let bundle = self.preflight_bundle(dir)?;
        self.revalidate_bundle(&bundle)?;
        let meta = bundle.meta.clone();
        self.candidate = Some(Candidate {
            meta: meta.clone(),
            bytes: bundle.config,
            assets: bundle.assets,
            overlay: bundle.overlay,
            source: None,
        });
        Ok(meta)
    }
    pub(crate) fn compose_bundle(
        &self, base: &ValidatedBundle, inputs: profile_policy::InputsOverlay,
    ) -> Result<ValidatedBundle, ActivationError> {
        let config = profile_policy::compose_inputs(&base.config, &base.assets, &inputs)
            .map_err(|_| ActivationError::Invalid)?;
        let bundle = ValidatedBundle {
            meta: base.meta.clone(),
            config,
            assets: base.assets.clone(),
            overlay: profile_policy::ManagedOverlay::Composite(inputs),
        };
        self.revalidate_bundle(&bundle)?;
        Ok(bundle)
    }
    /// The network journal is the commit decision for this profile intent.
    /// Recovery finalizes only an exact confirmed tx; rollback discards it.
    pub(crate) fn stage_network_acceptance(
        &self, dir: &std::path::Path, bundle: &ValidatedBundle, tx: &str, key: &str,
    ) -> Result<(), ActivationError> {
        if !matches!(bundle.overlay, profile_policy::ManagedOverlay::Manual) || uuid::Uuid::parse_str(tx).is_err() {
            return Err(ActivationError::Invalid);
        }
        self.store
            .with_revision(&bundle.meta.profile_id, &bundle.meta.revision, || {
                let mut journal = journal_read(dir)?;
                if let Some(p) = &journal.pending {
                    if p.network_tx_id.as_deref() == Some(tx) && p.candidate_id == bundle.meta.candidate_id {
                        return Ok(());
                    }
                    return Err(ActivationError::Conflict);
                }
                use base64::Engine;
                if let Some(previous) = &journal.current {
                    snapshot_previous(dir, previous)?;
                }
                journal.pending = Some(Saved {
                    tx: ManualTransaction {
                        id: tx.into(),
                        state: "committed".into(),
                        revision: bundle.meta.revision.clone(),
                    },
                    profile_id: bundle.meta.profile_id.clone(),
                    candidate_id: bundle.meta.candidate_id.clone(),
                    key: key.into(),
                    config: bundle.config.clone(),
                    assets: bundle
                        .assets
                        .iter()
                        .map(|a| SavedAsset {
                            path: a.path.clone(),
                            content_base64: base64::engine::general_purpose::STANDARD.encode(&a.content),
                        })
                        .collect(),
                    payload: None,
                    provider_metadata: None,
                    restore_running: false,
                    network_tx_id: Some(tx.into()),
                });
                journal_write(dir, &journal)
            })
            .map_err(map_config)?
    }
    pub(crate) fn settle_network_profile(&self, dir: &std::path::Path) -> Result<(), ActivationError> {
        let mut journal = journal_read(dir)?;
        if let Some(pending) = &journal.pending
            && pending.network_tx_id.is_some()
        {
            match profile_decision(dir, pending)? {
                Some(true) => {
                    journal.current = journal.pending.take();
                    journal_write(dir, &journal)?;
                }
                Some(false) => {
                    journal.pending = None;
                    journal_write(dir, &journal)?;
                }
                None => (),
            }
        }
        Ok(())
    }
    pub(crate) fn finish_network_acceptance(&self, dir: &std::path::Path, tx: &str) -> Result<(), ActivationError> {
        let mut journal = journal_read(dir)?;
        if let Some(p) = &journal.pending {
            if p.network_tx_id.as_deref() != Some(tx) {
                return Err(ActivationError::Conflict);
            }
            if profile_decision(dir, p)? != Some(true) {
                return Err(ActivationError::Conflict);
            }
            journal.current = journal.pending.take();
            journal_write(dir, &journal)?;
        }
        Ok(())
    }
    pub fn validate_network(
        &mut self, id: &str, revision: &str, manual_candidate_id: &str, network: profile_policy::NetworkOverlay,
    ) -> Result<ValidatedCandidate, ActivationError> {
        self.validate_network_inputs(id, revision, manual_candidate_id, network, None)
    }
    pub(crate) fn validate_network_inputs(
        &mut self, id: &str, revision: &str, manual_candidate_id: &str, network: profile_policy::NetworkOverlay,
        explicit: Option<profile_policy::ExplicitOverlay>,
    ) -> Result<ValidatedCandidate, ActivationError> {
        let bundle = self.candidate_bundle(id, revision, manual_candidate_id)?;
        if !matches!(bundle.overlay, profile_policy::ManagedOverlay::Manual) {
            return Err(ActivationError::Conflict);
        }
        let source = self
            .find_candidate(manual_candidate_id)
            .ok_or(ActivationError::Conflict)?
            .clone();
        let inputs = profile_policy::InputsOverlay {
            explicit,
            gateway: Some(network),
        };
        let bytes = profile_policy::compose_inputs(&bundle.config, &bundle.assets, &inputs)
            .map_err(|_| ActivationError::Invalid)?;
        let overlay = profile_policy::ManagedOverlay::Composite(inputs);
        if bytes.len() > MAX_PROFILE_BYTES || !profile_policy::complete_for(&bytes, &bundle.assets, &overlay) {
            return Err(ActivationError::Invalid);
        }
        self.validator.validate_overlay(&bytes, &bundle.assets, &overlay)?;
        if self.store.read(id).map_err(map_config)?.revision != revision {
            return Err(ActivationError::Conflict);
        }
        let meta = ValidatedCandidate {
            candidate_id: uuid::Uuid::new_v4().to_string(),
            profile_id: id.into(),
            revision: revision.into(),
            status: "valid".into(),
        };
        self.candidate = Some(Candidate {
            meta: meta.clone(),
            bytes,
            assets: bundle.assets,
            overlay,
            source: Some(Box::new(source)),
        });
        Ok(meta)
    }
}

/// Resolve the durable network decision, including a retired exact journal.
/// A Disabled state alone never grants acceptance of an unconfirmed profile.
fn profile_decision(dir: &std::path::Path, saved: &Saved) -> Result<Option<bool>, ActivationError> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let tx = saved.network_tx_id.as_deref().ok_or(ActivationError::Invalid)?;
    if !uuid::Uuid::parse_str(tx).is_ok_and(|id| id.to_string() == tx) {
        return Err(ActivationError::Storage);
    }
    let read = |path: &std::path::Path| -> Result<xkeenwrt_recovery::Journal, ActivationError> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| ActivationError::Storage)?;
        let m = f.metadata().map_err(|_| ActivationError::Storage)?;
        if !m.is_file()
            || m.uid() != unsafe { nix::libc::geteuid() }
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
            || m.len() > 1_048_576
        {
            return Err(ActivationError::Storage);
        }
        let mut bytes = Vec::new();
        f.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| ActivationError::Storage)?;
        let j: xkeenwrt_recovery::Journal = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Storage)?;
        if j.decision(&j.boot_id, j.created_boottime_ms, false) == xkeenwrt_recovery::Decision::Invalid {
            return Err(ActivationError::Storage);
        }
        Ok(j)
    };
    let current = read(&dir.join("recovery.json"))?;
    let network = if current.tx_id == tx {
        current
    } else {
        read(&dir.join("network-history").join(format!("{tx}.json")))?
    };
    if network.tx_id != tx
        || network.profile_id != saved.profile_id
        || network.revision != saved.tx.revision
        || network.idempotency_key != saved.key
    {
        return Err(ActivationError::Conflict);
    }
    if let Some(decision) = network.profile_acceptance {
        if decision.candidate_id != saved.candidate_id {
            return Err(ActivationError::Conflict);
        }
        return Ok(Some(true));
    }
    match network.state {
        xkeenwrt_recovery::State::RolledBack | xkeenwrt_recovery::State::Disabled => Ok(Some(false)),
        xkeenwrt_recovery::State::Pending | xkeenwrt_recovery::State::Revoked => Ok(None),
        _ => Err(ActivationError::Conflict),
    }
}
fn provider_asset_path(provider_id: &str) -> Result<String, ActivationError> {
    let (kind, index) = provider_id.split_once('-').ok_or(ActivationError::Invalid)?;
    let directory = match kind {
        "proxy" => "proxies",
        "rule" => "rules",
        _ => return Err(ActivationError::Invalid),
    };
    let parsed = index.parse::<u8>().map_err(|_| ActivationError::Invalid)?;
    if parsed.to_string() != index || usize::from(parsed) >= profile_policy::MAX_PROVIDER_FILES {
        return Err(ActivationError::Invalid);
    }
    Ok(format!("providers/{directory}/{parsed}.yaml"))
}

#[cfg(test)]
mod lifecycle_settlement_tests {
    use super::*;

    struct Accept;
    impl Validator for Accept {
        fn validate(&self, _: &str) -> Result<(), ActivationError> {
            Ok(())
        }
    }

    fn saved(profile_id: &str, config: &str, restore_running: bool) -> Saved {
        Saved {
            tx: ManualTransaction {
                id: "00000000-0000-4000-8000-000000000009".into(),
                state: "committed".into(),
                revision: "revision".into(),
            },
            profile_id: profile_id.into(),
            candidate_id: "candidate".into(),
            key: "key".into(),
            config: config.into(),
            assets: Vec::new(),
            payload: None,
            provider_metadata: None,
            restore_running,
            network_tx_id: None,
        }
    }

    #[test]
    fn stopped_lifecycle_settlement_discards_pending_restore_without_touching_current() {
        let dir = std::env::temp_dir().join(format!("xkeen-settle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = ConfigStore::new(dir.join("profiles")).unwrap();
        let activation = Activation::new(store, Accept, "synthetic-secret".into());
        let current = saved("home", "mode: rule\n", false);
        let pending = saved("home", "mode: direct\n", true);
        journal_write(
            &dir,
            &Journal {
                version: 1,
                current: Some(current.clone()),
                pending: Some(pending),
            },
        )
        .unwrap();

        activation.settle_stopped_manual(&dir).unwrap();

        let settled = journal_read(&dir).unwrap();
        assert!(settled.pending.is_none());
        assert_eq!(settled.current.unwrap().config, current.config);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
fn map_config(error: ConfigError) -> ActivationError {
    match error {
        ConfigError::Conflict | ConfigError::NotFound => ActivationError::Conflict,
        ConfigError::InvalidId | ConfigError::InvalidYaml | ConfigError::TooLarge => ActivationError::Invalid,
        _ => ActivationError::Storage,
    }
}
fn map_prepare(error: PrepareError) -> ActivationError {
    match error {
        PrepareError::Config(e) => map_config(e),
        _ => ActivationError::Invalid,
    }
}

/// The core adapter must publish only the supplied bytes and return success only after local health succeeds.
pub trait ManualCore {
    fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError>;
    fn emergency_stop(&mut self) -> Result<(), ActivationError> {
        self.replace_assets(None, &[])
    }
    fn running(&self) -> Result<bool, ActivationError>;
    fn can_apply(&self) -> Result<(), ActivationError> {
        Ok(())
    }
    fn admit(
        &self, _bundle_bytes: u64, _flash_staging_bytes: u64, _history_staging_bytes: u64,
    ) -> Result<(), ActivationError> {
        Ok(())
    }
    fn check_fence(&self) -> Result<(), ActivationError> {
        Ok(())
    }
    fn replace_assets(
        &mut self, config: Option<&str>, assets: &[profile_policy::Asset],
    ) -> Result<(), ActivationError> {
        if !assets.is_empty() {
            return Err(ActivationError::Unavailable);
        }
        self.replace(config)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManualTransaction {
    pub id: String,
    pub state: String,
    pub revision: String,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    tx: ManualTransaction,
    profile_id: String,
    candidate_id: String,
    key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    config: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    assets: Vec<SavedAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<payload::PayloadRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_metadata: Option<Vec<crate::mihomo::providers::metadata::AppliedProvider>>,
    #[serde(default)]
    restore_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_tx_id: Option<String>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAsset {
    path: String,
    content_base64: String,
}
impl Saved {
    fn bundle(&self) -> Result<Vec<profile_policy::Asset>, ActivationError> {
        use base64::Engine;
        if self.assets.len() > profile_policy::MAX_PROVIDER_FILES
            || self.assets.iter().map(|a| a.content_base64.len()).sum::<usize>() > 12 * 1024 * 1024
        {
            return Err(ActivationError::Storage);
        }
        let assets: Vec<_> = self
            .assets
            .iter()
            .map(|a| {
                let content = base64::engine::general_purpose::STANDARD
                    .decode(&a.content_base64)
                    .map_err(|_| ActivationError::Storage)?;
                Ok(profile_policy::Asset {
                    path: a.path.clone(),
                    content,
                })
            })
            .collect::<Result<_, ActivationError>>()?;
        if !profile_policy::complete(&self.config, &assets) {
            return Err(ActivationError::Storage);
        }
        Ok(assets)
    }
}
const JOURNAL_LIMIT: usize = 26 * 1024 * 1024;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    current: Option<Saved>,
    pending: Option<Saved>,
}
impl Journal {
    fn empty() -> Self {
        Self {
            version: 2,
            current: None,
            pending: None,
        }
    }
}
fn read_private(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, ActivationError> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ActivationError::Storage)?;
    let m = f.metadata().map_err(|_| ActivationError::Storage)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > limit as u64
    {
        return Err(ActivationError::Storage);
    }
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActivationError::Storage)?;
    if bytes.len() > limit {
        return Err(ActivationError::Storage);
    }
    Ok(bytes)
}
fn journal_metadata(dir: &std::path::Path) -> Result<Journal, ActivationError> {
    let path = dir.join("transaction.json");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Journal::empty()),
        Err(_) => return Err(ActivationError::Storage),
        Ok(_) => (),
    }
    let bytes = read_private(&path, JOURNAL_LIMIT)?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Storage)?;
    if ![1, 2].contains(&journal.version) || (journal.version == 2 && bytes.len() > 65_536) {
        return Err(ActivationError::Storage);
    }
    for saved in [&journal.current, &journal.pending].into_iter().flatten() {
        if journal.version == 2
            && (!saved.config.is_empty()
                || !saved.assets.is_empty()
                || saved.provider_metadata.is_none()
                || saved.payload.as_ref().is_none_or(|p| !p.valid()))
        {
            return Err(ActivationError::Storage);
        }
        if journal.version == 1 && saved.payload.is_some() {
            return Err(ActivationError::Storage);
        }
    }
    Ok(journal)
}
fn journal_read(dir: &std::path::Path) -> Result<Journal, ActivationError> {
    let mut journal = journal_metadata(dir)?;
    for saved in [&mut journal.current, &mut journal.pending].into_iter().flatten() {
        if let Some(reference) = &saved.payload {
            let (config, assets) = payload::read(dir, reference)?;
            saved.config = config;
            saved.assets = assets;
            saved.bundle()?;
        }
    }
    Ok(journal)
}
fn journal_write(dir: &std::path::Path, journal: &Journal) -> Result<(), ActivationError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir).map_err(|_| ActivationError::Storage)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { nix::libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(ActivationError::Storage);
    }
    if journal.version == 2 {
        payload::gc(dir)?;
    }
    let mut disk = journal.clone();
    if disk.version == 2 {
        for saved in [&mut disk.current, &mut disk.pending].into_iter().flatten() {
            *saved = payload::compact(dir, saved)?;
        }
    }
    let bytes = serde_json::to_vec(&disk).map_err(|_| ActivationError::Storage)?;
    if bytes.len() > JOURNAL_LIMIT {
        return Err(ActivationError::Storage);
    }
    let directory = std::fs::File::open(dir).map_err(|_| ActivationError::Storage)?;
    let space = rustix::fs::fstatvfs(&directory).map_err(|_| ActivationError::Storage)?;
    if space.f_bavail.saturating_mul(space.f_frsize) < 8 * 1024 * 1024 + bytes.len() as u64 {
        return Err(ActivationError::Storage);
    }
    atomic_replace(dir, &dir.join("transaction.json"), &bytes)
}
fn atomic_replace(dir: &std::path::Path, target: &std::path::Path, bytes: &[u8]) -> Result<(), ActivationError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let parent = target.parent().ok_or(ActivationError::Storage)?;
    let name = parent.join(format!(".journal-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&name)
            .map_err(|_| ActivationError::Storage)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ActivationError::Storage)?;
        std::fs::rename(&name, target).map_err(|_| ActivationError::Storage)?;
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| ActivationError::Storage)?;
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| ActivationError::Storage)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(name);
    }
    result
}

fn snapshot_previous(dir: &std::path::Path, previous: &Saved) -> Result<(), ActivationError> {
    use std::io::Read;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let history = dir.join("history");
    match std::fs::DirBuilder::new().mode(0o700).create(&history) {
        Ok(()) => std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| ActivationError::Storage)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(ActivationError::Storage),
    }
    let m = std::fs::symlink_metadata(&history).map_err(|_| ActivationError::Storage)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != unsafe { nix::libc::geteuid() } || m.mode() & 0o077 != 0
    {
        return Err(ActivationError::Storage);
    }
    if uuid::Uuid::parse_str(&previous.tx.id).is_err() {
        return Err(ActivationError::Storage);
    }
    let target_name = format!("{}.json", uuid::Uuid::new_v4());
    let target = history.join(&target_name);
    let mut count = 0;
    for entry in std::fs::read_dir(&history).map_err(|_| ActivationError::Storage)? {
        let entry = entry.map_err(|_| ActivationError::Storage)?;
        count += 1;
        if count > 128 {
            return Err(ActivationError::Storage);
        }
        let name = entry.file_name().into_string().map_err(|_| ActivationError::Storage)?;
        if name == target_name {
            continue;
        }
        if uuid::Uuid::parse_str(&name).is_ok()
            || name
                .strip_prefix(".stage-")
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        {
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| ActivationError::Storage)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { nix::libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(ActivationError::Storage);
            }
            continue;
        }
        let valid_snapshot = name
            .strip_suffix(".json")
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
            || name
                .strip_suffix(".yaml")
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
        let valid_stage = name
            .strip_prefix(".xkeenwrt-secret-")
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
        if !valid_snapshot && !valid_stage {
            return Err(ActivationError::Storage);
        }
    }
    let compact;
    let previous = if journal_metadata(dir)?.version == 2 {
        compact = payload::compact(dir, previous)?;
        &compact
    } else {
        previous
    };
    let snapshot = serde_json::to_vec(previous).map_err(|_| ActivationError::Storage)?;
    if snapshot.len() > JOURNAL_LIMIT / 2 {
        return Err(ActivationError::Storage);
    }
    match crate::private_file::publish_private(&target, &snapshot) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&target)
                .map_err(|_| ActivationError::Storage)?;
            let m = f.metadata().map_err(|_| ActivationError::Storage)?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != unsafe { nix::libc::geteuid() }
                || m.mode() & 0o077 != 0
                || m.len() > (JOURNAL_LIMIT / 2) as u64
            {
                return Err(ActivationError::Storage);
            }
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).map_err(|_| ActivationError::Storage)?;
            if bytes != snapshot {
                return Err(ActivationError::Storage);
            }
        }
        Err(_) => return Err(ActivationError::Storage),
    }
    std::fs::File::open(&history)
        .and_then(|f| f.sync_all())
        .map_err(|_| ActivationError::Storage)?;
    Ok(())
}
impl<V: Validator> Activation<V> {
    pub(crate) fn revalidate_bundle(&self, bundle: &ValidatedBundle) -> Result<(), ActivationError> {
        self.validator
            .validate_overlay(&bundle.config, &bundle.assets, &bundle.overlay)
    }
    pub fn start(&self, dir: &std::path::Path, core: &mut impl ManualCore) -> Result<(), ActivationError> {
        self.recover(dir, core)?;
        let journal = journal_read(dir)?;
        let active = journal.current.ok_or(ActivationError::Conflict)?;
        let assets = active.bundle()?;
        self.validator.validate_assets(&active.config, &assets)?;
        core.replace_assets(Some(&active.config), &assets)
    }
    pub fn stop(&self, dir: &std::path::Path, core: &mut impl ManualCore) -> Result<(), ActivationError> {
        self.recover(dir, core)?;
        if journal_read(dir)?.current.is_none() {
            return Err(ActivationError::Conflict);
        }
        core.replace(None)
    }
    /// Restores the last committed bytes after an interrupted apply before accepting another mutation.
    pub fn recover(&self, dir: &std::path::Path, core: &mut impl ManualCore) -> Result<(), ActivationError> {
        core.check_fence()?;
        let mut j = journal_read(dir)?;
        if let Some(pending) = &j.pending {
            if pending.network_tx_id.is_some() {
                match profile_decision(dir, pending)? {
                    Some(true) => {
                        j.current = j.pending.take();
                        journal_write(dir, &j)?;
                        return Ok(());
                    }
                    Some(false) => {
                        j.pending = None;
                        journal_write(dir, &j)?;
                        return Ok(());
                    }
                    None => return Err(ActivationError::Unavailable),
                }
            }
            if pending.restore_running {
                let previous = j.current.as_ref().ok_or(ActivationError::Storage)?;
                core.replace_assets(Some(&previous.config), &previous.bundle()?)?;
            } else {
                core.replace_assets(None, &[])?;
            }
            core.check_fence()?;
            j.pending = None;
            journal_write(dir, &j)?;
        }
        Ok(())
    }
    pub fn apply(
        &mut self, dir: &std::path::Path, core: &mut impl ManualCore, id: &str, revision: &str, candidate_id: &str,
        key: &str,
    ) -> Result<ManualTransaction, ActivationError> {
        if let Some(transaction) = self.repeated_transaction(dir, id, revision, candidate_id, key)? {
            return Ok(transaction);
        }
        let bundle = self
            .check_candidate(id, revision, candidate_id)
            .and_then(|()| self.candidate_bundle(id, revision, candidate_id));
        self.candidate = None;
        self.apply_bundle(
            dir,
            core,
            ManualApplyRequest {
                bundle: bundle?,
                profile_id: id.to_owned(),
                revision: revision.to_owned(),
                candidate_id: candidate_id.to_owned(),
                idempotency_key: key.to_owned(),
            },
        )
    }
    pub(crate) fn apply_bundle(
        &self, dir: &std::path::Path, core: &mut impl ManualCore, request: ManualApplyRequest,
    ) -> Result<ManualTransaction, ActivationError> {
        let ManualApplyRequest {
            bundle,
            profile_id,
            revision,
            candidate_id,
            idempotency_key,
        } = request;
        let (id, revision, candidate_id, key) = (
            profile_id.as_str(),
            revision.as_str(),
            candidate_id.as_str(),
            idempotency_key.as_str(),
        );
        core.check_fence()?;
        if key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ActivationError::Invalid);
        }
        self.recover(dir, core)?;
        let mut j = journal_read(dir)?;
        if let Some(saved) = &j.current
            && saved.key == key
        {
            return if saved.profile_id == id && saved.tx.revision == revision && saved.candidate_id == candidate_id {
                Ok(saved.tx.clone())
            } else {
                Err(ActivationError::Conflict)
            };
        }
        if bundle.meta.profile_id != id || bundle.meta.revision != revision || bundle.meta.candidate_id != candidate_id
        {
            return Err(ActivationError::Conflict);
        }
        if !matches!(bundle.overlay, profile_policy::ManagedOverlay::Manual) {
            return Err(ActivationError::Conflict);
        }
        self.store
            .with_revision(id, revision, || {
                core.can_apply()?;
                let restore_running = core.running()?;
                if restore_running && j.current.is_none() {
                    return Err(ActivationError::Unavailable);
                }
                let tx = ManualTransaction {
                    id: uuid::Uuid::new_v4().to_string(),
                    state: "committed".into(),
                    revision: revision.into(),
                };
                use base64::Engine;
                let next = Saved {
                    tx: tx.clone(),
                    profile_id: id.into(),
                    candidate_id: candidate_id.into(),
                    key: key.into(),
                    config: bundle.config.clone(),
                    assets: bundle
                        .assets
                        .iter()
                        .map(|a| SavedAsset {
                            path: a.path.clone(),
                            content_base64: base64::engine::general_purpose::STANDARD.encode(&a.content),
                        })
                        .collect(),
                    payload: None,
                    provider_metadata: None,
                    restore_running,
                    network_tx_id: None,
                };
                let previous_bytes = j
                    .current
                    .as_ref()
                    .map(|saved| {
                        let mut snapshot = saved.clone();
                        snapshot.restore_running = restore_running;
                        serde_json::to_vec(&snapshot)
                    })
                    .transpose()
                    .map_err(|_| ActivationError::Storage)?
                    .map_or(0, |v| v.len() as u64);
                j.pending = Some(next.clone());
                let journal_bytes = serde_json::to_vec(&j).map_err(|_| ActivationError::Storage)?.len() as u64;
                let mut committed = j.clone();
                committed.current = Some(next.clone());
                committed.pending = None;
                let committed_bytes = serde_json::to_vec(&committed)
                    .map_err(|_| ActivationError::Storage)?
                    .len() as u64;
                let bundle_bytes =
                    bundle.config.len() as u64 + bundle.assets.iter().map(|a| a.content.len() as u64).sum::<u64>();
                // Reserve the whole history cost once (decision 023): the new
                // payload (its files, directory and staging entry) and the
                // archived previous profile. Orphan payloads go first.
                payload::gc(dir)?;
                let mut need = xkeenwrt_recovery::resources::HistoryNeed {
                    bytes: bundle_bytes,
                    entries: bundle.assets.len().saturating_add(1).saturating_add(2),
                    ..Default::default()
                };
                if j.current.is_some() {
                    need = need.and(&xkeenwrt_recovery::resources::HistoryNeed::archive(
                        xkeenwrt_recovery::resources::HistoryArea::Snapshots,
                        previous_bytes,
                    ));
                }
                xkeenwrt_recovery::resources::reserve_history(dir, &need, &Default::default())
                    .map_err(|_| ActivationError::Storage)?;
                core.admit(
                    bundle_bytes,
                    previous_bytes
                        .saturating_add(journal_bytes)
                        .saturating_add(committed_bytes),
                    0,
                )?;
                if let Some(previous) = &j.current {
                    core.check_fence()?;
                    let mut snapshot = previous.clone();
                    snapshot.restore_running = restore_running;
                    snapshot_previous(dir, &snapshot)?;
                }
                core.check_fence()?;
                journal_write(dir, &j)?;
                core.check_fence()?;
                // Applying selects the accepted immutable profile. A stopped
                // service stays stopped until the separate Start operation.
                let published = if restore_running {
                    core.replace_assets(Some(&next.config), &bundle.assets)
                } else {
                    Ok(())
                };
                if let Err(e) = published {
                    core.check_fence()?;
                    let restored = if restore_running {
                        match j.current.as_ref() {
                            Some(prev) => prev
                                .bundle()
                                .and_then(|assets| core.replace_assets(Some(&prev.config), &assets)),
                            None => Err(ActivationError::Storage),
                        }
                    } else {
                        core.replace_assets(None, &[])
                    };
                    if restored.is_err() {
                        return Err(ActivationError::CommitUncertain);
                    }
                    j.pending = None;
                    journal_write(dir, &j).map_err(|_| ActivationError::CommitUncertain)?;
                    return Err(e);
                }
                j.current = Some(next);
                j.pending = None;
                core.check_fence().map_err(|_| ActivationError::CommitUncertain)?;
                if journal_write(dir, &j).is_err() {
                    return Err(ActivationError::CommitUncertain);
                }
                core.check_fence().map_err(|_| ActivationError::CommitUncertain)?;
                Ok(tx)
            })
            .map_err(map_config)?
    }
}

#[cfg(test)]
mod payload_migration_tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    struct Accept;
    impl Validator for Accept {
        fn validate(&self, _: &str) -> Result<(), ActivationError> {
            Ok(())
        }
    }
    fn fixture() -> (PathBuf, Activation<Accept>, Journal) {
        let root = std::env::temp_dir().join(format!("xkeen-payload-migrate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = ConfigStore::new(root.join("profiles")).unwrap();
        let profile = store.save("home", "mode: rule\n", None).unwrap();
        let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
        let candidate = activation.validate("home", &profile.revision).unwrap();
        let config = activation
            .candidate_bundle("home", &profile.revision, &candidate.candidate_id)
            .unwrap()
            .config;
        let saved = Saved {
            tx: ManualTransaction {
                id: uuid::Uuid::new_v4().to_string(),
                state: "committed".into(),
                revision: "revision".into(),
            },
            profile_id: "home".into(),
            candidate_id: uuid::Uuid::new_v4().to_string(),
            key: "key".into(),
            config,
            assets: Vec::new(),
            payload: None,
            provider_metadata: None,
            restore_running: false,
            network_tx_id: None,
        };
        let journal = Journal {
            version: 1,
            current: Some(saved),
            pending: None,
        };
        journal_write(&root, &journal).unwrap();
        (root, activation, journal)
    }
    #[test]
    fn interrupted_publish_keeps_legacy_readable_and_migration_reuses_exact_object() {
        let (root, activation, legacy) = fixture();
        let before = std::fs::read(root.join("transaction.json")).unwrap();
        let reference = payload::compact(&root, legacy.current.as_ref().unwrap()).unwrap();
        // Crash seam: complete payload published, root journal not yet replaced.
        assert_eq!(std::fs::read(root.join("transaction.json")).unwrap(), before);
        assert_eq!(
            journal_read(&root).unwrap().current.unwrap().config,
            legacy.current.as_ref().unwrap().config
        );
        let file = root
            .join("payloads")
            .join(&reference.payload.unwrap().digest)
            .join("config.yaml");
        use std::os::unix::fs::MetadataExt;
        let inode = std::fs::metadata(&file).unwrap().ino();
        activation.migrate_payloads_after_handoff(&root).unwrap();
        assert_eq!(journal_metadata(&root).unwrap().version, 2);
        assert_eq!(std::fs::metadata(file).unwrap().ino(), inode);
        assert_eq!(
            journal_read(&root).unwrap().current.unwrap().config,
            legacy.current.as_ref().unwrap().config
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn capacity_failure_preserves_legacy_and_emergency_stop_does_not_migrate() {
        let (root, activation, _) = fixture();
        let history = root.join("history");
        std::fs::create_dir(&history).unwrap();
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = history.join(format!("{}.yaml", uuid::Uuid::new_v4()));
        let f = std::fs::File::create(&pinned).unwrap();
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o600)).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        let before = std::fs::read(root.join("transaction.json")).unwrap();
        assert_eq!(
            activation.migrate_payloads_after_handoff(&root),
            Err(ActivationError::Storage)
        );
        assert_eq!(std::fs::read(root.join("transaction.json")).unwrap(), before);
        struct Stop(bool);
        impl ManualCore for Stop {
            fn replace(&mut self, c: Option<&str>) -> Result<(), ActivationError> {
                assert!(c.is_none());
                self.0 = true;
                Ok(())
            }
            fn running(&self) -> Result<bool, ActivationError> {
                Ok(false)
            }
        }
        let mut core = Stop(false);
        activation.emergency_stop(&mut core).unwrap();
        assert!(core.0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn gc_keeps_current_history_and_refuses_an_unreadable_lease_root() {
        let (root, activation, _) = fixture();
        activation.migrate_payloads_after_handoff(&root).unwrap();
        let mut alternate = journal_read(&root).unwrap().current.unwrap();
        let mut config: serde_json::Value = serde_json::from_str(&alternate.config).unwrap();
        config["mode"] = serde_json::json!("direct");
        alternate.config = serde_json::to_string(&config).unwrap();
        alternate.payload = None;
        let orphan = payload::compact(&root, &alternate).unwrap().payload.unwrap();
        let orphan_dir = root.join("payloads").join(&orphan.digest);
        let history = root.join("history");
        std::fs::create_dir(&history).unwrap();
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bad = history.join(format!("{}.json", uuid::Uuid::new_v4()));
        crate::private_file::publish_private(&bad, b"corrupt").unwrap();
        assert!(payload::gc(&root).is_err());
        assert!(orphan_dir.exists());
        std::fs::remove_file(bad).unwrap();
        payload::gc(&root).unwrap();
        assert!(!orphan_dir.exists());
        assert!(journal_read(&root).is_ok());
        let orphan = payload::compact(&root, &alternate).unwrap().payload.unwrap();
        let orphan_dir = root.join("payloads").join(&orphan.digest);
        let unknown = history.join(uuid::Uuid::new_v4().to_string());
        std::os::unix::fs::symlink("/tmp", &unknown).unwrap();
        assert!(payload::gc(&root).is_err());
        assert!(orphan_dir.exists());
        std::fs::remove_file(&unknown).unwrap();
        std::fs::write(&unknown, b"not a snapshot directory").unwrap();
        assert!(payload::gc(&root).is_err());
        assert!(orphan_dir.exists());
        std::fs::remove_file(&unknown).unwrap();
        // A foreign namespace or symlink is never eligible for deletion.
        std::os::unix::fs::symlink("/tmp", root.join("payloads").join("foreign")).unwrap();
        assert!(payload::gc(&root).is_err());
        assert!(root.join("payloads/foreign").is_symlink());
        std::fs::remove_dir_all(root).unwrap();
    }
}
