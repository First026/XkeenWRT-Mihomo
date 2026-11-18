//! Sequencing contract for the network transaction adapter.
//! Persistence, trusted plan lookup, helper IPC and mutation lock belong to the driver.
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub plan_id: String,
    pub candidate_id: String,
    pub idempotency_key: String,
    pub generation: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    pub request: Request,
    pub transaction_id: String,
    pub confirm_token: String,
    pub boot_id: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
}
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("request", &self.request)
            .field("transaction_id", &self.transaction_id)
            .field("confirm_token", &"[redacted]")
            .field("boot_id", &self.boot_id)
            .field("created_ms", &self.created_ms)
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Pending(Pending),
    Confirmed { transaction_id: String },
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotReady,
    Conflict,
    Expired,
    Storage,
    Unhealthy,
    /// Tailscale start: the gateway DNS did not answer (decision 024).
    RemoteDns,
    /// Tailscale start: no proxy node reached the probe URL (decision 024).
    RemoteEgress,
}

/// The guard returned by lock must hold the recovery helper's shared flock.
/// Every operation which reads or changes the journal is called with that guard alive.
pub trait Driver {
    type Guard;
    /// Create the transaction cgroups, start the helper and wait for idle-ready.
    fn idle_ready(&mut self, request: &Request, transaction_id: &str) -> Result<(), Error>;
    fn lock(&mut self) -> Result<Self::Guard, Error>;
    fn now_ms(&mut self) -> Result<u64, Error>;
    fn boot_id(&mut self) -> Result<String, Error>;
    /// Derive token from the separate persistent key. Never recreate a missing key while a journal exists.
    fn make_token(&mut self, tx_id: &str, request: &Request) -> Result<String, Error>;
    fn load_pending(&mut self) -> Result<Option<Pending>, Error>;
    /// Attach the existing operation and supervisor before a Pending replay.
    fn attach_pending(&mut self, _pending: &Pending) -> Result<(), Error> {
        Ok(())
    }
    /// Resolve trusted plan/candidate and pin all snapshots before durable pending.
    fn prepare_pending(&mut self, p: &Pending) -> Result<(), Error>;
    /// Wait boundedly without holding the mutation lock for helper READY.
    fn await_ready(&mut self, p: &Pending) -> Result<(), Error>;
    /// Match transaction, generation, boot-id and procd instance against READY.
    fn ready(&mut self, p: &Pending) -> Result<bool, Error>;
    /// Refresh trusted inventory and revalidate immutable candidate and generation.
    fn revalidate(&mut self, p: &Pending) -> Result<(), Error>;
    /// Verify exact transaction revoke fence and launch grant under the lock.
    fn not_revoked(&mut self, p: &Pending) -> Result<bool, Error>;
    /// Invoke fixed executor; any failure remains pending for recovery.
    fn apply(&mut self, p: &Pending) -> Result<(), Error>;
    /// Persist and later inspect the successful-apply receipt under the lock.
    fn mark_applied(&mut self, p: &Pending) -> Result<(), Error>;
    fn is_applied(&mut self, p: &Pending) -> Result<bool, Error>;
    /// Check the complete installed object semantics and ownership, not just its comment.
    fn verify_active(&mut self, p: &Pending) -> Result<bool, Error>;
    fn health(&mut self, p: &Pending) -> Result<bool, Error>;
    /// Extra evidence for a generation started over Tailscale (decision 024):
    /// the administrator is outside the LAN, so the router proves the gateway
    /// DNS and egress itself. A LAN start has nothing to add.
    fn remote_check(&mut self, _p: &Pending) -> Result<(), Error> {
        Ok(())
    }
    fn confirm(&mut self, p: &Pending) -> Result<(), Error>;
    /// Exact repeat of a durable confirmed transaction; no deadline extension.
    /// Return the durable confirmed receipt only for the same exact request.
    fn confirmed_for(&mut self, _request: &Request) -> Result<Option<String>, Error> {
        Ok(None)
    }
    fn already_confirmed(&mut self, _transaction_id: &str, _token: &str) -> Result<bool, Error> {
        Ok(false)
    }
}
pub struct Coordinator<D> {
    driver: D,
}
impl<D: Driver> Coordinator<D> {
    pub fn new(driver: D) -> Self {
        Self { driver }
    }
    pub fn driver(&self) -> &D {
        &self.driver
    }
    pub fn apply_or_replay(&mut self, request: Request) -> Result<ApplyOutcome, Error> {
        {
            let _guard = self.driver.lock()?;
            if let Some(transaction_id) = self.driver.confirmed_for(&request)? {
                return Ok(ApplyOutcome::Confirmed { transaction_id });
            }
        }
        self.apply(request).map(ApplyOutcome::Pending)
    }
    pub fn apply(&mut self, request: Request) -> Result<Pending, Error> {
        if request.generation == 0
            || [&request.plan_id, &request.candidate_id, &request.idempotency_key]
                .iter()
                .any(|s| s.is_empty() || s.len() > 128)
        {
            return Err(Error::Conflict);
        }
        {
            let _guard = self.driver.lock()?;
            if let Some(existing) = self.driver.load_pending()? {
                if existing.request == request
                    && self.driver.is_applied(&existing)?
                    && self.driver.not_revoked(&existing)?
                    && self.driver.boot_id()? == existing.boot_id
                    && (existing.created_ms..existing.deadline_ms).contains(&self.driver.now_ms()?)
                {
                    self.driver.attach_pending(&existing)?;
                    if self.driver.ready(&existing)?
                        && self.driver.verify_active(&existing)?
                        && self.driver.health(&existing)?
                        && self.driver.not_revoked(&existing)?
                        && (existing.created_ms..existing.deadline_ms).contains(&self.driver.now_ms()?)
                    {
                        return Ok(existing);
                    }
                }
                return Err(Error::Conflict);
            }
        }
        let transaction_id = Uuid::new_v4().to_string();
        self.driver.idle_ready(&request, &transaction_id)?;
        let pending = {
            let _guard = self.driver.lock()?;
            if self.driver.load_pending()?.is_some() {
                return Err(Error::Conflict);
            }
            let created_ms = self.driver.now_ms()?;
            let deadline_ms = created_ms.checked_add(120_000).ok_or(Error::Storage)?;
            let confirm_token = self.driver.make_token(&transaction_id, &request)?;
            let p = Pending {
                request,
                transaction_id,
                confirm_token,
                boot_id: self.driver.boot_id()?,
                created_ms,
                deadline_ms,
            };
            self.driver.prepare_pending(&p)?;
            p
        };
        self.driver.await_ready(&pending)?;
        {
            let _guard = self.driver.lock()?;
            if self.driver.load_pending()?.as_ref() != Some(&pending) {
                return Err(Error::Conflict);
            }
            if self.driver.boot_id()? != pending.boot_id
                || !(pending.created_ms..pending.deadline_ms).contains(&self.driver.now_ms()?)
            {
                return Err(Error::Expired);
            }
            if !self.driver.ready(&pending)? {
                return Err(Error::NotReady);
            }
            self.driver.revalidate(&pending)?;
            if !self.driver.not_revoked(&pending)? {
                return Err(Error::Conflict);
            }
            if !(pending.created_ms..pending.deadline_ms).contains(&self.driver.now_ms()?) {
                return Err(Error::Expired);
            }
            self.driver.apply(&pending)?;
            if !self.driver.not_revoked(&pending)? {
                return Err(Error::Conflict);
            }
            if !self.driver.verify_active(&pending)? {
                return Err(Error::Conflict);
            }
            if !self.driver.health(&pending)? {
                return Err(Error::Unhealthy);
            }
            if !(pending.created_ms..pending.deadline_ms).contains(&self.driver.now_ms()?) {
                return Err(Error::Expired);
            }
            if !self.driver.not_revoked(&pending)? {
                return Err(Error::Conflict);
            }
            self.driver.mark_applied(&pending)?;
        }
        Ok(pending)
    }
    pub fn confirm(&mut self, transaction_id: &str, token: &str) -> Result<(), Error> {
        let _guard = self.driver.lock()?;
        if self.driver.already_confirmed(transaction_id, token)? {
            return Ok(());
        }
        let p = self.driver.load_pending()?.ok_or(Error::Conflict)?;
        if p.transaction_id != transaction_id || !token_matches(&p.confirm_token, token) {
            return Err(Error::Conflict);
        }
        if self.driver.boot_id()? != p.boot_id || !(p.created_ms..p.deadline_ms).contains(&self.driver.now_ms()?) {
            return Err(Error::Expired);
        }
        if !self.driver.not_revoked(&p)? {
            return Err(Error::Conflict);
        }
        if !self.driver.is_applied(&p)? || !self.driver.ready(&p)? {
            return Err(Error::NotReady);
        }
        if !self.driver.verify_active(&p)? {
            return Err(Error::Conflict);
        }
        if !self.driver.health(&p)? {
            return Err(Error::Unhealthy);
        }
        // Probes take seconds; the deadline and fence are rechecked after them.
        self.driver.remote_check(&p)?;
        if !(p.created_ms..p.deadline_ms).contains(&self.driver.now_ms()?) {
            return Err(Error::Expired);
        }
        if !self.driver.not_revoked(&p)? || !self.driver.ready(&p)? {
            return Err(Error::Conflict);
        }
        self.driver.confirm(&p)
    }
}

/// A new generation is a replacement, not a replay of the confirmed request.
/// Reusing a key or changing an existing generation remains a conflict.
pub fn confirmed_request_is_replay(j: &xkeenwrt_recovery::Journal, r: &Request) -> Result<bool, Error> {
    if r.generation > j.generation && r.idempotency_key != j.idempotency_key {
        return Ok(false);
    }
    if r.generation == j.generation
        && r.idempotency_key == j.idempotency_key
        && r.plan_id == j.plan_id
        && r.candidate_id == j.candidate_id
    {
        Ok(true)
    } else {
        Err(Error::Conflict)
    }
}

fn token_matches(expected: &str, supplied: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(supplied.as_bytes()).into()
}

/// Stable, domain-separated HMAC over length-prefixed UTF-8 fields.
pub fn confirmation_token(
    key: &[u8; 32], tx_id: &str, generation: u64, plan_id: &str, idempotency_key: &str,
) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut mac = ring::hmac::Context::with_key(&key);
    mac.update(b"xkeenwrt-confirm-v1\0");
    mac.update(&generation.to_be_bytes());
    for value in [tx_id, plan_id, idempotency_key] {
        mac.update(&(value.len() as u32).to_be_bytes());
        mac.update(value.as_bytes());
    }
    mac.sign().as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Rebuild a pending response only from the authoritative recovery journal and
/// the existing confirmation key. A changed key or journal cannot auto-confirm.
pub fn pending_from_journal(
    journal: &xkeenwrt_recovery::Journal, key: &[u8; 32], boot_id: &str, now_ms: u64,
) -> Result<Pending, Error> {
    use sha2::{Digest, Sha256};
    if journal.decision(boot_id, now_ms, false) != xkeenwrt_recovery::Decision::Wait {
        return Err(Error::Conflict);
    }
    let token = confirmation_token(
        key,
        &journal.tx_id,
        journal.generation,
        &journal.plan_id,
        &journal.idempotency_key,
    );
    let digest = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if !token_matches(&digest, &journal.confirm_token_sha256) {
        return Err(Error::Conflict);
    }
    Ok(Pending {
        request: Request {
            plan_id: journal.plan_id.clone(),
            candidate_id: journal.candidate_id.clone(),
            idempotency_key: journal.idempotency_key.clone(),
            generation: journal.generation,
        },
        transaction_id: journal.tx_id.clone(),
        confirm_token: token,
        boot_id: journal.boot_id.clone(),
        created_ms: journal.created_boottime_ms,
        deadline_ms: journal.deadline_boottime_ms,
    })
}

/// A completed explicit confirmation remains idempotent after its pending
/// deadline, but a revoke fence or any binding mismatch rejects it.
pub fn confirmed_token_matches(
    journal: &xkeenwrt_recovery::Journal, key: &[u8; 32], tx_id: &str, token: &str, fence_absent: bool,
) -> bool {
    use sha2::{Digest, Sha256};
    if !fence_absent
        || journal.state != xkeenwrt_recovery::State::Confirmed
        || !journal.applied
        || journal.tx_id != tx_id
        || journal.decision(&journal.boot_id, journal.created_boottime_ms, false)
            != xkeenwrt_recovery::Decision::Settled
    {
        return false;
    }
    let expected = confirmation_token(
        key,
        &journal.tx_id,
        journal.generation,
        &journal.plan_id,
        &journal.idempotency_key,
    );
    let digest: String = Sha256::digest(expected.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    token_matches(&expected, token) && token_matches(&digest, &journal.confirm_token_sha256)
}
