//! Durable terminal receipts. They retain the disabled generation and the
//! obligation to return runtime only after recovery has released mutation.lock.
use crate::{Journal, LifecycleKind, LifecycleRequest, State, active, valid_owner};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Rollback,
    RollbackDirect,
    Disable,
    BootCleanup,
    LifecycleCleanup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleBinding {
    pub request_id: String,
    pub kind: LifecycleKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub kind: Kind,
    pub boot_id: String,
    pub active_generation: Option<u64>,
    pub runtime_resumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleBinding>,
}

impl Completion {
    pub fn valid_for(&self, j: &Journal) -> bool {
        let known = self.active_generation.is_none_or(|g| {
            g == j.current.generation || j.previous_good.as_ref().is_some_and(|m| m.generation == g)
        });
        valid_owner(&self.boot_id)
            && known
            && (self.kind == Kind::LifecycleCleanup || self.lifecycle.is_none())
            && match self.kind {
                Kind::Rollback => {
                    j.state == State::RolledBack
                        && self.active_generation == j.previous_good.as_ref().map(|m| m.generation)
                }
                Kind::RollbackDirect => {
                    j.state == State::Disabled && self.active_generation.is_none()
                }
                Kind::Disable => {
                    j.state == State::Disabled
                        && self.boot_id == j.boot_id
                        && self.active_generation.is_some()
                        && self.runtime_resumed
                }
                Kind::BootCleanup => j.state == State::Disabled && self.boot_id != j.boot_id,
                Kind::LifecycleCleanup => {
                    j.state == State::Disabled
                        && self.runtime_resumed
                        && self
                            .lifecycle
                            .as_ref()
                            .is_some_and(|b| valid_owner(&b.request_id))
                }
            }
    }
}

impl Journal {
    pub fn finish_disable(&mut self) {
        let generation = active::active_manifest(self).map(|m| m.generation);
        self.state = State::Disabled;
        self.completion = Some(Completion {
            kind: Kind::Disable,
            boot_id: self.boot_id.clone(),
            active_generation: generation,
            runtime_resumed: true,
            lifecycle: None,
        });
    }
    /// Caller has already proved old runtime/cgroup quiescence and restored
    /// the complete previous state. Persist this before returning runtime.
    pub fn finish_rollback(&mut self, boot: &str) {
        self.next_baseline_core = None;
        self.state = State::RolledBack;
        self.completion = Some(Completion {
            kind: Kind::Rollback,
            boot_id: boot.into(),
            active_generation: self.previous_good.as_ref().map(|m| m.generation),
            runtime_resumed: false,
            lifecycle: None,
        });
    }
    /// Both generations are absent and the safe baseline (including explicit)
    /// is restored. Preserve all previous manifests as history, not active work.
    pub fn finish_rollback_direct(&mut self, boot: &str) {
        self.next_baseline_core = None;
        self.state = State::Disabled;
        self.completion = Some(Completion {
            kind: Kind::RollbackDirect,
            boot_id: boot.into(),
            active_generation: None,
            runtime_resumed: false,
            lifecycle: None,
        });
    }
    pub fn rollback_direct_complete(&self) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|c| c.kind == Kind::RollbackDirect && c.valid_for(self))
    }
    pub fn needs_boot_cleanup(&self, boot: &str) -> bool {
        self.boot_id != boot
            && (matches!(
                self.state,
                State::Pending | State::Revoked | State::Confirmed | State::RolledBack
            ) || (self.state == State::Disabled
                && self.completion.as_ref().is_some_and(|c| {
                    (c.kind == Kind::Disable || !c.runtime_resumed) && c.boot_id != boot
                })))
    }
    /// Caller has archived the old active event, proved network absence and
    /// restored a stopped baseline. Reboot never re-enables interception.
    pub fn finish_boot_cleanup(&mut self, boot: &str) {
        let generation = active::active_manifest(self).map(|m| m.generation);
        self.state = State::Disabled;
        self.completion = Some(Completion {
            kind: Kind::BootCleanup,
            boot_id: boot.into(),
            active_generation: generation,
            runtime_resumed: false,
            lifecycle: None,
        });
    }
    pub fn boot_cleanup_complete(&self) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|c| c.kind == Kind::BootCleanup && c.valid_for(self))
    }
    pub fn needs_runtime_resume(&self, boot: &str) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|c| c.valid_for(self) && c.boot_id == boot && !c.runtime_resumed)
    }
    /// Caller has proved stopped core, absence of both generations and archived
    /// the bound active event. This receipt never grants automatic service start.
    pub fn finish_lifecycle_cleanup(
        &mut self,
        boot: &str,
        request: &LifecycleRequest,
        generation: Option<u64>,
    ) -> std::io::Result<()> {
        let id = request
            .request_id
            .as_deref()
            .filter(|id| valid_owner(id))
            .ok_or_else(|| std::io::Error::other("missing lifecycle request identity"))?;
        if request.version != 1
            || request.owner_id != self.current.owner_id
            || !valid_owner(boot)
            || generation.is_some_and(|g| {
                g != self.current.generation
                    && self
                        .previous_good
                        .as_ref()
                        .is_none_or(|p| p.generation != g)
            })
        {
            return Err(std::io::Error::other(
                "lifecycle completion binding mismatch",
            ));
        }
        self.state = State::Disabled;
        self.completion = Some(Completion {
            kind: Kind::LifecycleCleanup,
            boot_id: boot.into(),
            active_generation: generation,
            runtime_resumed: true,
            lifecycle: Some(LifecycleBinding {
                request_id: id.into(),
                kind: request.kind,
            }),
        });
        Ok(())
    }
    pub fn lifecycle_cleanup_complete(&self) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|c| c.kind == Kind::LifecycleCleanup && c.valid_for(self))
    }
    pub fn lifecycle_cleanup_matches(&self, request: &LifecycleRequest) -> bool {
        self.lifecycle_cleanup_complete()
            && self.current.owner_id == request.owner_id
            && self
                .completion
                .as_ref()
                .and_then(|c| c.lifecycle.as_ref())
                .is_some_and(|b| {
                    Some(b.request_id.as_str()) == request.request_id.as_deref()
                        && b.kind == request.kind
                })
    }
}
