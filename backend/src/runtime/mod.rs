mod input_guard;
mod inputs;
pub mod ipc;
pub(crate) mod resume;
mod service;
pub(crate) mod upgrade_adapter;
use crate::configuration::ManualCore;
use serde::{Deserialize, Serialize};
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeCommand {
    Status,
    Enable,
    Disable,
    Reload,
    Validate {
        profile_id: String,
        revision: String,
    },
    CancelCandidate {
        profile_id: String,
        revision: String,
        candidate_id: String,
    },
    RefreshProvider {
        profile_id: String,
        revision: String,
        provider_id: String,
    },
    ProviderContent {
        profile_id: String,
        revision: String,
        provider_id: String,
    },
    EditProvider {
        profile_id: String,
        revision: String,
        provider_id: String,
        content: String,
    },
    Apply {
        profile_id: String,
        revision: String,
        candidate_id: String,
        idempotency_key: String,
    },
    Start,
    ServiceStart {
        peer: crate::management::ManagementPeer,
    },
    ServiceStop,
    ServiceRestart {
        peer: crate::management::ManagementPeer,
    },
    ServiceApply {
        profile_id: String,
        revision: String,
        candidate_id: String,
        idempotency_key: String,
        peer: crate::management::ManagementPeer,
    },
    ExplicitSet {
        binding: Option<ExplicitBinding>,
        peer: crate::management::ManagementPeer,
    },
    InputsStatus,
    Stop,
    Restart,
    SelectCore {
        version: String,
    },
    ResumeAfterReinstall {
        request_id: String,
    },
    NetworkPlan {
        request: NetworkPlanRequest,
    },
    NetworkApply {
        plan_id: String,
        idempotency_key: String,
    },
    NetworkConfirm {
        transaction_id: String,
        confirm_token: String,
    },
    NetworkStatus,
    Compatibility {
        peer: crate::management::ManagementPeer,
    },
    NetworkDisable {
        idempotency_key: String,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitBinding {
    pub interface: String,
    pub address: std::net::Ipv4Addr,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlanRequest {
    pub profile_id: String,
    pub expected_revision: String,
    pub candidate_id: String,
    pub lan_interface: String,
    pub selected_ipv4: std::net::Ipv4Addr,
    pub management_ipv4: std::net::Ipv4Addr,
    pub selected_ipv6: Vec<String>,
    pub management_ipv6: Vec<String>,
    pub ipv6_policy: String,
    pub failure_policy: String,
    pub peer_ipv4: std::net::Ipv4Addr,
    /// Router address of the Tailscale listener that accepted `peer_ipv4`;
    /// absent for a LAN peer (decision 024).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale_router: Option<std::net::Ipv4Addr>,
}
impl NetworkPlanRequest {
    pub fn management_peer(&self) -> crate::management::ManagementPeer {
        match self.tailscale_router {
            Some(router) => crate::management::ManagementPeer::Tailscale {
                peer: self.peer_ipv4,
                router,
            },
            None => crate::management::ManagementPeer::Lan { peer: self.peer_ipv4 },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCapability {
    PlatformInspect,
    CoreControl,
    ProfileValidate,
    ProfileApplyManual,
    CoreRelay,
    ProviderRefresh,
    NetworkIntegration,
}
impl RuntimeCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformInspect => "platform_inspect",
            Self::CoreControl => "core_control",
            Self::ProfileValidate => "profile_validate",
            Self::ProfileApplyManual => "profile_apply_manual",
            Self::CoreRelay => "core_relay",
            Self::ProviderRefresh => "provider_refresh",
            Self::NetworkIntegration => "network_integration",
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub struct RuntimeReply {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<crate::mihomo::providers::diagnostic::Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<crate::configuration::ValidatedCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<crate::configuration::ManualTransaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<RuntimeCapability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_metadata: Option<Vec<crate::mihomo::providers::metadata::AppliedProvider>>,
}
impl RuntimeReply {
    pub fn error(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            diagnostic: None,
            validation: None,
            transaction: None,
            resume_request_id: None,
            capabilities: None,
            running: None,
            network: None,
            inputs: None,
            provider_content: None,
            active_profile_id: None,
            active_profile_revision: None,
            provider_metadata: None,
        }
    }
    pub fn diagnosed(diagnostic: crate::mihomo::providers::diagnostic::Diagnostic) -> Self {
        let mut reply = Self::error("VALIDATION_FAILED", &diagnostic.message());
        reply.diagnostic = Some(diagnostic);
        reply
    }
    pub fn for_command(command: RuntimeCommand) -> Self {
        match command {
            RuntimeCommand::Status => match crate::platform::Platform::service_status() {
                Ok(crate::platform::ServiceStatus::Running) => Self::error("OK", "running"),
                Ok(crate::platform::ServiceStatus::Stopped) => Self::error("OK", "stopped"),
                Err(code) => Self::error(code, "Unable to inspect the native procd service"),
            },
            RuntimeCommand::Enable | RuntimeCommand::Reload => Self::error(
                "NOT_READY",
                "Managed configuration validation and recovery prerequisites are not ready",
            ),
            RuntimeCommand::Disable => Self::error("NOT_READY", "Native procd control is not ready"),
            RuntimeCommand::Validate { .. }
            | RuntimeCommand::CancelCandidate { .. }
            | RuntimeCommand::RefreshProvider { .. }
            | RuntimeCommand::ProviderContent { .. }
            | RuntimeCommand::EditProvider { .. }
            | RuntimeCommand::Apply { .. }
            | RuntimeCommand::ServiceStart { .. }
            | RuntimeCommand::ServiceStop
            | RuntimeCommand::ServiceRestart { .. }
            | RuntimeCommand::ServiceApply { .. }
            | RuntimeCommand::ExplicitSet { .. }
            | RuntimeCommand::InputsStatus
            | RuntimeCommand::Start
            | RuntimeCommand::Stop
            | RuntimeCommand::Restart
            | RuntimeCommand::SelectCore { .. }
            | RuntimeCommand::ResumeAfterReinstall { .. }
            | RuntimeCommand::NetworkPlan { .. }
            | RuntimeCommand::NetworkApply { .. }
            | RuntimeCommand::NetworkConfirm { .. }
            | RuntimeCommand::NetworkStatus
            | RuntimeCommand::Compatibility { .. }
            | RuntimeCommand::NetworkDisable { .. } => Self::error("NOT_READY", "Runtime prerequisites are not ready"),
        }
    }
}

pub mod validator;

pub mod core;
pub mod networking;

pub struct Coordinator {
    activation: crate::configuration::Activation<validator::ProcessValidator>,
    core: core::ProcdCore,
    ready: bool,
    native_profile_ready: bool,
    native_apply_ready: bool,
    incarnation_cgroup: std::sync::Arc<std::fs::File>,
    pub(crate) incarnation_identity: xkeenwrt_recovery::RuntimeIncarnationIdentity,
    network_control: bool,
    storage_ready: bool,
    storage_attempt: Option<std::time::Instant>,
    /// Last Tailscale confirmation probes with their transaction (decision 024).
    /// Memory only: status shows them, flash never stores them.
    remote_check: Option<(String, networking::remote_check::RemoteCheck)>,
}
impl Coordinator {
    fn status_reply(&self, running: Option<bool>) -> RuntimeReply {
        let mut reply = RuntimeReply::error(
            "OK",
            match running {
                Some(true) => "running",
                Some(false) => "stopped",
                None => "unknown",
            },
        );
        reply.resume_request_id = resume::completed_request_id().ok().flatten();
        let mut capabilities = Vec::new();
        if core::deployment_allowed() {
            capabilities.push(RuntimeCapability::CoreControl);
        }
        if self.native_profile_ready {
            capabilities.push(RuntimeCapability::ProfileValidate);
            capabilities.push(RuntimeCapability::ProviderRefresh);
        }
        if self.native_apply_ready {
            capabilities.push(RuntimeCapability::ProfileApplyManual);
        }
        if self.native_profile_ready && running == Some(true) {
            capabilities.push(RuntimeCapability::CoreRelay);
        }
        if self.network_control {
            capabilities.push(RuntimeCapability::NetworkIntegration);
        }
        reply.capabilities = Some(capabilities);
        reply.running = running;
        if let Ok(bundle) = self.activation.applied_status(std::path::Path::new("/etc/xkeenwrt")) {
            reply.provider_metadata = Some(bundle.provider_metadata);
            reply.active_profile_id = Some(bundle.profile_id);
            reply.active_profile_revision = Some(bundle.revision);
        }
        reply
    }
    /// Read-only forecast of the next Start's real cost (decision 023): up to
    /// three snapshots of the profile, the archived journal and active event,
    /// with the memory of the core it will replace.
    fn start_forecast(&self, profile: Option<(u64, usize)>) -> resources::Forecast {
        use xkeenwrt_recovery::resources::{HistoryArea, HistoryNeed};
        let reclaimable = self.core.reclaimable_memory();
        let Some((bytes, files)) = profile else {
            return resources::forecast(0, 0, reclaimable, &HistoryNeed::default());
        };
        let journal = std::fs::symlink_metadata("/etc/xkeenwrt/recovery.json").map_or(0, |m| m.len());
        let snapshot = HistoryNeed::snapshot(bytes, files);
        let need = snapshot
            .clone()
            .and(&snapshot)
            .and(&snapshot)
            .and(&HistoryNeed::archive(HistoryArea::Network, journal))
            .and(&HistoryNeed::archive(HistoryArea::ActiveEvents, 16_384));
        resources::forecast(bytes, need.bytes, reclaimable, &need)
    }
    /// `candidate`: payload size and file count of the validated candidate the
    /// request names. Applying that candidate is what replaces a running
    /// gateway, so it satisfies the profile prerequisite and is what the
    /// operation will snapshot; the plan validates the same candidate right after.
    fn compatibility_report(
        &self, peer: crate::management::ManagementPeer, candidate: Option<(u64, usize)>,
    ) -> networking::compatibility::Report {
        use std::os::fd::AsRawFd;
        let accepted = self
            .activation
            .verified_applied_status(std::path::Path::new("/etc/xkeenwrt"))
            .ok();
        let package = crate::platform::Platform::compatible_packages_in(Some(self.incarnation_cgroup.as_raw_fd()));
        let recovery = crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
            .is_some_and(|(_, sha, build)| xkeenwrt_recovery::rescue::verify(&sha, build).is_ok());
        let journal = networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal();
        let profile = operation_profile(
            accepted.as_ref().map(|a| (a.payload_bytes, a.provider_metadata.len())),
            candidate,
        );
        let application = networking::compatibility::Application {
            journal_readable: journal.is_ok(),
            packages_verified: package,
            rescue_verified: recovery,
            accepted_profile: profile.is_some(),
            resources: self.start_forecast(profile),
            lifecycle_clear: self.ready && core::ensure_no_lifecycle_request().is_ok(),
        };
        let raw = networking::compatibility::collect(&self.incarnation_cgroup);
        let journal = journal.ok().flatten();
        let current = journal
            .as_ref()
            .and_then(networking::driver::OpenWrtDriver::<validator::ProcessValidator>::capability_manifest);
        networking::compatibility::evaluate(&raw, &application, peer, current)
    }
    fn compatibility_reply(&self, peer: crate::management::ManagementPeer) -> RuntimeReply {
        let _guard = match ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock")) {
            Ok(guard) => guard,
            Err(_) => return RuntimeReply::error("BUSY", "Network state is being updated"),
        };
        Self::network_reply(serde_json::json!({"compatibility":self.compatibility_report(peer, None)}))
    }
    fn network_reply(value: serde_json::Value) -> RuntimeReply {
        let mut reply = RuntimeReply::error("OK", "network operation completed");
        reply.network = Some(value);
        reply
    }
    fn network_error(error: networking::transaction::Error) -> RuntimeReply {
        use networking::transaction::Error;
        match error {
            Error::NotReady => RuntimeReply::error("NOT_READY", "Network recovery prerequisites are unavailable"),
            Error::Conflict => RuntimeReply::error("CONFLICT", "Network transaction or generation changed"),
            Error::Expired => RuntimeReply::error("EXPIRED", "Network confirmation window expired"),
            Error::Storage => RuntimeReply::error("STORAGE_ERROR", "Network transaction storage is unavailable"),
            Error::Unhealthy => RuntimeReply::error("UNHEALTHY", "The managed core failed its local health check"),
            Error::RemoteDns => RuntimeReply::error(
                "NETWORK_REMOTE_DNS",
                "Шлюзовый DNS не ответил на проверку. Перехват не подтверждён и будет снят.",
            ),
            Error::RemoteEgress => RuntimeReply::error(
                "NETWORK_REMOTE_EGRESS",
                "Ни один прокси не ответил на проверку выхода. Перехват не подтверждён и будет снят.",
            ),
        }
    }
    fn network_ready(&self) -> bool {
        self.ready && core::deployment_allowed() && networking::capability(&self.incarnation_cgroup)
    }
    fn network_status(&mut self) -> RuntimeReply {
        let _guard = match ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock")) {
            Ok(guard) => guard,
            Err(_) => return RuntimeReply::error("BUSY", "Network state is being updated"),
        };
        self.network_status_locked()
    }
    fn network_status_locked(&mut self) -> RuntimeReply {
        let journal = match networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal() {
            Ok(journal) => journal,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal cannot be read safely"),
        };
        let now = xkeenwrt_recovery::boottime_ms().unwrap_or(0);
        let state = match journal.as_ref() {
            None => networking::status::NetworkState::Inactive,
            Some(journal) => {
                networking::status::inspect_existing(journal, self.core.health().is_ok(), &self.incarnation_cgroup)
            }
        };
        let receipt = match networking::active::latest_status_locked(std::path::Path::new("/etc/xkeenwrt")) {
            Ok(receipt) => receipt,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network receipt cannot be validated"),
        };
        let active = journal.as_ref().and_then(|j| match j.state {
            xkeenwrt_recovery::State::Confirmed if j.operation == xkeenwrt_recovery::Operation::Apply => {
                Some(&j.current)
            }
            xkeenwrt_recovery::State::RolledBack => j.previous_good.as_ref(),
            _ => None,
        });
        let remaining = journal.as_ref().and_then(|j| {
            (j.state == xkeenwrt_recovery::State::Pending && now < j.deadline_boottime_ms)
                .then_some(j.deadline_boottime_ms.saturating_sub(now).div_ceil(1000))
        });
        let state = match state {
            networking::status::NetworkState::Inactive => "inactive",
            networking::status::NetworkState::Pending => "pending",
            networking::status::NetworkState::Active => "active",
            networking::status::NetworkState::Recovering => "recovering",
            networking::status::NetworkState::Degraded => "degraded",
        };
        Self::network_reply(serde_json::json!({
            "state": state,
            "transaction_id": journal.as_ref().map(|j| j.tx_id.as_str()),
            "active_generation": active.map(|m| m.generation),
            "failure_policy": active.map(|m| match m.failure_policy {
                xkeenwrt_recovery::FailurePolicy::DirectOnFailure => "direct_on_failure",
                xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure => "block_selected_on_failure",
            }),
            "remaining_seconds": remaining,
            "management_channel": journal.as_ref().and_then(|j| j.current.management_channel),
            "remote_check": journal.as_ref().and_then(|j| self
                .remote_check
                .as_ref()
                .filter(|(tx, _)| *tx == j.tx_id)
                .map(|(_, report)| report)),
            "active_event": receipt,
            "recovery_notice": journal.as_ref().and_then(|j| networking::active::recovery_notice(
                std::path::Path::new("/var/run/xkeenwrt/recovery-notice.json"),
                j,
            )),
        }))
    }
    fn network_plan(&mut self, request: NetworkPlanRequest) -> RuntimeReply {
        self.network_plan_inputs(request, None)
    }
    fn network_plan_inputs(
        &mut self, request: NetworkPlanRequest, explicit_override: Option<Option<profile_policy::ExplicitOverlay>>,
    ) -> RuntimeReply {
        use crate::configuration::ActivationError;
        use std::path::Path;
        let invalid = || RuntimeReply::error("INVALID", "Network plan request is invalid");
        if request.management_ipv4 != request.peer_ipv4
            || request.selected_ipv6.len() > 8
            || request.management_ipv6.len() > 8
            || request.profile_id.len() > 64
            || request.expected_revision.len() > 64
            || request.candidate_id.len() > 64
            || request.lan_interface.len() > 15
            || request.ipv6_policy != "block_external"
        {
            return invalid();
        }
        let failure_policy = match request.failure_policy.as_str() {
            "direct_on_failure" => crate::network::FailurePolicy::DirectOnFailure,
            "block_selected_on_failure" => crate::network::FailurePolicy::BlockSelectedOnFailure,
            _ => return invalid(),
        };
        let management_ipv6 = request
            .management_ipv6
            .iter()
            .map(|value| {
                value
                    .strip_suffix("/128")
                    .unwrap_or(value)
                    .parse::<std::net::Ipv6Addr>()
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(management_ipv6) = management_ipv6 else {
            return invalid();
        };
        if !self.network_ready() {
            return RuntimeReply::error("NOT_READY", "Native network prerequisites are unavailable");
        }
        let _guard = match Self::emergency_guard() {
            Ok(guard) => guard,
            Err(_) => return RuntimeReply::error("BUSY", "Another managed operation is in progress"),
        };
        if !self.network_ready() {
            return RuntimeReply::error("NOT_READY", "Native network prerequisites changed");
        }
        let candidate = self
            .activation
            .candidate_bundle(&request.profile_id, &request.expected_revision, &request.candidate_id)
            .ok()
            .map(|b| b.footprint());
        let report = self.compatibility_report(request.management_peer(), candidate);
        if !report.ready {
            let code = report
                .issues
                .iter()
                .find(|i| i.severity == xkeenwrt_recovery::topology::Severity::Blocker)
                .map(|i| i.code)
                .unwrap_or("NETWORK_PREREQUISITES");
            let mut reply = RuntimeReply::error(code, "Проверка совместимости обнаружила препятствия запуску.");
            reply.network = Some(serde_json::json!({"compatibility":report}));
            return reply;
        }

        if let Err(error) =
            self.activation
                .check_candidate(&request.profile_id, &request.expected_revision, &request.candidate_id)
        {
            return match error {
                ActivationError::CoreMissing => {
                    RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                        crate::mihomo::providers::diagnostic::Reason::CoreMissing,
                    ))
                }
                ActivationError::CoreIntegrity => {
                    RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                        crate::mihomo::providers::diagnostic::Reason::CoreIntegrity,
                    ))
                }
                ActivationError::CoreRejected => {
                    RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                        crate::mihomo::providers::diagnostic::Reason::CoreRejected,
                    ))
                }
                ActivationError::ValidatorUnavailable => {
                    RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                        crate::mihomo::providers::diagnostic::Reason::ValidatorUnavailable,
                    ))
                }
                ActivationError::Conflict => RuntimeReply::error("CONFLICT", "Profile revision or candidate changed"),
                ActivationError::Invalid => RuntimeReply::error("INVALID", "Profile candidate is invalid"),
                ActivationError::Unavailable => RuntimeReply::error("NOT_READY", "Profile validation is unavailable"),
                ActivationError::Storage => RuntimeReply::error("STORAGE_ERROR", "Profile storage is unavailable"),
                ActivationError::CommitUncertain => {
                    RuntimeReply::error("COMMIT_UNCERTAIN", "Profile state is uncertain")
                }
            };
        }
        let journal = match networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal() {
            Ok(journal) => journal,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal cannot be read safely"),
        };
        let now_boottime = match xkeenwrt_recovery::boottime_ms() {
            Ok(now) => now,
            Err(_) => return RuntimeReply::error("NOT_READY", "Boot clock is unavailable"),
        };
        if journal
            .as_ref()
            .is_some_and(|j| j.decision(&j.boot_id, now_boottime, false) != xkeenwrt_recovery::Decision::Settled)
        {
            return RuntimeReply::error("CONFLICT", "A network transaction is not settled");
        }
        let previous = journal
            .as_ref()
            .and_then(networking::driver::OpenWrtDriver::<validator::ProcessValidator>::active_manifest)
            .cloned();
        if previous.is_some() && self.core.health().is_err() {
            return RuntimeReply::error("UNHEALTHY", "The current managed core is not healthy");
        }
        let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(value) => value.as_secs(),
            Err(_) => return RuntimeReply::error("NOT_READY", "System clock is unavailable"),
        };
        let observed = match networking::collector::collect_for_generation(
            &request.lan_interface,
            request.selected_ipv4,
            request.management_ipv4,
            request.management_peer().channel(),
            timestamp,
            previous.as_ref(),
            &self.incarnation_cgroup,
        ) {
            Ok(observed) => observed,
            Err(networking::inventory::InventoryError::ResourceConflict { port, transport }) => {
                let protocol = match transport {
                    networking::inventory::SocketTransport::Tcp => "TCP",
                    networking::inventory::SocketTransport::Udp => "UDP",
                };
                return RuntimeReply::error(
                    "NETWORK_PORT_CONFLICT",
                    &format!("Порт {port}/{protocol}, необходимый шлюзу Mihomo, уже занят. Перехват не включён."),
                );
            }
            Err(_) => {
                return RuntimeReply::error(
                    "UNSUPPORTED",
                    "Live LAN, DNS, routing or service inventory is unsupported",
                );
            }
        };
        let identity = match networking::identity::reserve(Path::new("/etc/xkeenwrt")) {
            Ok(identity) => identity,
            Err(_) => return RuntimeReply::error("CONFLICT", "Network owner or generation state is invalid"),
        };
        let management_channel = request.management_peer().channel();
        let plan = match networking::planning::prepare(
            &mut self.activation,
            observed,
            networking::planning::PlanInput {
                profile_id: request.profile_id,
                revision: request.expected_revision,
                manual_candidate_id: request.candidate_id,
                selected_ipv4: request.selected_ipv4,
                management_ipv4: request.management_ipv4,
                management_channel,
                selected_ipv6: request.selected_ipv6,
                management_ipv6,
                failure_policy,
                owner_id: identity.owner_id,
                generation: identity.generation,
                previous,
                explicit: match explicit_override {
                    Some(e) => e,
                    None => match grant::selected_explicit() {
                        Ok(e) => e,
                        Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Explicit selection is unavailable"),
                    },
                },
            },
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return match error {
                    ActivationError::CoreMissing => {
                        RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                            crate::mihomo::providers::diagnostic::Reason::CoreMissing,
                        ))
                    }
                    ActivationError::CoreIntegrity => {
                        RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                            crate::mihomo::providers::diagnostic::Reason::CoreIntegrity,
                        ))
                    }
                    ActivationError::CoreRejected => {
                        RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                            crate::mihomo::providers::diagnostic::Reason::CoreRejected,
                        ))
                    }
                    ActivationError::ValidatorUnavailable => {
                        RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                            crate::mihomo::providers::diagnostic::Reason::ValidatorUnavailable,
                        ))
                    }
                    ActivationError::Conflict => RuntimeReply::error("CONFLICT", "Profile revision or scope changed"),
                    ActivationError::Invalid => {
                        RuntimeReply::error("INVALID", "The managed network profile is invalid")
                    }
                    ActivationError::Unavailable => {
                        RuntimeReply::error("UNSUPPORTED", "This network configuration is unsupported")
                    }
                    ActivationError::Storage => {
                        RuntimeReply::error("STORAGE_ERROR", "Network plan storage is unavailable")
                    }
                    ActivationError::CommitUncertain => {
                        RuntimeReply::error("COMMIT_UNCERTAIN", "Profile state is uncertain")
                    }
                };
            }
        };
        let bundle = match self
            .activation
            .candidate_bundle(&plan.profile_id, &plan.revision, &plan.candidate_id)
        {
            Ok(bundle) => bundle,
            Err(_) => return RuntimeReply::error("CONFLICT", "Prepared candidate is no longer available"),
        };
        let bundle_bytes = bundle.config.len() as u64
            + bundle
                .assets
                .iter()
                .map(|asset| asset.content.len() as u64)
                .sum::<u64>();
        let forecast = self.start_forecast(Some((bundle_bytes, bundle.assets.len())));
        if !forecast.admitted() {
            let code = forecast
                .shortages
                .first()
                .map_or("NETWORK_RESOURCES", resources::Shortage::code);
            let mut reply = RuntimeReply::error(code, "Available memory or storage is below the runtime limit");
            reply.network = Some(serde_json::json!({"resources": forecast}));
            return reply;
        }
        if networking::plans::save(&plan).is_err() {
            return RuntimeReply::error("STORAGE_ERROR", "Network plan could not be stored safely");
        }
        let manifest = plan.network.manifest();
        let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(plan.expires_unix as i64, 0)
            .map(|value| value.to_rfc3339())
            .unwrap_or_default();
        Self::network_reply(serde_json::json!({
            "plan_id": plan.plan_id,
            "candidate_id": plan.candidate_id,
            "generation": manifest.generation,
            "summary": {
                "lan_interface": manifest.lan_interface,
                "selected_ipv4": manifest.source_ipv4,
                "lan_scope": manifest.lan_scope,
                "selected_mac": manifest.selected_mac,
                "failure_policy": plan.network.failure_policy(),
            },
            "changes": ["owned nft interception", "selected-client local DNS policy", "owned IPv4 policy route"],
            "warnings": [],
            "expires_at": expires_at,
            "can_apply": true,
        }))
    }
    fn network_apply(&mut self, plan_id: &str, idempotency_key: &str) -> RuntimeReply {
        if idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return RuntimeReply::error("INVALID", "Network idempotency key is invalid");
        }
        if !self.network_ready() {
            return RuntimeReply::error("NOT_READY", "Native network prerequisites are unavailable");
        }
        if core::ensure_no_lifecycle_request().is_err() {
            return RuntimeReply::error("CONFLICT", "A package lifecycle operation is in progress");
        }
        let plan = match networking::plans::load(plan_id) {
            Ok(plan) => plan,
            Err(_) => return RuntimeReply::error("CONFLICT", "The prepared network plan is missing or expired"),
        };
        if self
            .activation
            .check_candidate(&plan.profile_id, &plan.revision, &plan.candidate_id)
            .is_err()
        {
            return RuntimeReply::error("CONFLICT", "Prepared candidate is no longer available");
        }
        use std::os::fd::AsRawFd;
        let Some((pinned, digest, build_id)) =
            crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
        else {
            return RuntimeReply::error("RESCUE_NOT_READY", "Persistent network recovery cannot be verified");
        };
        if xkeenwrt_recovery::rescue::provision(&pinned, &digest, build_id).is_err()
            || core::ensure_no_lifecycle_request().is_err()
        {
            return RuntimeReply::error("RESCUE_NOT_READY", "Persistent network recovery cannot be provisioned");
        }
        let generation = plan.network.manifest().generation;
        let request = networking::transaction::Request {
            plan_id: plan.plan_id.clone(),
            candidate_id: plan.candidate_id.clone(),
            idempotency_key: idempotency_key.to_owned(),
            generation,
        };
        let driver = networking::driver::OpenWrtDriver::new(
            &mut self.activation,
            &mut self.core,
            plan,
            self.incarnation_identity.clone(),
        );
        let mut coordinator = networking::transaction::Coordinator::new(driver);
        match coordinator.apply_or_replay(request) {
            Ok(networking::transaction::ApplyOutcome::Pending(pending)) => Self::network_reply(serde_json::json!({
                "state": "pending",
                "transaction_id": pending.transaction_id,
                "confirm_token": pending.confirm_token,
                "confirm_within_seconds": 120,
            })),
            Ok(networking::transaction::ApplyOutcome::Confirmed { transaction_id }) => {
                Self::network_reply(serde_json::json!({ "state": "confirmed", "transaction_id": transaction_id }))
            }
            Err(error) => Self::network_error(error),
        }
    }
    fn network_confirm(&mut self, transaction_id: &str, confirm_token: &str) -> RuntimeReply {
        use std::path::Path;
        if !uuid::Uuid::parse_str(transaction_id).is_ok_and(|id| id.to_string() == transaction_id)
            || confirm_token.len() != 64
            || !confirm_token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return RuntimeReply::error("INVALID", "Network confirmation binding is invalid");
        }
        let guard = match Self::emergency_guard() {
            Ok(guard) => guard,
            Err(_) => return RuntimeReply::error("BUSY", "Another managed operation is in progress"),
        };
        let journal = match networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal() {
            Ok(Some(journal)) => journal,
            Ok(None) => return RuntimeReply::error("CONFLICT", "Network transaction is missing"),
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal cannot be read safely"),
        };
        if journal.tx_id != transaction_id {
            return RuntimeReply::error("CONFLICT", "Network transaction changed");
        }
        if journal.state == xkeenwrt_recovery::State::Confirmed {
            let key = match networking::key::load(Path::new("/etc/xkeenwrt"), false) {
                Ok(key) => key,
                Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Confirmation key is unavailable"),
            };
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
            let fence = networking::helper::generation_unfenced(journal.generation).unwrap_or(false);
            if boot.trim() == journal.boot_id
                && networking::transaction::confirmed_token_matches(
                    &journal,
                    &key,
                    transaction_id,
                    confirm_token,
                    fence,
                )
            {
                if self
                    .activation
                    .finish_network_acceptance(Path::new("/etc/xkeenwrt"), transaction_id)
                    .is_err()
                    || inputs::settle_for(&journal).is_err()
                {
                    return RuntimeReply::error("STORAGE_ERROR", "Confirmed profile receipt is being recovered");
                }
                return Self::network_reply(
                    serde_json::json!({ "state": "confirmed", "transaction_id": transaction_id }),
                );
            }
            return RuntimeReply::error("CONFLICT", "Confirmation token or recovery fence changed");
        }
        // Confirm consumes the already admitted generation. Requiring the
        // global capability used by a new Plan here would make that same
        // generation block its own confirmation. The attached driver and
        // Coordinator recheck this generation's owner, readiness, revoke
        // fence, deadline, active nft/routes and core health below.
        if journal.state != xkeenwrt_recovery::State::Pending {
            return RuntimeReply::error("NOT_READY", "Pending network transaction is not confirmable");
        }
        let key = match networking::key::load(Path::new("/etc/xkeenwrt"), false) {
            Ok(key) => key,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Confirmation key is unavailable"),
        };
        let current_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
        let pending = match networking::transaction::pending_from_journal(
            &journal,
            &key,
            current_boot.trim(),
            xkeenwrt_recovery::boottime_ms().unwrap_or(0),
        ) {
            Ok(pending) if pending.confirm_token == confirm_token => pending,
            _ => return RuntimeReply::error("CONFLICT", "Confirmation token does not match pending transaction"),
        };
        drop(guard);
        let plan = match networking::plans::load(&pending.request.plan_id) {
            Ok(plan) => plan,
            Err(_) => return RuntimeReply::error("NOT_READY", "Prepared network plan is unavailable"),
        };
        let mut driver = networking::driver::OpenWrtDriver::new(
            &mut self.activation,
            &mut self.core,
            plan,
            self.incarnation_identity.clone(),
        );
        if let Err(error) = driver.attach_pending(&pending) {
            return Self::network_error(error);
        }
        let mut coordinator = networking::transaction::Coordinator::new(driver);
        let result = coordinator.confirm(transaction_id, confirm_token);
        let report = coordinator.driver().remote_report().cloned();
        drop(coordinator);
        if let Some(report) = &report {
            self.remote_check = Some((transaction_id.to_owned(), report.clone()));
        }
        let mut reply = match result {
            Ok(()) => {
                Self::network_reply(serde_json::json!({ "state": "confirmed", "transaction_id": transaction_id }))
            }
            Err(error) => Self::network_error(error),
        };
        if let Some(report) = report {
            let network = reply.network.get_or_insert_with(|| serde_json::json!({}));
            network["remote_check"] = serde_json::json!(report);
        }
        reply
    }
    fn network_disable(&mut self, idempotency_key: &str) -> RuntimeReply {
        use std::path::Path;
        if idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return RuntimeReply::error("INVALID", "Network idempotency key is invalid");
        }
        let journal = match networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal() {
            Ok(Some(journal)) => journal,
            Ok(None) => return RuntimeReply::error("CONFLICT", "No managed network generation is active"),
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal cannot be read safely"),
        };
        if matches!(
            journal.state,
            xkeenwrt_recovery::State::Pending | xkeenwrt_recovery::State::Revoked
        ) {
            let _guard = match Self::emergency_guard() {
                Ok(g) => g,
                Err(_) => return RuntimeReply::error("BUSY", "Gateway cancellation is settling"),
            };
            let mut fresh = match networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal() {
                Ok(Some(j)) if j.tx_id == journal.tx_id => j,
                _ => return RuntimeReply::error("CONFLICT", "Gateway generation changed"),
            };
            fresh.cancel_capture = true;
            if fresh.state == xkeenwrt_recovery::State::Pending {
                let generation = fresh.generation;
                if !fresh.revoke(generation) {
                    return RuntimeReply::error("CONFLICT", "Gateway generation changed");
                }
            }
            if xkeenwrt_recovery::write_journal(Path::new("/etc/xkeenwrt"), &fresh).is_err() {
                return RuntimeReply::error("STORAGE_ERROR", "Cancellation intent unavailable");
            }
            return Self::network_reply(serde_json::json!({"state":"cancelling","transaction_id":fresh.tx_id}));
        }
        let Some(active) = xkeenwrt_recovery::active::active_manifest(&journal) else {
            return RuntimeReply::error("CONFLICT", "No managed network generation is active");
        };
        let record = match networking::active::request(
            Path::new("/etc/xkeenwrt"),
            Path::new("/var/run/xkeenwrt/mutation.lock"),
            &active.owner_id,
            active.generation,
            xkeenwrt_recovery::active::Kind::DisableRequested,
            Some(idempotency_key),
            None,
        ) {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return RuntimeReply::error("BUSY", "Network recovery is handling another operation");
            }
            Err(_) => return RuntimeReply::error("CONFLICT", "Network generation changed or disable was rejected"),
        };
        Self::network_reply(serde_json::json!({
            "state": match record.phase {
                xkeenwrt_recovery::active::Phase::Completed => "completed",
                xkeenwrt_recovery::active::Phase::Error => "error",
                _ => "pending",
            },
            "event_id": record.event_id,
            "active_generation": record.generation,
            "outcome": record.outcome,
            "error_code": record.error_code,
        }))
    }
    fn finish_upgrade_for_control_plane(&mut self) -> Result<(), crate::configuration::ActivationError> {
        use crate::configuration::ActivationError;
        use std::{
            io::Read,
            os::{
                fd::AsRawFd,
                unix::fs::{MetadataExt, OpenOptionsExt},
            },
            path::Path,
        };
        use xkeenwrt_recovery::rescue::{UpgradePhase, UpgradeSpec};
        let dir = Path::new("/etc/xkeenwrt");
        let mut mutation_lock = Some(
            ipc::RuntimeLock::acquire(Path::new("/var/run/xkeenwrt/mutation.lock"))
                .map_err(|_| ActivationError::Unavailable)?,
        );
        let read = |path: &Path, max: u64| -> Result<Vec<u8>, ActivationError> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| ActivationError::Storage)?;
            let m = f.metadata().map_err(|_| ActivationError::Storage)?;
            if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 || m.len() > max {
                return Err(ActivationError::Storage);
            }
            let mut bytes = Vec::new();
            f.take(max + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ActivationError::Storage)?;
            if bytes.len() as u64 > max {
                return Err(ActivationError::Storage);
            }
            Ok(bytes)
        };
        let read_receipt = || -> Result<Option<xkeenwrt_recovery::LifecycleRequest>, ActivationError> {
            match std::fs::symlink_metadata(dir.join("removal.json")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(ActivationError::Storage),
                Ok(_) => (),
            }
            serde_json::from_slice(&read(&dir.join("removal.json"), 4096)?)
                .map(Some)
                .map_err(|_| ActivationError::Storage)
        };
        let check_receipt = |receipt: &xkeenwrt_recovery::LifecycleRequest,
                             owner: &str,
                             request_id: &str|
         -> Result<(), ActivationError> {
            if receipt.version != 1
                || receipt.owner_id != owner
                || receipt.request_id.as_deref() != Some(request_id)
                || receipt.kind != xkeenwrt_recovery::LifecycleKind::Upgrade
                || receipt.state != xkeenwrt_recovery::LifecycleState::CleanupComplete
            {
                return Err(ActivationError::Conflict);
            }
            Ok(())
        };
        let initial_receipt = read_receipt()?;
        let initial_intent = match xkeenwrt_recovery::rescue::upgrade_status() {
            Ok(intent) => intent,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && initial_receipt.is_none() => None,
            Err(_) => return Err(ActivationError::Unavailable),
        };
        if initial_receipt.is_none() && initial_intent.is_none() {
            return Ok(());
        }
        if !crate::platform::Platform::compatible_packages_in(Some(self.incarnation_cgroup.as_raw_fd())) {
            return Err(ActivationError::Unavailable);
        }
        let Some((new_helper, new_sha256, new_build_id)) =
            crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
        else {
            return Err(ActivationError::Unavailable);
        };
        let owner = String::from_utf8(read(&dir.join("owner-id"), 36)?).map_err(|_| ActivationError::Storage)?;
        if uuid::Uuid::parse_str(&owner)
            .map_err(|_| ActivationError::Storage)?
            .to_string()
            != owner
        {
            return Err(ActivationError::Storage);
        }
        let spec = if let Some(intent) = &initial_intent {
            let spec = &intent.spec;
            if spec.owner_id != owner || spec.new_sha256 != new_sha256 || spec.new_build_id != new_build_id {
                return Err(ActivationError::Conflict);
            }
            match &initial_receipt {
                Some(receipt) => check_receipt(receipt, &owner, &spec.request_id)?,
                None if intent.phase == UpgradePhase::Finalizing => (),
                None => return Err(ActivationError::Conflict),
            }
            spec.clone()
        } else {
            let receipt = initial_receipt.as_ref().ok_or(ActivationError::Conflict)?;
            let request_id = receipt.request_id.as_deref().ok_or(ActivationError::Conflict)?;
            check_receipt(receipt, &owner, request_id)?;
            let identity =
                String::from_utf8(read(&dir.join("rescue/identity"), 256)?).map_err(|_| ActivationError::Storage)?;
            let mut lines = identity.lines();
            if lines.next() != Some("xkeenwrt-rescue-v1") {
                return Err(ActivationError::Storage);
            }
            let old_build_id = lines
                .next()
                .and_then(|line| line.strip_prefix("build_id="))
                .ok_or(ActivationError::Storage)?
                .to_owned();
            let old_sha256 = lines
                .next()
                .and_then(|line| line.strip_prefix("sha256="))
                .ok_or(ActivationError::Storage)?
                .to_owned();
            if lines.next().is_some()
                || identity != format!("xkeenwrt-rescue-v1\nbuild_id={old_build_id}\nsha256={old_sha256}\n")
            {
                return Err(ActivationError::Storage);
            }
            let old = xkeenwrt_recovery::rescue::verify(&old_sha256, &old_build_id)
                .map_err(|_| ActivationError::Unavailable)?;
            drop(old);
            UpgradeSpec {
                owner_id: owner.clone(),
                request_id: request_id.to_owned(),
                old_sha256,
                old_build_id,
                new_sha256: new_sha256.clone(),
                new_build_id: new_build_id.to_owned(),
            }
        };
        if !spec.valid() {
            return Err(ActivationError::Conflict);
        }
        let mut adapter = upgrade_adapter::NativeUpgradeAdapter {
            incarnation: &self.incarnation_cgroup,
            identity: &self.incarnation_identity,
        };
        if initial_intent
            .as_ref()
            .is_none_or(|intent| intent.phase != UpgradePhase::Finalizing)
        {
            xkeenwrt_recovery::rescue::prepare_upgrade(&spec, &new_helper, &mut adapter)
                .map_err(|_| ActivationError::Unavailable)?;
            drop(mutation_lock.take());
            xkeenwrt_recovery::rescue::start_upgrade(&spec, &mut adapter).map_err(|_| ActivationError::Unavailable)?;
            mutation_lock = Some(
                ipc::RuntimeLock::acquire(Path::new("/var/run/xkeenwrt/mutation.lock"))
                    .map_err(|_| ActivationError::Unavailable)?,
            );
            if !crate::platform::Platform::compatible_packages_in(Some(self.incarnation_cgroup.as_raw_fd())) {
                return Err(ActivationError::Unavailable);
            }
            let Some((verified_after_start, sha_after_start, build_after_start)) =
                crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
            else {
                return Err(ActivationError::Unavailable);
            };
            let before = new_helper.metadata().map_err(|_| ActivationError::Unavailable)?;
            let after = verified_after_start
                .metadata()
                .map_err(|_| ActivationError::Unavailable)?;
            if sha_after_start != new_sha256
                || build_after_start != new_build_id
                || before.dev() != after.dev()
                || before.ino() != after.ino()
            {
                return Err(ActivationError::Unavailable);
            }
        }
        let current_intent = xkeenwrt_recovery::rescue::upgrade_status()
            .map_err(|_| ActivationError::Unavailable)?
            .ok_or(ActivationError::Conflict)?;
        if current_intent.spec != spec {
            return Err(ActivationError::Conflict);
        }
        let current_receipt = read_receipt()?;
        if let Some(receipt) = &current_receipt {
            check_receipt(receipt, &owner, &spec.request_id)?;
            xkeenwrt_recovery::rescue::finish_upgrade(&spec, &mut adapter).map_err(|_| ActivationError::Unavailable)?;
            self.activation.settle_after_upgrade(dir)?;
            xkeenwrt_recovery::verify_upgrade_after_integrity_check(dir, &owner, &spec.request_id)
                .map_err(|_| ActivationError::Conflict)?;
            xkeenwrt_recovery::finish_upgrade_after_integrity_check(dir, &owner, &spec.request_id)
                .map_err(|_| ActivationError::Conflict)?;
        } else if current_intent.phase != UpgradePhase::Finalizing {
            return Err(ActivationError::Conflict);
        }
        grant::ensure_core_cgroup().map_err(|_| ActivationError::Unavailable)?;
        xkeenwrt_recovery::rescue::clear_upgrade_fence(&spec, &mut adapter)
            .map_err(|_| ActivationError::Unavailable)?;
        drop(mutation_lock);
        self.ready = true;
        Ok(())
    }
    fn bootstrap_owner(dir: &std::path::Path) -> std::io::Result<()> {
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let _guard = ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock"))?;
        let owner = dir.join("owner-id");
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&owner)
        {
            Ok(mut f) => {
                let m = f.metadata()?;
                if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 || m.len() != 36 {
                    return Err(std::io::Error::other("invalid owner identity"));
                }
                let mut text = String::new();
                f.read_to_string(&mut text)?;
                let id = uuid::Uuid::parse_str(&text).map_err(std::io::Error::other)?;
                if id.to_string() != text {
                    return Err(std::io::Error::other("invalid owner identity"));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(dir.join("recovery.json")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err(std::io::Error::other("network state prevents fresh bootstrap")),
                }
                match std::fs::symlink_metadata(dir.join("network-never-enabled")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err(std::io::Error::other("unexpected bootstrap marker")),
                }
                match std::fs::symlink_metadata(dir.join("network-generation")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err(std::io::Error::other("unexpected network generation")),
                }
                // Owner first: a crash before marker publication is fail-closed on reinstall.
                crate::private_file::publish_private(&owner, uuid::Uuid::new_v4().to_string().as_bytes())?;
                crate::private_file::publish_private(&dir.join("network-generation"), b"0\n")?;
                crate::private_file::publish_private(&dir.join("network-never-enabled"), b"xkeenwrt-no-network-v1\n")
            }
            Err(e) => Err(e),
        }
    }
    fn manual_guard() -> Result<ipc::RuntimeLock, crate::configuration::ActivationError> {
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let guard = ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock"))
            .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
        core::ensure_no_lifecycle_request()?;
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open("/etc/xkeenwrt/recovery.json")
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(guard),
            Err(_) => return Err(crate::configuration::ActivationError::Storage),
        };
        let meta = file
            .metadata()
            .map_err(|_| crate::configuration::ActivationError::Storage)?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.nlink() != 1
            || meta.mode() & 0o777 != 0o600
            || meta.len() > 512 * 1024
        {
            return Err(crate::configuration::ActivationError::Storage);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(512 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| crate::configuration::ActivationError::Storage)?;
        if bytes.len() > 512 * 1024 {
            return Err(crate::configuration::ActivationError::Storage);
        }
        let journal: xkeenwrt_recovery::Journal =
            serde_json::from_slice(&bytes).map_err(|_| crate::configuration::ActivationError::Storage)?;
        let inactive_rollback =
            journal.state == xkeenwrt_recovery::State::RolledBack && journal.previous_good.is_none();
        let completed_disable = networking::active::settled_disable(&journal, std::path::Path::new("/etc/xkeenwrt"))
            .map_err(|_| crate::configuration::ActivationError::Storage)?;
        if !inactive_rollback && !completed_disable {
            return Err(crate::configuration::ActivationError::Conflict);
        }
        Ok(guard)
    }
    /// Startup may recover the manual editor journal while a confirmed
    /// network generation is active. Pending/revoked generations remain owned
    /// exclusively by the independent recovery helper.
    fn startup_guard() -> Result<ipc::RuntimeLock, crate::configuration::ActivationError> {
        let guard = ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock"))
            .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
        core::ensure_no_lifecycle_request()?;
        if let Some(journal) = networking::driver::OpenWrtDriver::<validator::ProcessValidator>::secure_journal()
            .map_err(|_| crate::configuration::ActivationError::Storage)?
        {
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| crate::configuration::ActivationError::Storage)?;
            let now = xkeenwrt_recovery::boottime_ms().map_err(|_| crate::configuration::ActivationError::Storage)?;
            if journal.decision(boot.trim(), now, false) != xkeenwrt_recovery::Decision::Settled {
                return Err(crate::configuration::ActivationError::Conflict);
            }
        }
        Ok(guard)
    }
    fn emergency_guard() -> Result<ipc::RuntimeLock, crate::configuration::ActivationError> {
        let guard = ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock"))
            .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
        core::ensure_no_lifecycle_request()?;
        Ok(guard)
    }
    fn stop_guard() -> Result<ipc::RuntimeLock, crate::configuration::ActivationError> {
        let guard = ipc::RuntimeLock::acquire_emergency(std::path::Path::new("/var/run/xkeenwrt/mutation.lock"))
            .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
        core::ensure_no_lifecycle_request()?;
        Ok(guard)
    }
    pub fn open(incarnation: &networking::incarnation::RuntimeIncarnation) -> std::io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let dir = std::path::Path::new("/etc/xkeenwrt");
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => std::fs::File::open("/etc")?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unsafe configuration directory",
            ));
        }
        Self::bootstrap_owner(dir)?;
        let secret = crate::private_file::load_or_create_bootstrap(&dir.join("controller-secret"))?;
        let store = crate::configuration::ConfigStore::new(dir.join("profiles"))
            .map_err(|_| std::io::Error::other("profile store unavailable"))?;
        let incarnation_cgroup = std::sync::Arc::new(incarnation.dir().try_clone()?);
        let activation = crate::configuration::Activation::new(
            store,
            validator::ProcessValidator::new(incarnation_cgroup.clone()),
            secret.clone(),
        );
        let mut core = core::ProcdCore::new(secret, incarnation_cgroup.clone());
        let ready = if core::deployment_allowed() && grant::ensure_core_cgroup().is_ok() {
            Self::startup_guard()
                .is_ok_and(|_guard| activation.recover(dir, &mut core).is_ok() && inputs::settle().is_ok())
        } else {
            false
        };
        let network_control = networking::control_visible(&incarnation_cgroup);
        let mut coordinator = Self {
            activation,
            core,
            ready,
            native_profile_ready: false,
            native_apply_ready: false,
            incarnation_cgroup,
            incarnation_identity: incarnation.identity().clone(),
            network_control,
            storage_ready: false,
            storage_attempt: None,
            remote_check: None,
        };
        coordinator.refresh_bootstrap();
        Ok(coordinator)
    }
    /// Independent startup maintenance, never called by an API status/preflight.
    pub(super) fn maintain_storage(&mut self) {
        if self.storage_ready
            || !self.native_apply_ready
            || self.storage_attempt.is_some_and(|t| t.elapsed().as_secs() < 30)
        {
            return;
        }
        self.storage_attempt = Some(std::time::Instant::now());
        let attempt = (|| {
            let _guard = Self::manual_guard()?;
            let owner = std::fs::read_to_string("/etc/xkeenwrt/owner-id")
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
            let identity = networking::helper::read_idle(std::path::Path::new("/var/run/xkeenwrt/recovery.idle"))
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
            networking::helper::verify_supervisor(&identity, owner.trim(), boot.trim(), &self.incarnation_cgroup)
                .map_err(|_| crate::configuration::ActivationError::Unavailable)?;
            self.activation
                .migrate_payloads_after_handoff(std::path::Path::new("/etc/xkeenwrt"))
        })();
        // A storage error never removes Stop/emergency cleanup availability.
        self.storage_ready = attempt.is_ok();
    }
    fn refresh_bootstrap(&mut self) {
        use std::os::fd::AsRawFd;
        if self.native_apply_ready || !core::deployment_allowed() {
            return;
        }
        // An APK upgrade leaves a verified, quiescent lifecycle receipt. Finish
        // only that existing handoff before advertising validation: requiring
        // Start here would prevent checking a saved profile with Mihomo stopped.
        // The handoff rechecks package/owner/helper proofs and never starts core.
        if !self.ready && (self.finish_upgrade_for_control_plane().is_err() || !self.ready) {
            return;
        }
        // post-install can start us before APK publishes its final database.
        // Retry the exact package proof on Status; never cache that race forever.
        let Some((file, digest, build_id)) =
            crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
        else {
            return;
        };
        self.native_profile_ready = true;
        let prepared = Self::startup_guard()
            .is_ok_and(|_guard| xkeenwrt_recovery::rescue::provision(&file, &digest, build_id).is_ok());
        if prepared && networking::helper::start(&self.incarnation_cgroup).is_ok() {
            self.native_apply_ready = true;
            self.network_control = networking::control_visible(&self.incarnation_cgroup);
        }
    }
    pub fn command(&mut self, command: RuntimeCommand) -> RuntimeReply {
        use crate::configuration::ActivationError;
        let map = |error| match error {
            ActivationError::CoreMissing => {
                RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                    crate::mihomo::providers::diagnostic::Reason::CoreMissing,
                ))
            }
            ActivationError::CoreIntegrity => {
                RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                    crate::mihomo::providers::diagnostic::Reason::CoreIntegrity,
                ))
            }
            ActivationError::CoreRejected => {
                RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                    crate::mihomo::providers::diagnostic::Reason::CoreRejected,
                ))
            }
            ActivationError::ValidatorUnavailable => {
                RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                    crate::mihomo::providers::diagnostic::Reason::ValidatorUnavailable,
                ))
            }
            ActivationError::Conflict => RuntimeReply::error("CONFLICT", "Revision or candidate changed"),
            ActivationError::Invalid => RuntimeReply::diagnosed(crate::mihomo::providers::diagnostic::Diagnostic::new(
                crate::mihomo::providers::diagnostic::Reason::Policy,
            )),
            ActivationError::Unavailable => {
                RuntimeReply::error("NOT_READY", "Required validation or core service unavailable")
            }
            ActivationError::Storage => RuntimeReply::error("STORAGE_ERROR", "Transaction storage unavailable"),
            ActivationError::CommitUncertain => {
                RuntimeReply::error("COMMIT_UNCERTAIN", "Restart runtime to reconcile transaction")
            }
        };
        if matches!(command, RuntimeCommand::Status) {
            self.refresh_bootstrap();
            let _guard = match ipc::RuntimeLock::acquire(std::path::Path::new("/var/run/xkeenwrt/mutation.lock")) {
                Ok(guard) => guard,
                Err(_) => return RuntimeReply::error("BUSY", "Network state is being updated"),
            };
            let running = self.core.running().ok();
            let mut reply = self.status_reply(running);
            let network = self.network_status_locked();
            if network.code != "OK" {
                return network;
            }
            reply.network = network.network;
            let inputs = self.inputs_status_with_running(running);
            if inputs.code != "OK" {
                return inputs;
            }
            reply.inputs = inputs.network;
            return reply;
        }
        if let RuntimeCommand::SelectCore { version } = &command {
            // Downloads run outside the mutation lock. Only this fixed IPC command
            // may switch the verified executable, after rechecking all live state.
            if !self.ready || !core::deployment_allowed() {
                return RuntimeReply::error("NOT_READY", "Runtime is unavailable");
            }
            let _guard = match Self::manual_guard() {
                Ok(guard) => guard,
                Err(error) => return map(error),
            };
            if self.core.running().ok() != Some(false) {
                return RuntimeReply::error("CONFLICT", "Stop Mihomo before changing its version");
            }
            self.activation.discard_candidate();
            if networking::plans::invalidate().is_err() {
                return RuntimeReply::error("STORAGE_ERROR", "Could not invalidate the previous network plan");
            }
            let result = crate::core_update::select_verified_version(version, || {
                match self
                    .activation
                    .current_manual_bundle(std::path::Path::new("/etc/xkeenwrt"))
                {
                    Ok(bundle) => self.activation.revalidate_bundle(&bundle),
                    Err(ActivationError::Conflict) => Ok(()),
                    Err(error) => Err(error),
                }
            });
            return result.map_or_else(
                |_| RuntimeReply::error("NOT_READY", "Version change failed; previous core retained"),
                |_| RuntimeReply::error("OK", "Core version selected without starting it"),
            );
        }
        if let RuntimeCommand::ResumeAfterReinstall { request_id } = &command {
            return resume::resume_after_reinstall(self, request_id);
        }
        if matches!(
            command,
            RuntimeCommand::ServiceStart { .. }
                | RuntimeCommand::ServiceStop
                | RuntimeCommand::ServiceRestart { .. }
                | RuntimeCommand::ServiceApply { .. }
                | RuntimeCommand::ExplicitSet { .. }
                | RuntimeCommand::NetworkDisable { .. }
                | RuntimeCommand::NetworkApply { .. }
                | RuntimeCommand::Apply { .. }
                | RuntimeCommand::Start
                | RuntimeCommand::Stop
                | RuntimeCommand::Restart
        ) {
            let _guard = match Self::emergency_guard() {
                Ok(g) => g,
                Err(_) => return RuntimeReply::error("BUSY", "Input settlement is in progress"),
            };
            if self
                .activation
                .settle_network_profile(std::path::Path::new("/etc/xkeenwrt"))
                .is_err()
                || inputs::settle().is_err()
            {
                return RuntimeReply::error("STORAGE_ERROR", "Confirmed input selection could not be settled");
            }
        }
        match &command {
            RuntimeCommand::ServiceStart { peer } => return self.service_start(*peer),
            RuntimeCommand::ServiceStop => return self.service_stop(),
            RuntimeCommand::ServiceRestart { peer } => return self.service_restart(*peer),
            RuntimeCommand::ServiceApply {
                profile_id,
                revision,
                candidate_id,
                idempotency_key,
                peer,
            } => return self.service_apply(profile_id, revision, candidate_id, idempotency_key, *peer),
            RuntimeCommand::ExplicitSet { binding, peer } => {
                return self.explicit_set(binding.clone(), *peer);
            }
            RuntimeCommand::InputsStatus => return self.inputs_status(),
            RuntimeCommand::NetworkStatus => return self.network_status(),
            RuntimeCommand::Compatibility { peer } => return self.compatibility_reply(*peer),
            RuntimeCommand::NetworkDisable { idempotency_key } => {
                {
                    let _guard = match Self::emergency_guard() {
                        Ok(g) => g,
                        Err(_) => return RuntimeReply::error("BUSY", "Input choice is changing"),
                    };
                    let mut chosen = match inputs::load() {
                        Ok(s) => s,
                        Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Input choice unavailable"),
                    };
                    chosen.gateway = false;
                    if inputs::save(&chosen).is_err() {
                        return RuntimeReply::error("STORAGE_ERROR", "Input choice could not be persisted");
                    }
                }
                return self.network_disable(idempotency_key);
            }
            RuntimeCommand::NetworkPlan { request } => return self.network_plan(request.clone()),
            RuntimeCommand::NetworkApply {
                plan_id,
                idempotency_key,
            } => {
                return self.network_apply(plan_id, idempotency_key);
            }
            RuntimeCommand::NetworkConfirm {
                transaction_id,
                confirm_token,
            } => {
                return self.network_confirm(transaction_id, confirm_token);
            }
            _ => (),
        }
        if let RuntimeCommand::CancelCandidate {
            profile_id,
            revision,
            candidate_id,
        } = &command
        {
            self.activation.cancel_candidate(profile_id, revision, candidate_id);
            return RuntimeReply::error("OK", "candidate cancelled");
        }
        let provider_prior_assets = if let RuntimeCommand::RefreshProvider {
            profile_id, revision, ..
        } = &command
        {
            let prior = (|| {
                let bundle = self
                    .activation
                    .current_manual_bundle(std::path::Path::new("/etc/xkeenwrt"))?;
                if bundle.meta.profile_id != *profile_id || bundle.meta.revision != *revision {
                    return Err(crate::configuration::ActivationError::Conflict);
                }
                Ok(bundle.assets)
            })();
            self.activation.discard_candidate();
            Some(prior)
        } else {
            None
        };
        let mut applying_candidate = if let RuntimeCommand::Apply {
            profile_id,
            revision,
            candidate_id,
            ..
        } = &command
        {
            let candidate = self
                .activation
                .check_candidate(profile_id, revision, candidate_id)
                .and_then(|()| self.activation.candidate_bundle(profile_id, revision, candidate_id));
            self.activation.discard_candidate();
            Some(candidate)
        } else {
            None
        };
        if matches!(command, RuntimeCommand::Validate { .. }) {
            self.activation.discard_candidate();
        }
        if matches!(command, RuntimeCommand::Stop) {
            let _guard = match Self::stop_guard() {
                Ok(guard) => guard,
                Err(error) => return map(error),
            };
            return match self.activation.emergency_stop(&mut self.core) {
                Ok(()) => RuntimeReply::error("OK", "stopped"),
                Err(error) => map(error),
            };
        }
        if matches!(command, RuntimeCommand::Restart) && self.core.running().ok() != Some(true) {
            return RuntimeReply::error("CONFLICT", "Restart requires a running Mihomo service");
        }
        if matches!(command, RuntimeCommand::Start | RuntimeCommand::Restart)
            && core::deployment_allowed()
            && let Err(error) = self.finish_upgrade_for_control_plane()
        {
            return map(error);
        }
        if !self.ready || !core::deployment_allowed() {
            return RuntimeReply::error("NOT_READY", "Runtime deployment is not enabled");
        }
        if matches!(
            command,
            RuntimeCommand::Validate { .. }
                | RuntimeCommand::RefreshProvider { .. }
                | RuntimeCommand::ProviderContent { .. }
                | RuntimeCommand::EditProvider { .. }
                | RuntimeCommand::Apply { .. }
                | RuntimeCommand::Start
                | RuntimeCommand::Restart
                | RuntimeCommand::NetworkPlan { .. }
                | RuntimeCommand::NetworkApply { .. }
        ) && !{
            use std::os::fd::AsRawFd;
            crate::platform::Platform::compatible_packages_in(Some(self.incarnation_cgroup.as_raw_fd()))
        } {
            return RuntimeReply::error("PACKAGE_MISMATCH", "Installed packages do not match this build");
        }
        let _manual_guard = if matches!(
            command,
            RuntimeCommand::Apply { .. }
                | RuntimeCommand::Start
                | RuntimeCommand::Stop
                | RuntimeCommand::Restart
                | RuntimeCommand::EditProvider { .. }
        ) {
            match Self::manual_guard() {
                Ok(guard) => Some(guard),
                Err(e) => return map(e),
            }
        } else {
            None
        };
        if let RuntimeCommand::Apply {
            profile_id,
            revision,
            candidate_id,
            idempotency_key,
        } = &command
        {
            match self.activation.repeated_transaction(
                std::path::Path::new("/etc/xkeenwrt"),
                profile_id,
                revision,
                candidate_id,
                idempotency_key,
            ) {
                Ok(Some(transaction)) => {
                    let mut reply = RuntimeReply::error("OK", "committed");
                    reply.transaction = Some(transaction);
                    return reply;
                }
                Ok(None) => (),
                Err(error) => return map(error),
            }
            if let Some(Err(error)) = applying_candidate.as_ref() {
                return map(error.clone());
            }
        }
        if matches!(command, RuntimeCommand::Start | RuntimeCommand::Restart)
            && self
                .activation
                .current_manual_bundle(std::path::Path::new("/etc/xkeenwrt"))
                .is_err()
        {
            return RuntimeReply::error("CONFLICT", "No committed manual generation is available");
        }
        if matches!(
            command,
            RuntimeCommand::Apply { .. } | RuntimeCommand::Start | RuntimeCommand::Restart
        ) {
            use std::os::fd::AsRawFd;
            if let Err(error) = core::ensure_no_lifecycle_request() {
                return map(error);
            }
            let Some((pinned, digest, build_id)) =
                crate::platform::Platform::verified_recovery(self.incarnation_cgroup.as_raw_fd())
            else {
                return RuntimeReply::error("RESCUE_NOT_READY", "Persistent rescue cannot be verified");
            };
            if let Err(error) = core::ensure_no_lifecycle_request() {
                return map(error);
            }
            if xkeenwrt_recovery::rescue::provision(&pinned, &digest, build_id).is_err() {
                return RuntimeReply::error("RESCUE_NOT_READY", "Persistent rescue cannot be provisioned");
            }
            if let Err(error) = core::ensure_no_lifecycle_request() {
                return map(error);
            }
        }
        match command {
            RuntimeCommand::Validate { profile_id, revision } => {
                let mut diagnostic = None;
                match self.activation.validate_with_loader(&profile_id, &revision, |config| {
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                let runtime = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .map_err(|_| ActivationError::Unavailable)?;
                                let staged = runtime
                                    .block_on(crate::mihomo::providers::prepare_profile_assets(config, &profile_id))
                                    .map_err(|error| {
                                        diagnostic = Some(error.diagnostic());
                                        ActivationError::Unavailable
                                    })?;
                                Ok((staged.config, staged.files))
                            })
                            .join()
                            .unwrap_or(Err(ActivationError::Unavailable))
                    })
                }) {
                    Ok(validation) => {
                        let mut reply = RuntimeReply::error("OK", "validated");
                        reply.validation = Some(validation);
                        reply
                    }
                    Err(e) => match diagnostic {
                        Some(d) => RuntimeReply::diagnosed(d),
                        None => map(e),
                    },
                }
            }
            RuntimeCommand::RefreshProvider {
                profile_id,
                revision,
                provider_id,
            } => {
                let prior = match provider_prior_assets {
                    Some(Ok(p)) => p,
                    Some(Err(e)) => return map(e),
                    None => return map(ActivationError::Conflict),
                };
                if prior.is_empty() {
                    return map(ActivationError::Conflict);
                }
                let mut diagnostic = None;
                match self.activation.validate_with_loader(&profile_id, &revision, |config| {
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                let runtime = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .map_err(|_| ActivationError::Unavailable)?;
                                let staged = runtime
                                    .block_on(crate::mihomo::providers::refresh_profile_assets(
                                        config,
                                        &profile_id,
                                        &provider_id,
                                        &prior,
                                    ))
                                    .map_err(|error| {
                                        diagnostic = Some(error.diagnostic());
                                        ActivationError::Unavailable
                                    })?;
                                Ok((staged.config, staged.files))
                            })
                            .join()
                            .unwrap_or(Err(ActivationError::Unavailable))
                    })
                }) {
                    Ok(validation) => {
                        let mut reply = RuntimeReply::error("OK", "validated");
                        reply.validation = Some(validation);
                        reply
                    }
                    Err(e) => match diagnostic {
                        Some(d) => RuntimeReply::diagnosed(d),
                        None => map(e),
                    },
                }
            }
            RuntimeCommand::ProviderContent {
                profile_id,
                revision,
                provider_id,
            } => {
                match self.activation.current_provider_asset(
                    std::path::Path::new("/etc/xkeenwrt"),
                    &profile_id,
                    &revision,
                    &provider_id,
                ) {
                    Ok(content) => {
                        let mut reply = RuntimeReply::error("OK", "provider content loaded");
                        reply.provider_content = Some(content);
                        reply
                    }
                    Err(error) => map(error),
                }
            }
            RuntimeCommand::EditProvider {
                profile_id,
                revision,
                provider_id,
                content,
            } => {
                // Editing must first save an immutable local resource and a
                // new source revision. A remote cache is never an edit target.
                let _ = (profile_id, revision, provider_id, content);
                RuntimeReply::error("UNSUPPORTED", "Save a local resource and apply its profile revision")
            }
            RuntimeCommand::Apply {
                profile_id,
                revision,
                candidate_id,
                idempotency_key,
            } => match applying_candidate
                .take()
                .unwrap_or(Err(ActivationError::Conflict))
                .and_then(|bundle| {
                    if self.core.running()? {
                        self.activation.compose_bundle(
                            &bundle,
                            profile_policy::InputsOverlay {
                                explicit: inputs::load()?.explicit,
                                gateway: None,
                            },
                        )?;
                    }
                    self.activation.apply_bundle(
                        std::path::Path::new("/etc/xkeenwrt"),
                        &mut self.core,
                        crate::configuration::ManualApplyRequest {
                            bundle,
                            profile_id,
                            revision,
                            candidate_id,
                            idempotency_key,
                        },
                    )
                }) {
                Ok(transaction) => {
                    let mut reply = RuntimeReply::error("OK", "committed");
                    reply.transaction = Some(transaction);
                    reply
                }
                Err(e) => {
                    if e == ActivationError::CommitUncertain {
                        self.ready = false;
                    }
                    map(e)
                }
            },
            RuntimeCommand::Start => self
                .activation
                .start(std::path::Path::new("/etc/xkeenwrt"), &mut self.core)
                .map_or_else(map, |_| RuntimeReply::error("OK", "started")),
            RuntimeCommand::Restart => self
                .activation
                .start(std::path::Path::new("/etc/xkeenwrt"), &mut self.core)
                .map_or_else(map, |_| RuntimeReply::error("OK", "restarted")),
            RuntimeCommand::Stop => self
                .activation
                .stop(std::path::Path::new("/etc/xkeenwrt"), &mut self.core)
                .map_or_else(map, |_| RuntimeReply::error("OK", "stopped")),
            other => RuntimeReply::for_command(other),
        }
    }
}

pub(crate) mod process;
mod resources;

pub mod grant;

/// The profile an operation will run, as (payload bytes, provider count).
/// A validated candidate named by the request wins: Apply on a running
/// gateway snapshots and starts the candidate, while the store already holds
/// its newer revision, so the applied profile no longer verifies. Without a
/// candidate, Start and Restart run the verified applied profile.
fn operation_profile(accepted: Option<(u64, usize)>, candidate: Option<(u64, usize)>) -> Option<(u64, usize)> {
    candidate.or(accepted)
}

#[cfg(test)]
mod operation_profile_tests {
    use super::operation_profile;

    #[test]
    fn apply_on_running_gateway_uses_candidate_when_applied_profile_is_stale() {
        assert_eq!(operation_profile(None, Some((4096, 2))), Some((4096, 2)));
    }

    #[test]
    fn candidate_replaces_applied_profile_in_forecast() {
        assert_eq!(operation_profile(Some((100, 0)), Some((4096, 2))), Some((4096, 2)));
    }

    #[test]
    fn start_without_candidate_runs_applied_profile() {
        assert_eq!(operation_profile(Some((100, 1)), None), Some((100, 1)));
    }

    #[test]
    fn no_applied_profile_and_no_candidate_is_profile_required() {
        assert_eq!(operation_profile(None, None), None);
    }
}
