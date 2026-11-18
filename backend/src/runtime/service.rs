//! Normal UI service control owns both Mihomo and LAN interception. The
//! existing transaction, confirmation and rescue contracts remain authoritative.
use super::{Coordinator, NetworkPlanRequest, RuntimeReply, networking, validator};
use crate::configuration::ManualCore;
use std::{net::Ipv4Addr, path::Path};
use xkeenwrt_recovery::State;

type Driver = networking::driver::OpenWrtDriver<'static, validator::ProcessValidator>;
const CONFIG: &str = "/etc/xkeenwrt";

impl Coordinator {
    pub(super) fn service_start(&mut self, peer_ipv4: Ipv4Addr) -> RuntimeReply {
        self.refresh_bootstrap();
        let journal = match Driver::secure_journal() {
            Ok(journal) => journal,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal is unavailable"),
        };
        if let Some(journal) = &journal {
            if journal.state == State::Pending {
                // Recover the same token after a lost response. Confirmation
                // still verifies the exact generation, health, deadline and fence.
                let pending = (|| {
                    let key = networking::key::load(Path::new(CONFIG), false).ok()?;
                    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
                    networking::transaction::pending_from_journal(
                        journal,
                        &key,
                        boot.trim(),
                        xkeenwrt_recovery::boottime_ms().ok()?,
                    )
                    .ok()
                })();
                return match pending {
                    Some(p) => Self::network_reply(serde_json::json!({"state":"pending",
                        "transaction_id":p.transaction_id,"confirm_token":p.confirm_token})),
                    None => RuntimeReply::error("NOT_READY", "Network rollback is in progress"),
                };
            }
            if Driver::active_manifest(journal).is_some() {
                let status = self.network_status();
                return if status.network.as_ref().and_then(|n| n["state"].as_str()) == Some("active") {
                    status
                } else {
                    RuntimeReply::error("CONFLICT", "Restart the service to restore LAN routing")
                };
            }
        }
        if !self.ready || !super::core::deployment_allowed() {
            return RuntimeReply::error("NOT_READY", "Native service control is unavailable");
        }
        {
            let _guard = match super::ipc::RuntimeLock::acquire(Path::new("/var/run/xkeenwrt/mutation.lock")) {
                Ok(guard) => guard,
                Err(_) => return RuntimeReply::error("BUSY", "Network state is being updated"),
            };
            let report = self.compatibility_report(peer_ipv4, None);
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
        }
        let candidate = {
            let _guard = match Self::manual_guard() {
                Ok(guard) => guard,
                Err(_) => return RuntimeReply::error("BUSY", "Network recovery is still settling"),
            };
            match self.activation.stage_committed(Path::new(CONFIG)) {
                Ok(candidate) => candidate,
                Err(_) => {
                    return RuntimeReply::error("CONFLICT", "Apply the saved profile before starting LAN routing");
                }
            }
        };
        let lan = (|| {
            let bytes =
                networking::read::query(networking::read::Query::NetworkStatus, &self.incarnation_cgroup).ok()?;
            let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let matches: Vec<_> = value["interface"]
                .as_array()?
                .iter()
                .filter(|entry| entry["interface"] == "lan" && entry["up"] == true)
                .collect();
            let [entry] = matches.as_slice() else {
                return None;
            };
            Some(entry["l3_device"].as_str()?.to_owned())
        })();
        let Some(lan_interface) = lan else {
            return RuntimeReply::error("UNSUPPORTED", "The trusted LAN interface is unavailable");
        };
        let plan = self.network_plan(NetworkPlanRequest {
            profile_id: candidate.profile_id,
            expected_revision: candidate.revision,
            candidate_id: candidate.candidate_id,
            lan_interface,
            selected_ipv4: peer_ipv4,
            management_ipv4: peer_ipv4,
            peer_ipv4,
            selected_ipv6: Vec::new(),
            management_ipv6: Vec::new(),
            ipv6_policy: "block_external".into(),
            failure_policy: "direct_on_failure".into(),
        });
        if plan.code != "OK" {
            return plan;
        }
        let Some(plan_id) = plan.network.as_ref().and_then(|n| n["plan_id"].as_str()) else {
            return RuntimeReply::error("NOT_READY", "LAN plan is unavailable");
        };
        self.network_apply(plan_id, &uuid::Uuid::new_v4().to_string())
    }

    pub(super) fn service_stop(&mut self) -> RuntimeReply {
        let journal = match Driver::secure_journal() {
            Ok(journal) => journal,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal is unavailable"),
        };
        if let Some(journal) = journal {
            if matches!(journal.state, State::Pending | State::Revoked) {
                let _guard = match Self::emergency_guard() {
                    Ok(guard) => guard,
                    Err(_) => return RuntimeReply::error("BUSY", "Network recovery is in progress"),
                };
                let fresh = Driver::secure_journal();
                if let Ok(Some(mut fresh)) = fresh {
                    if fresh.tx_id != journal.tx_id {
                        return RuntimeReply::error("BUSY", "Network generation changed");
                    }
                    if fresh.state == State::Pending
                        && fresh.revoke(journal.generation)
                        && xkeenwrt_recovery::write_journal(Path::new(CONFIG), &fresh).is_err()
                    {
                        return RuntimeReply::error("STORAGE_ERROR", "Could not persist network cancellation");
                    }
                } else {
                    return RuntimeReply::error("STORAGE_ERROR", "Network journal is unavailable");
                }
                return Self::network_reply(serde_json::json!({"state":"stopping"}));
            }
            if Driver::active_manifest(&journal).is_some() {
                let disabled = self.network_disable(&format!("service-stop-{}", journal.tx_id));
                if disabled.code != "OK" {
                    return disabled;
                }
                return Self::network_reply(serde_json::json!({"state":"stopping"}));
            }
            // Stop the listener only after a fresh absence check. A lingering
            // interception table must never be hidden by a successful Stop.
            let status = self.network_status();
            if status.network.as_ref().and_then(|n| n["state"].as_str()) != Some("inactive") {
                return RuntimeReply::error("BUSY", "Waiting for LAN interception cleanup");
            }
        }
        let _guard = match Self::stop_guard() {
            Ok(guard) => guard,
            Err(_) => return RuntimeReply::error("BUSY", "Network recovery is still settling"),
        };
        match self.activation.emergency_stop(&mut self.core) {
            Ok(()) => match xkeenwrt_recovery::input_state::settle_stopped() {
                Ok(()) => Self::network_reply(serde_json::json!({"state":"stopped"})),
                Err(_) => RuntimeReply::error("STORAGE_ERROR", "Input cleanup receipt unavailable"),
            },
            Err(_) => RuntimeReply::error("NOT_READY", "Mihomo did not stop"),
        }
    }
}

impl Coordinator {
    fn main_lan(&self) -> Result<(String, Ipv4Addr, String), &'static str> {
        use networking::read::{self, Query};
        let data =
            read::query(Query::NetworkStatus, &self.incarnation_cgroup).map_err(|_| "LAN inventory unavailable")?;
        let net: serde_json::Value = serde_json::from_slice(&data).map_err(|_| "LAN inventory invalid")?;
        let entries: Vec<_> = net["interface"]
            .as_array()
            .ok_or("LAN inventory missing")?
            .iter()
            .filter(|i| i["interface"] == "lan" && i["up"] == true)
            .collect();
        let [lan] = entries.as_slice() else {
            return Err("Trusted LAN is ambiguous");
        };
        let name = lan["l3_device"].as_str().ok_or("LAN interface missing")?;
        let addresses =
            read::query(Query::Addresses, &self.incarnation_cgroup).map_err(|_| "Address inventory unavailable")?;
        let facts =
            networking::inventory::address_facts(&addresses, name).map_err(|_| "LAN addresses are unsupported")?;
        let [cidr] = facts.lan_cidrs.as_slice() else {
            return Err("LAN subnet is ambiguous");
        };
        let scope = xkeenwrt_recovery::lan_network(cidr).ok_or("LAN subnet invalid")?;
        Ok((name.into(), facts.lan_address, scope))
    }
    pub(super) fn inputs_status(&mut self) -> RuntimeReply {
        let running = self.core.running().ok();
        self.inputs_status_with_running(running)
    }
    pub(super) fn inputs_status_with_running(&mut self, running: Option<bool>) -> RuntimeReply {
        let lan = self.main_lan().ok();
        let grant = match super::grant::read_current() {
            Ok(g) => g,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Input launch state is unavailable"),
        };
        let chosen = super::inputs::load().ok();
        let explicit = grant
            .as_ref()
            .filter(|g| g.desired_running && running == Some(true))
            .and_then(|g| g.overlay.explicit());
        let guarded = explicit.is_some_and(|e| super::input_guard::verify(e, &self.incarnation_cgroup).is_ok());
        Self::network_reply(
            serde_json::json!({"core": match running {Some(true)=>"running",Some(false)=>"stopped",None=>"unknown"},
            "explicit":if explicit.is_some(){if guarded{"active"}else{"degraded"}}else{"inactive"},
            "explicit_selected":chosen.as_ref().is_some_and(|s|s.explicit.is_some()),
            "gateway_selected":chosen.as_ref().is_some_and(|s|s.gateway),
            "trusted_bindings":lan.map(|(interface,address,_)|vec![serde_json::json!({"interface":interface,"address":address,"port":7890})]).unwrap_or_default()}),
        )
    }
    fn replace_gateway_candidate(
        &mut self, profile_id: &str, revision: &str, candidate_id: &str, key: &str, peer_ipv4: Ipv4Addr,
        explicit: Option<Option<profile_policy::ExplicitOverlay>>,
    ) -> RuntimeReply {
        let (lan, _, _) = match self.main_lan() {
            Ok(l) => l,
            Err(m) => return RuntimeReply::error("UNSUPPORTED", m),
        };
        let plan = self.network_plan_inputs(
            NetworkPlanRequest {
                profile_id: profile_id.into(),
                expected_revision: revision.into(),
                candidate_id: candidate_id.into(),
                lan_interface: lan,
                selected_ipv4: peer_ipv4,
                management_ipv4: peer_ipv4,
                peer_ipv4,
                selected_ipv6: vec![],
                management_ipv6: vec![],
                ipv6_policy: "block_external".into(),
                failure_policy: "direct_on_failure".into(),
            },
            explicit,
        );
        if plan.code != "OK" {
            return plan;
        }
        let Some(id) = plan.network.as_ref().and_then(|n| n["plan_id"].as_str()) else {
            return RuntimeReply::error("NOT_READY", "LAN plan unavailable");
        };
        self.network_apply(id, key)
    }
    pub(super) fn service_apply(
        &mut self, profile_id: &str, revision: &str, candidate_id: &str, key: &str, peer_ipv4: Ipv4Addr,
    ) -> RuntimeReply {
        match self
            .activation
            .repeated_transaction(Path::new(CONFIG), profile_id, revision, candidate_id, key)
        {
            Ok(Some(transaction)) => {
                let mut reply = RuntimeReply::error("OK", "committed");
                reply.transaction = Some(transaction);
                return reply;
            }
            Err(crate::configuration::ActivationError::Unavailable) => (),
            Err(_) => return RuntimeReply::error("CONFLICT", "Profile apply binding changed"),
            Ok(None) => (),
        }
        if let Ok(Some(j)) = Driver::secure_journal()
            && j.state == State::Pending
            && j.profile_id == profile_id
            && j.revision == revision
            && j.idempotency_key == key
        {
            if networking::plans::load(&j.plan_id).is_ok_and(|p| p.manual_candidate_id == candidate_id) {
                return self.service_start(peer_ipv4);
            }
            return RuntimeReply::error("CONFLICT", "Pending profile binding changed");
        }
        let active = match Driver::secure_journal() {
            Ok(j) => j.as_ref().and_then(Driver::active_manifest).is_some(),
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal unavailable"),
        };
        if active {
            self.replace_gateway_candidate(profile_id, revision, candidate_id, key, peer_ipv4, None)
        } else {
            self.command(super::RuntimeCommand::Apply {
                profile_id: profile_id.into(),
                revision: revision.into(),
                candidate_id: candidate_id.into(),
                idempotency_key: key.into(),
            })
        }
    }
    pub(super) fn explicit_set(&mut self, binding: Option<super::ExplicitBinding>, peer: Ipv4Addr) -> RuntimeReply {
        self.refresh_bootstrap();
        if !self.ready || !self.native_apply_ready || !super::core::deployment_allowed() {
            return RuntimeReply::error("NOT_READY", "Native input control unavailable");
        }
        let target = if let Some(binding) = binding {
            let (lan, address, scope) = match self.main_lan() {
                Ok(l) => l,
                Err(m) => return RuntimeReply::error("UNSUPPORTED", m),
            };
            if binding.interface != lan
                || binding.address != address
                || !xkeenwrt_recovery::valid_lan_scope(&scope, address, peer)
            {
                return RuntimeReply::error("INVALID", "Choose the trusted LAN binding");
            }
            let id = {
                let _g = match Self::emergency_guard() {
                    Ok(g) => g,
                    Err(_) => return RuntimeReply::error("BUSY", "Input state is changing"),
                };
                match networking::identity::reserve(Path::new(CONFIG)) {
                    Ok(id) => id,
                    Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Input owner unavailable"),
                }
            };
            Some(profile_policy::ExplicitOverlay {
                lan_ifname: lan,
                lan_ipv4: address,
                lan_scope: scope,
                port: 7890,
                owner_id: id.owner_id,
                generation: id.generation,
            })
        } else {
            None
        };
        let journal = match Driver::secure_journal() {
            Ok(j) => j,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Network journal unavailable"),
        };
        if journal
            .as_ref()
            .is_some_and(|j| j.state == State::Pending || j.state == State::Revoked)
        {
            return RuntimeReply::error("BUSY", "Network confirmation or rollback pending");
        }
        if journal.as_ref().and_then(Driver::active_manifest).is_some() {
            let candidate = match self.activation.stage_committed(Path::new(CONFIG)) {
                Ok(c) => c,
                Err(_) => return RuntimeReply::error("CONFLICT", "Accepted profile unavailable"),
            };
            return self.replace_gateway_candidate(
                &candidate.profile_id,
                &candidate.revision,
                &candidate.candidate_id,
                &uuid::Uuid::new_v4().to_string(),
                peer,
                Some(target),
            );
        }
        let _guard = match Self::manual_guard() {
            Ok(g) => g,
            Err(_) => return RuntimeReply::error("BUSY", "Input recovery is settling"),
        };
        use xkeenwrt_recovery::input_state::{self, Phase, Transition};
        match input_state::load_transition() {
            Ok(Some(t)) if t.phase == Phase::Applying => {
                return RuntimeReply::error("BUSY", "Explicit recovery is pending");
            }
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Explicit transition unavailable"),
            _ => (),
        }
        let base = match self.activation.current_manual_bundle(Path::new(CONFIG)) {
            Ok(b) => b,
            Err(_) => return RuntimeReply::error("CONFLICT", "Apply the exact saved profile first"),
        };
        let was_running = match self.core.running() {
            Ok(r) => r,
            Err(_) => return RuntimeReply::error("NOT_READY", "Core state unavailable"),
        };
        let previous = match super::grant::read_current() {
            Ok(g) => g.map(|g| g.overlay.explicit().cloned()).unwrap_or(None),
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Previous input state unavailable"),
        };
        if target.is_some() && previous.is_none() && !super::input_guard::port_free(&self.incarnation_cgroup) {
            return RuntimeReply::error("RESOURCE_CONFLICT", "Mixed listener port is occupied");
        }
        let inputs = profile_policy::InputsOverlay {
            explicit: target.clone(),
            gateway: None,
        };
        let next = match self.activation.compose_bundle(&base, inputs) {
            Ok(b) => b,
            Err(_) => return RuntimeReply::error("VALIDATION_FAILED", "Combined input configuration was rejected"),
        };
        let previous_selection = match super::inputs::load() {
            Ok(s) => s,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Previous selection unavailable"),
        };
        let previous_bundle = match self.activation.compose_bundle(
            &base,
            profile_policy::InputsOverlay {
                explicit: previous,
                gateway: None,
            },
        ) {
            Ok(b) => b,
            Err(_) => return RuntimeReply::error("NOT_READY", "Previous input snapshot unavailable"),
        };
        // Both snapshots are reserved before the first is written: pinning
        // never prunes, so the first cannot be lost to the second (decision 023).
        let need = super::core::snapshot_need(&previous_bundle).and(&super::core::snapshot_need(&next));
        if super::resources::reserve_history(&need, &Default::default()).is_err() {
            return RuntimeReply::error("STORAGE_ERROR", "Input snapshots unavailable");
        }
        let (previous_core, target_core) = match self.core.snapshot_pin(&previous_bundle, was_running).and_then(|p| {
            self.core
                .snapshot_pin(&next, was_running || target.is_some())
                .map(|n| (p, n))
        }) {
            Ok(s) => s,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Input snapshots unavailable"),
        };
        let generation = target
            .as_ref()
            .map(|e| e.generation)
            .or_else(|| previous_selection.explicit.as_ref().map(|e| e.generation))
            .unwrap_or(1);
        let owner_id = target
            .as_ref()
            .map(|e| e.owner_id.clone())
            .or_else(|| previous_selection.explicit.as_ref().map(|e| e.owner_id.clone()))
            .unwrap_or_else(|| std::fs::read_to_string("/etc/xkeenwrt/owner-id").unwrap_or_default());
        let mut transition = Transition {
            version: 1,
            owner_id,
            generation,
            runtime: self.incarnation_identity.clone(),
            previous_core,
            target_core,
            previous_selection: previous_selection.clone(),
            target_selection: super::inputs::Selection {
                explicit: target,
                gateway: false,
                network_commit: previous_selection.network_commit.clone(),
            },
            phase: Phase::Applying,
        };
        if input_state::save_transition(&transition).is_err() {
            return RuntimeReply::error("STORAGE_ERROR", "Input intent could not be persisted");
        }
        let started = if transition.target_core.running {
            self.core.publish(Some(&next.config), &next.assets, &next.overlay)
        } else {
            self.activation.emergency_stop(&mut self.core)
        };
        let result = started.and_then(|()| super::inputs::save(&transition.target_selection));
        if result.is_err() {
            let restored = self
                .core
                .restore_pinned(&transition.previous_core)
                .and_then(|()| super::inputs::save(&transition.previous_selection));
            if restored.is_ok() {
                transition.phase = Phase::RolledBack;
                let _ = input_state::save_transition(&transition);
            }
            return RuntimeReply::error(
                if restored.is_ok() {
                    "NOT_READY"
                } else {
                    "RECOVERY_ERROR"
                },
                "Explicit input failed; previous selection retained",
            );
        }
        transition.phase = Phase::Committed;
        if input_state::save_transition(&transition).is_err() {
            return RuntimeReply::error("STORAGE_ERROR", "Input commit is pending independent recovery");
        }
        Self::network_reply(serde_json::json!({"state":"explicit_updated"}))
    }
    pub(super) fn service_restart(&mut self, peer: Ipv4Addr) -> RuntimeReply {
        let selection = match super::inputs::load() {
            Ok(s) => s,
            Err(_) => return RuntimeReply::error("STORAGE_ERROR", "Selected inputs unavailable"),
        };
        // A remote admin may always Stop. Restarting selected inputs requires
        // the real main-LAN peer before any destructive stop phase begins.
        if selection.gateway || selection.explicit.is_some() {
            let (_, address, scope) = match self.main_lan() {
                Ok(l) => l,
                Err(m) => return RuntimeReply::error("UNSUPPORTED", m),
            };
            if !xkeenwrt_recovery::valid_lan_scope(&scope, address, peer) {
                return RuntimeReply::error("UNSUPPORTED", "Restart selected inputs from the main IPv4 LAN");
            }
        }
        let stop = self.service_stop();
        if stop.code != "OK" || stop.network.as_ref().and_then(|n| n["state"].as_str()) != Some("stopped") {
            return stop;
        }
        if let Some(e) = selection.explicit {
            let reply = self.explicit_set(
                Some(super::ExplicitBinding {
                    interface: e.lan_ifname,
                    address: e.lan_ipv4,
                }),
                peer,
            );
            if reply.code != "OK" {
                return reply;
            }
        }
        if selection.gateway {
            if let Ok(mut chosen) = super::inputs::load() {
                chosen.gateway = true;
                let _ = super::inputs::save(&chosen);
            }
            return self.service_start(peer);
        }
        if self.core.running().ok() != Some(true) {
            let _guard = match Self::manual_guard() {
                Ok(g) => g,
                Err(_) => return RuntimeReply::error("BUSY", "Core recovery is settling"),
            };
            let result = self
                .activation
                .current_manual_bundle(Path::new(CONFIG))
                .and_then(|b| {
                    self.activation
                        .compose_bundle(&b, profile_policy::InputsOverlay::default())
                })
                .and_then(|b| self.core.publish(Some(&b.config), &b.assets, &b.overlay));
            if result.is_err() {
                return RuntimeReply::error("NOT_READY", "Core restart failed");
            }
        }
        Self::network_reply(serde_json::json!({"state":"restarted"}))
    }
}
