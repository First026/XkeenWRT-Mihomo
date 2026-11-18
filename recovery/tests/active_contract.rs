use xkeenwrt_recovery::{Journal, Manifest, State};

fn journal() -> Journal {
    Journal {
        version: 1,
        network_evidence: None,
        previous_network_evidence: None,
        operation: xkeenwrt_recovery::Operation::Apply,
        tx_id: "00000000-0000-4000-8000-000000000004".into(),
        plan_id: "00000000-0000-4000-8000-000000000003".into(),
        candidate_id: "candidate-1".into(),
        profile_id: "profile-1".into(),
        revision: "00000000-0000-4000-8000-000000000007".into(),
        idempotency_key: "synthetic-idempotency".into(),
        confirm_token_sha256: "2".repeat(64),
        applied: false,
        generation: 2,
        runtime_pid: 1234,
        runtime_starttime: 5000,
        runtime_nonce: "00000000-0000-4000-8000-000000000005".into(),
        boot_id: "00000000-0000-4000-8000-000000000006".into(),
        created_boottime_ms: 1_000,
        deadline_boottime_ms: 121_000,
        state: State::Confirmed,
        completion: None,
        current: Manifest {
            failure_policy: xkeenwrt_recovery::FailurePolicy::DirectOnFailure,
            owner_id: "00000000-0000-4000-8000-000000000001".into(),
            generation: 2,
            nft_semantic_sha256: "0".repeat(64),
            lan_interface: "br-test".into(),
            lan_address: "192.0.2.1".parse().unwrap(),
            lan_scope: None,
            capture_version: None,
            selected_mac: "02:00:00:00:00:02".into(),
            management_macs: vec!["02:00:00:00:00:03".into()],
            source_ipv4: "192.0.2.2".parse().unwrap(),
            management_ipv4: "192.0.2.3".parse().unwrap(),
            management_ipv6: vec!["2001:db8::3".parse().unwrap()],
            management_channel: None,
            local_ipv4: vec!["192.0.2.0/24".into()],
            selected_ipv6: vec!["2001:db8::2/128".into()],
            local_ipv6: vec!["2001:db8::/64".into()],
            route_table: 100,
            mark: 0x100,
            mask: 0x100,
            priority: 10000,
        },
        previous_good: None,
        failblock_semantic_sha256: None,
        active_failblock_semantic_sha256: None,
        current_core: xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000002".into(),
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
            sha256: "0".repeat(64),
            running: false,
            controller_port: 9090,
            controller_secret_sha256: "3".repeat(64),
            assets: vec![],
        },
        previous_core: xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000002".into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: "0".repeat(64),
            running: false,
            controller_port: 9090,
            controller_secret_sha256: "3".repeat(64),
            assets: vec![],
        },
        next_baseline_core: None,
        profile_acceptance: None,
        cancel_capture: false,
        baseline_core: xkeenwrt_recovery::CoreSnapshot {
            snapshot_id: "00000000-0000-4000-8000-000000000002".into(),
            overlay: profile_policy::ManagedOverlay::Manual,
            sha256: "0".repeat(64),
            running: false,
            controller_port: 9090,
            controller_secret_sha256: "3".repeat(64),
            assets: vec![],
        },
    }
}

#[test]
fn stale_generation_is_rejected_before_any_action() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind};
    let j = journal();
    let mut record = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    record.generation += 1;
    assert!(!record.valid_for(&j));
}

#[derive(Default)]
struct Fake {
    calls: Vec<&'static str>,
    actions: Vec<xkeenwrt_recovery::active::Action>,
    fail: Option<&'static str>,
    fail_code: Option<xkeenwrt_recovery::active::Code>,
    healthy: bool,
    other_boot: bool,
    persist_count: usize,
    fail_persist_at: Option<usize>,
    unsafe_restore: bool,
    record_path: Option<std::path::PathBuf>,
}
impl xkeenwrt_recovery::active::Adapter for Fake {
    fn restore_admissible(&mut self, _: &Journal) -> Result<bool, xkeenwrt_recovery::active::Code> {
        Ok(!self.unsafe_restore)
    }
    fn same_boot(&mut self, _: &Journal) -> Result<bool, xkeenwrt_recovery::active::Code> {
        Ok(!self.other_boot)
    }
    fn observe_core(
        &mut self,
        _: &Journal,
    ) -> Result<xkeenwrt_recovery::active::CoreHealth, xkeenwrt_recovery::active::Code> {
        Ok(if self.healthy {
            xkeenwrt_recovery::active::CoreHealth::Healthy
        } else {
            xkeenwrt_recovery::active::CoreHealth::Failed
        })
    }
    fn secure_nft(
        &mut self,
        _: &Journal,
        action: xkeenwrt_recovery::active::Action,
    ) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.actions.push(action);
        self.step("nft")
    }
    fn reconcile_routes(
        &mut self,
        _: &Journal,
        _: xkeenwrt_recovery::active::Action,
    ) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.step("routes")
    }
    fn finish_interception(
        &mut self,
        _: &Journal,
        _: xkeenwrt_recovery::active::Action,
    ) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.step("interception")
    }
    fn restore_baseline(&mut self, _: &Journal) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.step("baseline")
    }
    fn verify_final(
        &mut self,
        _: &Journal,
        _: xkeenwrt_recovery::active::Action,
    ) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.step("verify")
    }
    fn mark_disabled(&mut self, j: &mut Journal) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.step("commit")?;
        j.finish_disable();
        Ok(())
    }
    fn persist(
        &mut self,
        record: &xkeenwrt_recovery::active::ActiveRecord,
    ) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.persist_count += 1;
        if self.fail_persist_at == Some(self.persist_count) {
            self.calls.push("persist");
            return Err(xkeenwrt_recovery::active::Code::Storage);
        }
        if let Some(path) = &self.record_path {
            std::fs::write(path, xkeenwrt_recovery::active::encode(record)?)
                .map_err(|_| xkeenwrt_recovery::active::Code::Storage)?;
        }
        self.step("persist")
    }
}

#[test]
fn unsafe_reconcile_receipt_survives_disk_reload_and_owner_disable() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind, Outcome, Phase, decode, process};
    let dir = std::env::temp_dir().join(format!("xkeen-active-direct-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("active.json");
    let mut j = journal();
    xkeenwrt_recovery::write_journal(&dir, &j).unwrap();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000008",
        Kind::ReconcileRequested,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        healthy: true,
        unsafe_restore: true,
        record_path: Some(path.clone()),
        ..Default::default()
    };
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Direct)
    );
    let mut persisted = decode(&std::fs::read(&path).unwrap()).unwrap();
    let mut j = xkeenwrt_recovery::read_journal(&dir).unwrap();
    assert_eq!(persisted.phase, Phase::Completed);
    assert!(persisted.valid_for(&j));
    let writes = driver.persist_count;
    assert_eq!(
        process(&mut j, &mut persisted, &mut driver),
        Ok(Outcome::Direct)
    );
    assert_eq!(driver.persist_count, writes);
    assert!(xkeenwrt_recovery::active::archiveable(&persisted, &j));
    let mut disable = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000009",
        Kind::DisableRequested,
        Some("owner-disable".into()),
    )
    .unwrap();
    disable.retry_of = Some(persisted.event_id.clone());
    assert_eq!(
        process(&mut j, &mut disable, &mut driver),
        Ok(Outcome::Disabled)
    );
    xkeenwrt_recovery::write_journal(&dir, &j).unwrap();
    let j = xkeenwrt_recovery::read_journal(&dir).unwrap();
    let disable = decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(j.state, State::Disabled);
    assert!(disable.valid_for(&j));
    assert!(persisted.valid_binding(&j));
    std::fs::remove_dir_all(&dir).unwrap();
}
impl Fake {
    fn step(&mut self, name: &'static str) -> Result<(), xkeenwrt_recovery::active::Code> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(self
                .fail_code
                .unwrap_or(xkeenwrt_recovery::active::Code::Drift))
        } else {
            Ok(())
        }
    }
}

#[test]
fn disable_proves_network_absent_and_restores_baseline_before_receipt() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind, Outcome, Phase, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::DisableRequested,
        Some("request-1".into()),
    )
    .unwrap();
    let mut driver = Fake::default();
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Disabled)
    );
    assert_eq!(j.state, State::Disabled);
    assert_eq!(event.phase, Phase::Completed);
    let steps: Vec<_> = driver
        .calls
        .iter()
        .copied()
        .filter(|x| *x != "persist")
        .collect();
    assert_eq!(
        steps,
        ["nft", "routes", "baseline", "verify", "verify", "commit"]
    );
}

#[test]
fn snapshot_assets_are_part_of_binding() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind};
    let j = journal();
    let record = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut changed = j.clone();
    changed.current_core.running = true;
    assert!(!record.valid_for(&changed));
}

#[test]
fn semantic_drift_stops_before_routes_and_persists_error() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, Phase, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        fail: Some("nft"),
        ..Default::default()
    };
    assert_eq!(process(&mut j, &mut event, &mut driver), Err(Code::Drift));
    assert_eq!(event.phase, Phase::Error);
    assert_eq!(event.failed_phase, Some(Phase::Intent));
    assert!(!driver.calls.contains(&"routes"));
    let n = driver.calls.len();
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Err(Code::Recovery)
    );
    assert_eq!(driver.calls.len(), n);
}

#[test]
fn drifted_reconcile_error_is_archived_and_replaced_by_core_failure() {
    use xkeenwrt_recovery::active::{
        ActiveRecord, Code, Kind, Outcome, Phase, archiveable, may_replace_for_health_event,
        may_start_core_failed, process,
    };
    let mut j = journal();
    let mut prior = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::ReconcileRequested,
        None,
    )
    .unwrap();
    let mut reconcile = Fake {
        healthy: true,
        fail: Some("nft"),
        ..Default::default()
    };
    assert_eq!(
        process(&mut j, &mut prior, &mut reconcile),
        Err(Code::Drift)
    );
    assert_eq!(prior.phase, Phase::Error);
    assert_eq!(
        prior.action,
        Some(xkeenwrt_recovery::active::Action::Restore)
    );
    assert!(may_replace_for_health_event(&prior, &j));
    assert!(archiveable(&prior, &j));
    assert!(may_start_core_failed(Some(&prior), &j));

    let mut failed = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000008",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    failed.retry_of = Some(prior.event_id.clone());
    assert!(failed.valid_for(&j));
    let mut driver = Fake::default();
    assert_eq!(
        process(&mut j, &mut failed, &mut driver),
        Ok(Outcome::Direct)
    );
    assert_eq!(failed.retry_of.as_deref(), Some(prior.event_id.as_str()));

    let mut unrelated = prior.clone();
    unrelated.error_code = Some("HEALTH".into());
    assert!(may_replace_for_health_event(&unrelated, &j));
    assert!(may_start_core_failed(Some(&unrelated), &j));
    unrelated.error_code = Some("INVALID".into());
    assert!(!may_replace_for_health_event(&unrelated, &j));
    assert!(!may_start_core_failed(Some(&unrelated), &j));
    let mut stale = prior;
    stale.generation += 1;
    assert!(!may_start_core_failed(Some(&stale), &j));

    // The same transition must honor the previously declared block policy,
    // while preserving the failed reconciliation as the retry's parent.
    let mut blocked_journal = journal();
    blocked_journal.current.failure_policy =
        xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure;
    blocked_journal.active_failblock_semantic_sha256 = Some("4".repeat(64));
    let mut blocked_prior = ActiveRecord::new(
        &blocked_journal,
        "00000000-0000-4000-8000-000000000017",
        Kind::ReconcileRequested,
        None,
    )
    .unwrap();
    let mut drift = Fake {
        healthy: true,
        fail: Some("nft"),
        ..Default::default()
    };
    assert_eq!(
        process(&mut blocked_journal, &mut blocked_prior, &mut drift),
        Err(Code::Drift)
    );
    assert!(archiveable(&blocked_prior, &blocked_journal));
    assert!(may_start_core_failed(
        Some(&blocked_prior),
        &blocked_journal
    ));
    let mut blocked_failure = ActiveRecord::new(
        &blocked_journal,
        "00000000-0000-4000-8000-000000000018",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    blocked_failure.retry_of = Some(blocked_prior.event_id.clone());
    let mut block_driver = Fake::default();
    assert_eq!(
        process(
            &mut blocked_journal,
            &mut blocked_failure,
            &mut block_driver
        ),
        Ok(Outcome::Blocked)
    );
    assert_eq!(
        blocked_failure.retry_of.as_deref(),
        Some(blocked_prior.event_id.as_str())
    );
}

#[test]
fn healthy_core_failure_hint_does_not_mutate_network() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        healthy: true,
        ..Default::default()
    };
    assert_eq!(process(&mut j, &mut event, &mut driver), Err(Code::Health));
    assert!(!driver.calls.contains(&"nft"));
}

#[test]
fn crash_after_nft_replays_only_idempotent_step_before_routes() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, Outcome, Phase, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        fail_persist_at: Some(2),
        ..Default::default()
    };
    assert_eq!(process(&mut j, &mut event, &mut driver), Err(Code::Storage));
    assert_eq!(event.phase, Phase::Intent);
    assert!(!driver.calls.contains(&"routes"));
    driver.fail_persist_at = None;
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Direct)
    );
    assert_eq!(driver.calls.iter().filter(|v| **v == "nft").count(), 2);
    assert_eq!(driver.calls.iter().filter(|v| **v == "routes").count(), 1);
}

#[test]
fn failed_core_uses_predeclared_block_policy_before_removing_routes() {
    use xkeenwrt_recovery::active::{Action, ActiveRecord, Kind, Outcome, process};
    let mut j = journal();
    j.current.failure_policy = xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure;
    j.active_failblock_semantic_sha256 = Some("4".repeat(64));
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut driver = Fake::default();
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Blocked)
    );
    assert_eq!(driver.actions, [Action::Block]);
    let steps: Vec<_> = driver
        .calls
        .iter()
        .copied()
        .filter(|x| *x != "persist")
        .collect();
    assert_eq!(&steps[..2], ["nft", "routes"]);
}

#[test]
fn disable_receipt_retries_after_journal_was_durably_disabled() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, Outcome, Phase, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::DisableRequested,
        Some("request-1".into()),
    )
    .unwrap();
    let mut driver = Fake {
        fail_persist_at: Some(6),
        ..Default::default()
    };
    assert_eq!(process(&mut j, &mut event, &mut driver), Err(Code::Storage));
    assert_eq!(j.state, State::Disabled);
    assert_eq!(event.phase, Phase::Verified);
    driver.fail_persist_at = None;
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Disabled)
    );
    assert_eq!(event.phase, Phase::Completed);
}

#[test]
fn reboot_prevents_active_network_mutation() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::ReconcileRequested,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        healthy: true,
        other_boot: true,
        ..Default::default()
    };
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Err(Code::Unavailable)
    );
    assert!(!driver.calls.contains(&"nft"));
    assert!(!driver.calls.contains(&"routes"));
}

#[test]
fn archived_receipt_keeps_binding_after_disable_but_cannot_run_again() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind, Outcome, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    assert_eq!(
        process(&mut j, &mut event, &mut Fake::default()),
        Ok(Outcome::Direct)
    );
    j.state = State::Disabled;
    assert!(event.valid_binding(&j));
    assert!(!event.valid_for(&j));
}

#[test]
fn disable_replacement_keeps_the_generation_that_was_actually_active() {
    use xkeenwrt_recovery::active::{ActiveRecord, Kind, Outcome, process};
    for rolled_back in [false, true] {
        let mut j = journal();
        let mut previous = j.current.clone();
        previous.generation = 1;
        previous.route_table = 101;
        previous.priority = 10001;
        previous.mark = 0x200;
        previous.mask = 0x200;
        j.previous_good = Some(previous);
        j.previous_core = j.current_core.clone();
        if rolled_back {
            j.state = State::RolledBack;
        }
        assert_eq!(
            j.decision(&j.boot_id, 1001, false),
            xkeenwrt_recovery::Decision::Settled
        );
        let generation = if rolled_back { 1 } else { 2 };
        let mut event = ActiveRecord::new(
            &j,
            "00000000-0000-4000-8000-000000000008",
            Kind::DisableRequested,
            Some("disable-replacement".into()),
        )
        .expect("the active previous generation must also be disableable");
        assert_eq!(event.generation, generation);
        assert_eq!(
            process(&mut j, &mut event, &mut Fake::default()),
            Ok(Outcome::Disabled)
        );
        assert!(
            event.valid_for(&j),
            "completed Disable must survive journal reload"
        );
        assert_eq!(
            process(&mut j, &mut event, &mut Fake::default()),
            Ok(Outcome::Disabled)
        );
    }
}

#[test]
fn transient_failure_retries_owned_cleanup_with_a_durable_bound() {
    use xkeenwrt_recovery::{
        FailurePolicy,
        active::{ActiveRecord, Code, Kind, Outcome, process},
    };
    for block in [false, true] {
        let mut j = journal();
        if block {
            j.current.failure_policy = FailurePolicy::BlockSelectedOnFailure;
            j.active_failblock_semantic_sha256 = Some("f".repeat(64));
        }
        let mut event = ActiveRecord::new(
            &j,
            "00000000-0000-4000-8000-000000000008",
            Kind::CoreFailed,
            None,
        )
        .unwrap();
        let mut driver = Fake {
            fail: Some("nft"),
            fail_code: Some(Code::Recovery),
            ..Fake::default()
        };
        assert_eq!(
            process(&mut j, &mut event, &mut driver),
            Err(Code::Recovery)
        );
        assert!(!driver.calls.contains(&"routes"));
        driver.fail = None;
        assert_eq!(
            process(&mut j, &mut event, &mut driver),
            Ok(if block {
                Outcome::Blocked
            } else {
                Outcome::Direct
            })
        );
        assert!(driver.calls.contains(&"nft"));
        assert_eq!(event.retry_failures.len(), 1);
        assert_eq!(event.retry_failures[0].code, "RECOVERY");
    }
}

#[test]
fn repeated_command_failure_is_bounded_across_record_reload() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, decode, encode, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000008",
        Kind::CoreFailed,
        None,
    )
    .unwrap();
    let mut driver = Fake {
        fail: Some("nft"),
        fail_code: Some(Code::Recovery),
        ..Fake::default()
    };
    for attempt in 0..8 {
        assert_eq!(
            process(&mut j, &mut event, &mut driver),
            Err(Code::Recovery)
        );
        event = decode(&encode(&event).unwrap()).unwrap();
        if attempt == 0 {
            let saved = event.clone();
            driver.other_boot = true;
            assert_eq!(
                process(&mut j, &mut event, &mut driver),
                Err(Code::Unavailable)
            );
            assert_eq!(
                event, saved,
                "a stale retry must preserve the durable error"
            );
            driver.other_boot = false;
        }
    }
    assert_eq!(
        driver.calls.iter().filter(|call| **call == "nft").count(),
        3
    );
    assert_eq!(event.retry_failures.len(), 2);
    assert!(!driver.calls.contains(&"routes"));
}

#[test]
fn completed_recovery_retains_runtime_resume_obligation_across_restart() {
    let mut j = journal();
    let boot = j.boot_id.clone();
    j.finish_rollback(&boot);
    let mut reloaded: Journal = serde_json::from_slice(&serde_json::to_vec(&j).unwrap()).unwrap();
    assert!(reloaded.needs_runtime_resume(&boot));
    assert_eq!(
        reloaded.decision(&boot, 121_001, true),
        xkeenwrt_recovery::Decision::Settled
    );
    reloaded.completion.as_mut().unwrap().runtime_resumed = true;
    assert!(!reloaded.needs_runtime_resume(&boot));
    let reboot = "00000000-0000-4000-8000-000000000009";
    assert!(reloaded.needs_boot_cleanup(reboot));
    reloaded.finish_boot_cleanup(reboot);
    assert!(reloaded.boot_cleanup_complete());
    assert!(reloaded.needs_runtime_resume(reboot));
    assert!(!reloaded.needs_boot_cleanup(reboot));
    assert_eq!(
        reloaded.decision(reboot, 1, true),
        xkeenwrt_recovery::Decision::Settled
    );
}

#[test]
fn foreign_boot_cleans_pending_revoked_and_split_disable_without_restoring_network() {
    use xkeenwrt_recovery::active::{Action, ActiveRecord, Kind, Phase};
    let reboot = "00000000-0000-4000-8000-000000000009";
    for state in [State::Pending, State::Revoked] {
        let mut j = journal();
        j.state = state;
        assert!(!j.needs_boot_cleanup(&j.boot_id));
        assert!(
            j.needs_boot_cleanup(reboot),
            "old-boot transaction must not restore interception"
        );
    }
    let mut j = journal();
    let mut r = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000008",
        Kind::DisableRequested,
        Some("disable-before-power-loss".into()),
    )
    .unwrap();
    r.phase = Phase::Verified;
    r.action = Some(Action::Disable);
    j.finish_disable();
    let j: Journal = serde_json::from_slice(&serde_json::to_vec(&j).unwrap()).unwrap();
    let r: ActiveRecord = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert!(r.valid_for(&j));
    assert!(
        j.needs_boot_cleanup(reboot),
        "durable Disabled plus Verified event must settle after reboot"
    );
}

/// 0.1.26.3 lab, run 3: a one-off I/O error while restoring the baseline core
/// (after nft and routes were already gone) left the owner's Disable in Error
/// for good, and every later Stop answered BUSY. It must resume from the
/// failed step under the same two-retry bound as CoreFailed.
#[test]
fn transient_baseline_failure_resumes_owner_disable() {
    use xkeenwrt_recovery::active::{
        ActiveRecord, Code, Kind, Outcome, Phase, decode, encode, process,
    };
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::DisableRequested,
        Some("service-stop-1".into()),
    )
    .unwrap();
    let mut driver = Fake {
        fail: Some("baseline"),
        fail_code: Some(Code::Recovery),
        ..Fake::default()
    };
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Err(Code::Recovery)
    );
    assert_eq!(event.phase, Phase::Error);
    assert_eq!(event.failed_phase, Some(Phase::RoutingDone));
    assert_ne!(j.state, State::Disabled);
    event = decode(&encode(&event).unwrap()).unwrap();
    driver.fail = None;
    driver.calls.clear();
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Ok(Outcome::Disabled)
    );
    assert_eq!(j.state, State::Disabled);
    assert_eq!(event.phase, Phase::Completed);
    assert_eq!(event.retry_failures.len(), 1);
    assert_eq!(event.retry_failures[0].phase, Phase::RoutingDone);
    let steps: Vec<_> = driver
        .calls
        .iter()
        .copied()
        .filter(|x| *x != "persist")
        .collect();
    assert_eq!(
        steps,
        ["baseline", "verify", "verify", "commit"],
        "resume, never redo nft or routes"
    );
    assert!(event.valid_for(&j));
}

#[test]
fn owner_disable_retry_is_bounded_and_only_for_recovery_errors() {
    use xkeenwrt_recovery::active::{ActiveRecord, Code, Kind, Phase, decode, encode, process};
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::DisableRequested,
        Some("service-stop-1".into()),
    )
    .unwrap();
    let mut driver = Fake {
        fail: Some("baseline"),
        fail_code: Some(Code::Recovery),
        ..Fake::default()
    };
    for _ in 0..8 {
        assert_eq!(
            process(&mut j, &mut event, &mut driver),
            Err(Code::Recovery)
        );
        event = decode(&encode(&event).unwrap()).unwrap();
    }
    assert_eq!(driver.calls.iter().filter(|c| **c == "baseline").count(), 3);
    assert_eq!(event.retry_failures.len(), 2);
    assert_eq!(event.phase, Phase::Error);
    // A health or drift verdict is not transient: it is never retried.
    let mut j = journal();
    let mut event = ActiveRecord::new(
        &j,
        "00000000-0000-4000-8000-000000000007",
        Kind::DisableRequested,
        Some("service-stop-2".into()),
    )
    .unwrap();
    let mut driver = Fake {
        fail: Some("verify"),
        fail_code: Some(Code::Health),
        ..Fake::default()
    };
    assert_eq!(process(&mut j, &mut event, &mut driver), Err(Code::Health));
    driver.fail = None;
    assert_eq!(
        process(&mut j, &mut event, &mut driver),
        Err(Code::Recovery)
    );
    assert!(event.retry_failures.is_empty());
    assert_ne!(j.state, State::Disabled);
}
