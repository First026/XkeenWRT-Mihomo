use xkeenwrt_recovery::{Decision, Journal, Manifest, State};

fn pending() -> Journal {
    Journal {
        version: 1,
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
        state: State::Pending,
        completion: None,
        network_evidence: None,
        previous_network_evidence: None,
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
fn deadline_and_restart_revoke_without_extending() {
    let j = pending();
    assert_eq!(
        j.decision("00000000-0000-4000-8000-000000000006", 120_999, false),
        Decision::Wait
    );
    assert_eq!(
        j.decision("00000000-0000-4000-8000-000000000006", 121_000, false),
        Decision::Revoke
    );
    assert_eq!(
        j.decision("00000000-0000-4000-8000-000000000006", 1_001, true),
        Decision::Revoke
    );
    assert_eq!(
        j.decision("00000000-0000-4000-8000-000000000007", 1, false),
        Decision::Revoke
    );
}

#[test]
fn canonical_profile_revision_is_accepted_but_malformed_revision_is_invalid() {
    let mut journal = pending();
    journal.revision = "63e5177e-08e8-4988-9fb3-f1fcdbea3668".into();
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Wait
    );

    journal.revision = "not-a-canonical-uuid".into();
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Invalid
    );
}

#[test]
fn durable_journal_round_trips_a_complete_transaction() {
    let dir = std::env::temp_dir().join(format!("xkeenwrt-recovery-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let journal = pending();
    xkeenwrt_recovery::write_journal(&dir, &journal).unwrap();
    let read = xkeenwrt_recovery::read_journal(&dir).unwrap();
    assert_eq!(read.tx_id, journal.tx_id);
    assert_eq!(
        read.decision("00000000-0000-4000-8000-000000000006", 121_000, false),
        Decision::Revoke
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn journal_cannot_extend_deadline_or_use_system_routes() {
    let mut journal = pending();
    journal.deadline_boottime_ms += 1;
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_000, false),
        Decision::Invalid
    );
    journal.deadline_boottime_ms -= 1;
    journal.current.route_table = 254;
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_000, false),
        Decision::Invalid
    );
}

#[test]
fn mutation_lock_is_bounded_when_another_owner_holds_it() {
    let dir = std::env::temp_dir().join(format!("xkeenwrt-lock-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("mutation.lock");
    std::fs::File::create(&path).unwrap();
    let _held =
        xkeenwrt_recovery::MutationLock::acquire(&path, std::time::Duration::from_millis(100))
            .unwrap();
    let other =
        xkeenwrt_recovery::MutationLock::acquire(&path, std::time::Duration::from_millis(20));
    assert!(matches!(other, Err(e) if e.kind() == std::io::ErrorKind::TimedOut));
    drop(_held);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn revocation_is_generation_checked_and_cannot_revoke_confirmation() {
    let mut journal = pending();
    assert!(!journal.revoke(3));
    assert_eq!(journal.state, State::Pending);
    assert!(journal.revoke(2));
    assert_eq!(journal.state, State::Revoked);
    journal.state = State::Confirmed;
    assert!(!journal.revoke(2));
    assert_eq!(journal.state, State::Confirmed);
}

#[test]
fn nft_digest_ignores_runtime_counters_but_detects_rule_changes() {
    let a = br#"{"nftables":[{"metainfo":{"version":"1"}},{"table":{"family":"inet","name":"xkeenwrt"}},{"chain":{"family":"inet","table":"xkeenwrt","name":"c"}},{"rule":{"family":"inet","table":"xkeenwrt","chain":"c","handle":12,"expr":[{"counter":{"packets":5,"bytes":200}},{"accept":null}]}}]}"#;
    let b = br#"{"nftables":[{"metainfo":{"version":"2"}},{"table":{"family":"inet","name":"xkeenwrt"}},{"chain":{"family":"inet","table":"xkeenwrt","name":"c"}},{"rule":{"family":"inet","table":"xkeenwrt","chain":"c","handle":44,"expr":[{"counter":{"packets":30,"bytes":400}},{"accept":null}]}}]}"#;
    let changed = br#"{"nftables":[{"table":{"family":"inet","name":"xkeenwrt"}},{"chain":{"family":"inet","table":"xkeenwrt","name":"c"}},{"rule":{"family":"inet","table":"xkeenwrt","chain":"c","handle":44,"expr":[{"counter":{"packets":30,"bytes":400}},{"drop":null}]}}]}"#;
    let digest = xkeenwrt_recovery::nft_semantic_digest(a).unwrap();
    assert_eq!(digest, xkeenwrt_recovery::nft_semantic_digest(b).unwrap());
    assert_ne!(
        digest,
        xkeenwrt_recovery::nft_semantic_digest(changed).unwrap()
    );
}

#[test]
fn nft_digest_rejects_unmodelled_sets_and_timeouts() {
    let input = br#"{"nftables":[{"set":{"name":"foreign","timeout":30000}}]}"#;
    assert!(xkeenwrt_recovery::nft_semantic_digest(input).is_err());
}

#[test]
fn block_failure_plan_keeps_local_traffic_and_blocks_selected_wan() {
    let journal = pending();
    let batch = journal
        .current
        .failblock_json_batch(&journal.current, false)
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&batch).unwrap();
    let rules = value["nftables"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|v| v.to_string().contains("192.0.2.0") && v.to_string().contains("return"))
    );
    assert!(rules.iter().any(|v| v.to_string().contains("192.0.2.2")
        && v.to_string().contains("02:00:00:00:00:02")
        && v.to_string().contains("drop")));
    assert!(
        rules
            .iter()
            .any(|v| v.to_string().contains("02:00:00:00:00:02")
                && v.to_string().contains("nfproto")
                && v.to_string().contains("drop"))
    );
    assert!(!batch.contains("\"hook\":\"output\""));
}

#[test]
fn snapshot_manifest_rejects_traversal_duplicates_and_excess_size() {
    let mut journal = pending();
    let asset = |path: &str, size| xkeenwrt_recovery::SnapshotAsset {
        relative_path: path.into(),
        sha256: "0".repeat(64),
        size,
    };
    journal.previous_core.assets = vec![asset("providers/proxies/0.yaml", 10)];
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Wait
    );
    journal
        .previous_core
        .assets
        .push(asset("providers/proxies/0.yaml", 10));
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Invalid
    );
    journal.previous_core.assets = vec![asset("providers/proxies/../../secret.yaml", 10)];
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Invalid
    );
    journal.previous_core.assets = vec![asset("providers/rules/0.yaml", 8 * 1024 * 1024 + 1)];
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Invalid
    );
}

#[test]
fn fenced_transaction_revokes_even_if_confirm_won_a_race() {
    let mut journal = pending();
    journal.state = State::Confirmed;
    assert!(journal.revoke_fenced(2));
    assert_eq!(journal.state, State::Revoked);
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000006", 1_001, false),
        Decision::Revoke
    );
}

#[test]
fn json_first_plan_has_stable_digest_and_atomic_replace_commands() {
    let journal = pending();
    let ast = journal.current.expected_nft_ast().unwrap();
    let digest =
        xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&ast).unwrap()).unwrap();
    assert_eq!(digest.len(), 64);
    let batch: serde_json::Value =
        serde_json::from_str(&journal.current.nft_json_batch(true).unwrap()).unwrap();
    let operations = batch["nftables"].as_array().unwrap();
    assert_eq!(operations[0]["delete"]["table"]["name"], "xkeenwrt");
    assert_eq!(operations[1]["add"]["table"]["name"], "xkeenwrt");
    let block = journal
        .current
        .expected_failblock_ast(&journal.current)
        .unwrap();
    assert_ne!(
        digest,
        xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&block).unwrap()).unwrap()
    );
}

#[test]
fn selected_client_dns_packets_return_before_capture_for_tcp_and_udp() {
    let journal = pending();
    let ast = journal.current.expected_nft_ast().unwrap();
    let rules = ast["nftables"].as_array().unwrap();
    let dns_bypass = rules.iter().any(|item| {
        let Some(rule) = item.get("rule") else {
            return false;
        };
        if rule.get("chain").and_then(serde_json::Value::as_str) != Some("capture") {
            return false;
        }
        let expr = rule
            .get("expr")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        let protocols = expr.iter().any(|value| {
            value["match"]["left"]["meta"]["key"] == "l4proto"
                && value["match"]["right"]["set"] == serde_json::json!(["tcp", "udp"])
        });
        let port53 = expr.iter().any(|value| {
            value["match"]["left"]["payload"]["protocol"] == "th"
                && value["match"]["left"]["payload"]["field"] == "dport"
                && value["match"]["right"] == 53
        });
        protocols && port53 && expr.iter().any(|value| value.get("return").is_some())
    });
    assert!(
        dns_bypass,
        "capture must return TCP and UDP DNS before TPROXY"
    );
    assert!(
        rules.iter().any(|item| {
            let rule = &item["rule"];
            rule["chain"] == "dns"
                && rule.to_string().contains("redirect")
                && rule.to_string().contains("1053")
        }),
        "the existing DNS redirect must remain in place"
    );
}

#[test]
fn capture_guards_ipv4_before_mark_and_bypasses_multicast_and_broadcast() {
    let journal = pending();
    let ast = journal.current.expected_nft_ast().unwrap();
    let rules = ast["nftables"].as_array().unwrap();
    let ipv4_guard = rules
        .iter()
        .position(|item| {
            let rule = &item["rule"];
            rule["chain"] == "capture"
                && rule["expr"][0]["match"]["left"]["meta"]["key"] == "nfproto"
                && rule["expr"][0]["match"]["op"] == "!="
                && rule["expr"][0]["match"]["right"] == "ipv4"
                && rule["expr"][1].get("return").is_some()
        })
        .unwrap();
    let mark = rules
        .iter()
        .position(|item| {
            item["rule"]["chain"] == "capture" && item["rule"].to_string().contains("mangle")
        })
        .unwrap();
    assert!(
        ipv4_guard < mark,
        "non-IPv4 packets return before mark mutation"
    );

    let bypasses: Vec<_> = rules
        .iter()
        .filter(|item| {
            let rule = &item["rule"];
            rule["chain"] == "capture"
                && rule.to_string().contains("daddr")
                && rule.to_string().contains("return")
        })
        .collect();
    assert!(
        bypasses
            .iter()
            .any(|item| item.to_string().contains("224.0.0.0"))
    );
    assert!(
        bypasses
            .iter()
            .any(|item| item.to_string().contains("255.255.255.255"))
    );
    assert!(
        bypasses
            .iter()
            .any(|item| item.to_string().contains("192.0.2.255"))
    );

    let mut manifest = journal.current.clone();
    manifest.local_ipv4 = vec!["192.0.2.3/32".into()];
    let deduped = manifest.expected_nft_ast().unwrap();
    let exact_management_bypasses = deduped["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| {
            let rule = &item["rule"];
            rule["chain"] == "capture"
                && rule.to_string().contains("192.0.2.3")
                && rule.to_string().contains("daddr")
        })
        .count();
    assert_eq!(exact_management_bypasses, 1);
}

#[test]
fn nft_emergency_ownership_proof_accepts_only_generated_table_shapes() {
    let j = pending();
    let expected = j.current.expected_nft_ast().unwrap();
    let bytes = serde_json::to_vec(&expected).unwrap();
    assert!(
        xkeenwrt_recovery::nft_ownership_proof(&bytes, std::slice::from_ref(&expected)).unwrap()
    );

    let mut drifted = expected.clone();
    let items = drifted["nftables"].as_array_mut().unwrap();
    let capture = items
        .iter_mut()
        .find(|item| {
            item["rule"]["chain"] == "capture"
                && item["rule"]["expr"][0]["match"]["left"]["meta"]["key"] == "iifname"
        })
        .unwrap();
    capture["rule"]["expr"][0]["match"]["right"] = serde_json::json!("br-foreign");
    let changed = serde_json::to_vec(&drifted).unwrap();
    assert_ne!(
        xkeenwrt_recovery::nft_semantic_digest(&changed).unwrap(),
        xkeenwrt_recovery::nft_semantic_digest(&bytes).unwrap()
    );
    assert!(
        xkeenwrt_recovery::nft_ownership_proof(&changed, std::slice::from_ref(&expected)).unwrap()
    );

    let mut extra = expected.clone();
    extra["nftables"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "rule": {"family":"inet", "table":"xkeenwrt", "chain":"capture", "expr":[{"drop":null}]}
        }));
    assert!(
        !xkeenwrt_recovery::nft_ownership_proof(
            &serde_json::to_vec(&extra).unwrap(),
            std::slice::from_ref(&expected)
        )
        .unwrap()
    );

    let mut changed_verdict = expected.clone();
    let capture = changed_verdict["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["rule"]["chain"] == "capture")
        .unwrap();
    let verdict = capture["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    *verdict = serde_json::json!({"drop":null});
    assert!(
        !xkeenwrt_recovery::nft_ownership_proof(
            &serde_json::to_vec(&changed_verdict).unwrap(),
            std::slice::from_ref(&expected)
        )
        .unwrap()
    );

    let mut wrong_owner = expected.clone();
    wrong_owner["nftables"][0]["table"]["comment"] = serde_json::json!("foreign");
    assert!(
        !xkeenwrt_recovery::nft_ownership_proof(
            &serde_json::to_vec(&wrong_owner).unwrap(),
            std::slice::from_ref(&expected)
        )
        .unwrap()
    );
}

fn private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn test_id(seed: u64) -> String {
    format!("00000000-0000-4000-8000-{seed:012x}")
}

fn private_file(path: &std::path::Path, bytes: &[u8]) {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn snapshot_dir(history: &std::path::Path, id: &str) {
    let path = history.join(id);
    private_dir(&path);
    private_file(&path.join("config.yaml"), b"# synthetic snapshot\n");
}

#[test]
fn history_pruning_keeps_recovery_and_manual_snapshot_links() {
    let root = std::env::temp_dir().join(format!("xkeen-history-prune-{}", test_id(1000)));
    private_dir(&root);
    let history = root.join("history");
    private_dir(&history);
    let journal = pending();
    xkeenwrt_recovery::write_journal(&root, &journal).unwrap();
    let current_snapshot = journal.current_core.snapshot_id.clone();
    let manual_snapshot = test_id(1001);
    snapshot_dir(&history, &current_snapshot);
    snapshot_dir(&history, &manual_snapshot);
    private_file(
        &root.join("transaction.json"),
        format!("{{\"current\":{{\"snapshot_id\":\"{manual_snapshot}\"}}}}\n").as_bytes(),
    );
    for index in 0..126 {
        snapshot_dir(&history, &test_id(1100 + index));
    }
    assert_eq!(std::fs::read_dir(&history).unwrap().count(), 128);
    xkeenwrt_recovery::resources::prepare_history_append(
        &root,
        16,
        xkeenwrt_recovery::resources::HistoryArea::Snapshots,
        2,
        1,
    )
    .unwrap();
    assert!(history.join(&current_snapshot).exists());
    assert!(history.join(&manual_snapshot).exists());
    assert_eq!(std::fs::read_dir(&history).unwrap().count(), 127);

    snapshot_dir(&history, &test_id(1300));
    private_file(
        &root.join("removal.json"),
        b"{\"state\":\"cleanup_complete\"}\n",
    );
    assert!(
        xkeenwrt_recovery::resources::prepare_history_append(
            &root,
            16,
            xkeenwrt_recovery::resources::HistoryArea::Snapshots,
            2,
            1,
        )
        .is_err()
    );
    assert!(history.join(&current_snapshot).exists());
    assert!(history.join(&manual_snapshot).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn history_pruning_keeps_active_event_network_journal_and_its_snapshots() {
    let root = std::env::temp_dir().join(format!("xkeen-network-prune-{}", test_id(2000)));
    private_dir(&root);
    private_dir(&root.join("network-history"));
    let mut current = pending();
    current.state = State::Confirmed;
    xkeenwrt_recovery::write_journal(&root, &current).unwrap();
    let mut pinned = current.clone();
    pinned.tx_id = test_id(2001);
    let pinned_snapshot = test_id(2002);
    pinned.current_core.snapshot_id = pinned_snapshot.clone();
    let event = xkeenwrt_recovery::active::ActiveRecord::new(
        &pinned,
        &test_id(2003),
        xkeenwrt_recovery::active::Kind::CoreFailed,
        None,
    )
    .unwrap();
    let history = root.join("network-history");
    private_file(
        &history.join(format!("{}.json", pinned.tx_id)),
        &serde_json::to_vec(&pinned).unwrap(),
    );
    private_file(
        &root.join("active-reconcile.json"),
        &xkeenwrt_recovery::active::encode(&event).unwrap(),
    );
    for index in 0..127 {
        let mut archive = current.clone();
        archive.tx_id = test_id(2100 + index);
        private_file(
            &history.join(format!("{}.json", archive.tx_id)),
            &serde_json::to_vec(&archive).unwrap(),
        );
    }
    assert_eq!(std::fs::read_dir(&history).unwrap().count(), 128);
    xkeenwrt_recovery::resources::prepare_history_append(
        &root,
        32,
        xkeenwrt_recovery::resources::HistoryArea::Network,
        1,
        1,
    )
    .unwrap();
    assert!(history.join(format!("{}.json", pinned.tx_id)).exists());
    assert_eq!(std::fs::read_dir(&history).unwrap().count(), 127);
    assert!(
        std::fs::read_dir(&history)
            .unwrap()
            .all(|entry| entry.is_ok())
    );
    let root_history = root.join("history");
    private_dir(&root_history);
    snapshot_dir(&root_history, &current.current_core.snapshot_id);
    snapshot_dir(&root_history, &pinned_snapshot);
    for index in 0..126 {
        snapshot_dir(&root_history, &test_id(2300 + index));
    }
    xkeenwrt_recovery::resources::prepare_history_append(
        &root,
        1,
        xkeenwrt_recovery::resources::HistoryArea::Snapshots,
        1,
        1,
    )
    .unwrap();
    assert!(root_history.join(current.current_core.snapshot_id).exists());
    assert!(root_history.join(pinned_snapshot).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn history_admission_runs_more_than_128_dependency_cycles_without_dangling_links() {
    use xkeenwrt_recovery::{
        active::{Action, ActiveRecord, Kind, Outcome, Phase},
        resources::{HistoryArea, admit_history_append, prepare_history_append},
    };

    fn settled_journal(tx_id: &str, snapshot_id: &str) -> Journal {
        let mut journal = pending();
        journal.state = State::Confirmed;
        journal.applied = true;
        journal.tx_id = tx_id.to_owned();
        journal.current_core.snapshot_id = snapshot_id.to_owned();
        journal
    }
    fn completed_event(journal: &Journal, event_id: &str) -> ActiveRecord {
        let mut record = ActiveRecord::new(journal, event_id, Kind::CoreFailed, None).unwrap();
        record.phase = Phase::Completed;
        record.action = Some(Action::Direct);
        record.outcome = Some(Outcome::Direct);
        record
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "xkeen-history-graph-{}-{nonce}",
        std::process::id()
    ));
    private_dir(&root);
    let snapshots = root.join("history");
    let networks = root.join("network-history");
    let events = root.join("active-event-history");
    private_dir(&snapshots);
    private_dir(&networks);
    private_dir(&events);

    for index in 0..128 {
        let journal = settled_journal(&test_id(3000 + index), &test_id(4000 + index));
        let journal_bytes = serde_json::to_vec(&journal).unwrap();
        private_file(
            &networks.join(format!("{}.json", journal.tx_id)),
            &journal_bytes,
        );
        snapshot_dir(&snapshots, &journal.current_core.snapshot_id);
        let record = completed_event(&journal, &test_id(5000 + index));
        let event_bytes = xkeenwrt_recovery::active::encode(&record).unwrap();
        private_file(
            &events.join(format!("{}.json", record.event_id)),
            &event_bytes,
        );
    }

    for index in 0..130 {
        let snapshot_id = test_id(6000 + index);
        prepare_history_append(&root, 24, HistoryArea::Snapshots, 2, 1).unwrap();
        snapshot_dir(&snapshots, &snapshot_id);

        let journal = settled_journal(&test_id(7000 + index), &snapshot_id);
        let journal_bytes = serde_json::to_vec(&journal).unwrap();
        admit_history_append(&root, journal_bytes.len() as u64, HistoryArea::Network).unwrap();
        private_file(
            &networks.join(format!("{}.json", journal.tx_id)),
            &journal_bytes,
        );

        let record = completed_event(&journal, &test_id(8000 + index));
        let event_bytes = xkeenwrt_recovery::active::encode(&record).unwrap();
        admit_history_append(&root, event_bytes.len() as u64, HistoryArea::ActiveEvents).unwrap();
        private_file(
            &events.join(format!("{}.json", record.event_id)),
            &event_bytes,
        );
    }

    prepare_history_append(&root, 0, HistoryArea::Snapshots, 0, 0).unwrap();
    assert_eq!(std::fs::read_dir(&snapshots).unwrap().count(), 128);
    assert_eq!(std::fs::read_dir(&networks).unwrap().count(), 128);
    assert_eq!(std::fs::read_dir(&events).unwrap().count(), 128);
    assert!(!networks.join(format!("{}.json", test_id(3000))).exists());
    assert!(!events.join(format!("{}.json", test_id(5000))).exists());
    assert!(!snapshots.join(test_id(4000)).exists());
    assert!(snapshots.join(test_id(6129)).exists());
    assert!(networks.join(format!("{}.json", test_id(7129))).exists());
    assert!(events.join(format!("{}.json", test_id(8129))).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_validator_budgets_are_purpose_specific() {
    use std::time::Duration;
    use xkeenwrt_recovery::VerifiedPurpose;
    assert!(VerifiedPurpose::Validator.permits(Duration::from_secs(75)));
    assert!(!VerifiedPurpose::Validator.permits(Duration::from_secs(76)));
    assert!(VerifiedPurpose::ValidatorCleanup.permits(Duration::from_secs(25)));
    assert!(!VerifiedPurpose::ValidatorCleanup.permits(Duration::from_secs(26)));
    assert!(!VerifiedPurpose::Validator.permits(Duration::ZERO));
}

#[test]
fn first_publication_never_exposes_a_second_hard_link() {
    use std::os::unix::fs::MetadataExt;
    let dir = std::env::temp_dir().join(format!("xkeenwrt-publish-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let temp = dir.join("temp");
    let dest = dir.join("journal");
    std::fs::write(&temp, b"first").unwrap();
    assert!(xkeenwrt_recovery::publish_noreplace(&temp, &dest).unwrap());
    assert_eq!(std::fs::metadata(&dest).unwrap().nlink(), 1);
    std::fs::write(&temp, b"second").unwrap();
    assert!(!xkeenwrt_recovery::publish_noreplace(&temp, &dest).unwrap());
    assert_eq!(std::fs::read(&dest).unwrap(), b"first");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn upgrade_resource_absence_rejects_owned_and_ambiguous_objects() {
    use xkeenwrt_recovery::evidence::resources_absent;
    let j = pending();
    let empty_nft = br#"{"nftables":[]}"#;
    let empty = b"[]";
    assert!(resources_absent(&j.current, empty_nft, empty, empty, empty, empty).is_ok());
    let own = br#"{"nftables":[{"table":{"family":"inet","name":"xkeenwrt"}}]}"#;
    assert!(resources_absent(&j.current, own, empty, empty, empty, empty).is_err());
    let rule = format!(
        "[{{\"priority\":{},\"table\":{}}}]",
        j.current.priority, j.current.route_table
    );
    assert!(resources_absent(&j.current, empty_nft, rule.as_bytes(), empty, empty, empty).is_err());
    let route = format!(
        "[{{\"table\":{},\"dst\":\"default\",\"type\":\"local\",\"dev\":\"lo\"}}]",
        j.current.route_table
    );
    assert!(
        resources_absent(&j.current, empty_nft, empty, empty, route.as_bytes(), empty).is_err()
    );
    assert!(resources_absent(&j.current, b"{}", empty, empty, empty, empty).is_err());
}

#[test]
fn unchanged_identity_never_hides_changed_content_or_the_current_deadline() {
    let journal = pending();
    let boot = journal.boot_id.as_str();
    assert_eq!(journal.decision(boot, 1_001, false), Decision::Wait);
    for change in [0, 1, 2, 3] {
        let mut changed = journal.clone();
        match change {
            0 => changed.current.route_table = 254,
            1 => changed.current_core.controller_secret_sha256 = "invalid".into(),
            2 => changed.deadline_boottime_ms += 1,
            _ => changed
                .baseline_core
                .assets
                .push(xkeenwrt_recovery::SnapshotAsset {
                    relative_path: "../foreign".into(),
                    sha256: "0".repeat(64),
                    size: 1,
                }),
        }
        assert_eq!(changed.tx_id, journal.tx_id);
        assert_eq!(changed.generation, journal.generation);
        assert_eq!(changed.decision(boot, 1_001, false), Decision::Invalid);
        assert_eq!(journal.decision(boot, 120_999, false), Decision::Wait);
    }
    assert_eq!(journal.decision(boot, 121_000, false), Decision::Revoke);
    assert_eq!(journal.decision(boot, 1_001, true), Decision::Revoke);
    assert_eq!(
        journal.decision("00000000-0000-4000-8000-000000000008", 1_001, false),
        Decision::Revoke
    );
}

// r26: one reservation per operation, computed by a pure plan.

fn unique_root(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("xkeen-{tag}-{}-{nonce}", std::process::id()));
    private_dir(&root);
    root
}

/// Pin deterministic pruning order: older candidates are removed first.
fn age(path: &std::path::Path, seconds_ago: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds_ago);
    std::fs::File::open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// A core snapshot with `rules` provider files: 5 + rules directory entries.
fn provider_snapshot(history: &std::path::Path, id: &str, rules: usize) {
    snapshot_dir(history, id);
    let assets = history.join(id).join("assets");
    private_dir(&assets);
    private_dir(&assets.join("providers"));
    let dir = assets.join("providers").join("rules");
    private_dir(&dir);
    for index in 0..rules {
        private_file(&dir.join(format!("{index}.yaml")), b"payload: []\n");
    }
}

fn archived_journal(tx_id: &str, snapshot_id: &str) -> Journal {
    let mut journal = pending();
    journal.state = State::Confirmed;
    journal.applied = true;
    journal.tx_id = tx_id.to_owned();
    journal.current_core.snapshot_id = snapshot_id.to_owned();
    journal.previous_core.snapshot_id = snapshot_id.to_owned();
    journal.baseline_core.snapshot_id = snapshot_id.to_owned();
    journal
}

fn listing(root: &std::path::Path) -> std::collections::BTreeSet<std::path::PathBuf> {
    let mut all = std::collections::BTreeSet::new();
    for tree in ["history", "network-history", "active-event-history"] {
        if let Ok(entries) = std::fs::read_dir(root.join(tree)) {
            all.extend(entries.map(|entry| entry.unwrap().path()));
        }
    }
    all
}

/// A working router's tree of 17.11: the current journal and seven archived generations,
/// each pinning one 42-file provider snapshot (383 accounted entries).
fn r2_tree(root: &std::path::Path) -> Journal {
    let history = root.join("history");
    let network = root.join("network-history");
    private_dir(&history);
    private_dir(&network);
    let mut current = archived_journal(&test_id(9000), &test_id(9100));
    current.current_core.snapshot_id = test_id(9100);
    xkeenwrt_recovery::write_journal(root, &current).unwrap();
    provider_snapshot(&history, &test_id(9100), 42);
    for index in 0..7 {
        let snapshot = test_id(9200 + index);
        provider_snapshot(&history, &snapshot, 42);
        let journal = archived_journal(&test_id(9300 + index), &snapshot);
        let path = network.join(format!("{}.json", journal.tx_id));
        private_file(&path, &serde_json::to_vec(&journal).unwrap());
        age(&history.join(&snapshot), 1000 - index * 10);
        age(&path, 1000 - index * 10);
    }
    current
}

#[test]
fn start_reservation_keeps_every_snapshot_it_writes_on_the_r2_tree() {
    use xkeenwrt_recovery::resources::{HistoryArea, HistoryNeed, history_fits, reserve_history};
    let root = unique_root("r26-t1");
    let current = r2_tree(&root);
    let history = root.join("history");
    // Start without a prior generation: previous, candidate and next
    // baseline snapshots, plus the archived settled journal.
    let snapshot = HistoryNeed::snapshot(4096, 42);
    let archive = HistoryNeed::archive(HistoryArea::Network, 4096);
    let need = snapshot.clone().and(&snapshot).and(&snapshot).and(&archive);
    reserve_history(&root, &need, &Default::default()).unwrap();
    let written = [test_id(9500), test_id(9501), test_id(9502)];
    for id in &written {
        history_fits(&root, &snapshot).unwrap();
        provider_snapshot(&history, id, 42);
    }
    history_fits(&root, &archive).unwrap();
    for id in &written {
        assert!(
            history.join(id).exists(),
            "Start lost its own snapshot {id}"
        );
    }
    assert!(history.join(&current.current_core.snapshot_id).exists());
    // The oldest unattached generation paid for the reservation.
    assert!(
        !root
            .join("network-history")
            .join(format!("{}.json", test_id(9300)))
            .exists()
    );
    assert!(!history.join(test_id(9200)).exists());
    xkeenwrt_recovery::resources::history_size(&root).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_snapshot_survives_even_when_it_is_the_oldest() {
    use xkeenwrt_recovery::resources::{HistoryNeed, history_full, reserve_history};
    let root = unique_root("r26-t2");
    let history = root.join("history");
    private_dir(&history);
    for index in 0..128 {
        snapshot_dir(&history, &test_id(9600 + index));
        age(&history.join(test_id(9600 + index)), 2000 - index);
    }
    let protect = std::collections::BTreeSet::from([test_id(9600)]);
    reserve_history(&root, &HistoryNeed::snapshot(16, 0), &protect).unwrap();
    assert!(history.join(test_id(9600)).exists());
    assert!(!history.join(test_id(9601)).exists());
    assert_eq!(std::fs::read_dir(&history).unwrap().count(), 127);

    // If the only reclaimable entry is protected, nothing is removed.
    let only = unique_root("r26-t2b");
    let history = only.join("history");
    private_dir(&history);
    xkeenwrt_recovery::write_journal(&only, &archived_journal(&test_id(9800), &test_id(9801)))
        .unwrap();
    for index in 0..128 {
        snapshot_dir(&history, &test_id(9801 + index));
    }
    let before = listing(&only);
    let protect = (9802..9929)
        .map(test_id)
        .collect::<std::collections::BTreeSet<_>>();
    let error = reserve_history(&only, &HistoryNeed::snapshot(16, 0), &protect).unwrap_err();
    let full = history_full(&error).expect("typed shortage");
    assert_eq!(full.reclaimable_entries, 0);
    assert_eq!(listing(&only), before);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(only).unwrap();
}

#[test]
fn plan_is_pure_and_reservation_removes_exactly_the_plan() {
    use xkeenwrt_recovery::resources::{HistoryNeed, plan_history_append, reserve_history};
    let root = unique_root("r26-t3");
    r2_tree(&root);
    let need = HistoryNeed::snapshot(4096, 42)
        .and(&HistoryNeed::snapshot(4096, 42))
        .and(&HistoryNeed::snapshot(4096, 42))
        .and(&HistoryNeed::snapshot(4096, 42));
    let before = listing(&root);
    let plan = plan_history_append(&root, &need, &Default::default()).unwrap();
    assert_eq!(listing(&root), before, "planning must not modify history");
    assert!(
        plan.removals.len() >= 4,
        "the plan must release journals and then snapshots"
    );
    reserve_history(&root, &need, &Default::default()).unwrap();
    let removed: std::collections::BTreeSet<_> =
        before.difference(&listing(&root)).cloned().collect();
    assert_eq!(removed, plan.removals.iter().cloned().collect());
    assert_eq!(plan.freed_entries, 48 * plan.removals.len() / 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn shortage_is_reported_with_numbers_only_when_cleanup_cannot_cover_it() {
    use xkeenwrt_recovery::resources::{HistoryNeed, history_full, plan_history_append};
    let root = unique_root("r26-t7");
    r2_tree(&root);
    // Seven unattached generations can release 336 entries.
    let fits = HistoryNeed::snapshot(4096, 300);
    assert!(plan_history_append(&root, &fits, &Default::default()).is_ok());
    let before = listing(&root);
    let too_big = HistoryNeed::snapshot(4096, 470);
    let full =
        history_full(&plan_history_append(&root, &too_big, &Default::default()).unwrap_err())
            .expect("typed shortage");
    assert_eq!(full.used_entries, 383);
    assert_eq!(full.limit_entries, 512);
    assert_eq!(full.needed_entries, 476);
    assert_eq!(full.reclaimable_entries, 336);
    assert_eq!(listing(&root), before);
    std::fs::remove_dir_all(root).unwrap();
}
