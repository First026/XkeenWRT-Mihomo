use xkeen_ui::runtime::networking::inventory::{InventoryError, occupied_rules};

#[test]
fn occupied_rule_masks_include_masked_marks_and_priorities() {
    let rules = br#"[{"priority":10001,"table":120,"fwmark":"0x100/0xff00"},{"priority":32766,"table":"main"}]"#;
    let found = occupied_rules(rules).unwrap();
    assert_eq!(found.priorities, vec![10001, 32766]);
    assert_eq!(found.tables, vec![120, 254]);
    assert_eq!(found.marks, vec![(0x100, 0xff00)]);
}

#[test]
fn malformed_or_ambiguous_rule_is_not_an_empty_inventory() {
    assert_eq!(
        occupied_rules(br#"[{"priority":5,"table":"vpn","fwmark":"bad"}]"#),
        Err(InventoryError::Unsupported)
    );
    assert_eq!(occupied_rules(br#"{}"#), Err(InventoryError::Unsupported));
}

#[test]
fn a_new_generation_is_not_confused_with_a_confirmed_replay() {
    use xkeen_ui::runtime::networking::transaction::{Error, Request, confirmed_request_is_replay};
    let j = recovery_fixture();
    let mut request = Request {
        plan_id: j.plan_id.clone(),
        candidate_id: j.candidate_id.clone(),
        idempotency_key: j.idempotency_key.clone(),
        generation: j.generation,
    };
    assert_eq!(confirmed_request_is_replay(&j, &request), Ok(true));
    request.generation += 1;
    assert_eq!(confirmed_request_is_replay(&j, &request), Err(Error::Conflict));
    request.idempotency_key = "replacement-request".into();
    request.plan_id = "00000000-0000-4000-8000-000000000009".into();
    assert_eq!(confirmed_request_is_replay(&j, &request), Ok(false));
    request.generation = j.generation;
    assert_eq!(confirmed_request_is_replay(&j, &request), Err(Error::Conflict));
}

#[test]
fn terminal_rollback_with_proven_absence_is_inactive_despite_its_old_fence() {
    use xkeen_ui::runtime::networking::status::{NetworkState, OperationalEvidence, classify};
    let mut j = recovery_fixture();
    j.finish_rollback(&j.boot_id.clone());
    let mut evidence = OperationalEvidence {
        nft_semantic_sha256: "",
        route_and_rule_match: false,
        core_healthy: false,
        fence_absent: false,
        network_absent: true,
    };
    assert_eq!(
        classify(&j, &j.boot_id, 121_001, Some(&evidence), false),
        NetworkState::Inactive
    );
    evidence.network_absent = false;
    assert_eq!(
        classify(&j, &j.boot_id, 121_001, Some(&evidence), false),
        NetworkState::Degraded
    );
}

#[test]
fn nft_inventory_finds_foreign_table_and_tracks_known_masked_bits() {
    use xkeen_ui::runtime::networking::inventory::occupied_nft;
    let nft = br#"{"nftables":[{"metainfo":{"version":"1.0"}},{"table":{"family":"inet","name":"xkeenwrt"}},{"rule":{"family":"inet","table":"fw4","expr":[{"match":{"left":{"meta":{"key":"mark"}},"op":"==","right":256}}]}}]}"#;
    let found = occupied_nft(nft).unwrap();
    assert!(found.xkeenwrt_table_exists);
    assert_eq!(found.used_mark_mask, 0);
    assert_eq!(
        occupied_nft(br#"{"nftables":[{"rule":42}]}"#),
        Err(InventoryError::Unsupported)
    );
}

#[test]
fn transaction_does_not_mutate_without_matching_ready() {
    use xkeen_ui::runtime::networking::transaction::{Coordinator, Driver, Error, Pending, Request};
    #[derive(Default)]
    struct Fake {
        pending: Option<Pending>,
        applied: bool,
    }
    impl Driver for Fake {
        type Guard = ();
        fn idle_ready(&mut self, _: &Request, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn lock(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn now_ms(&mut self) -> Result<u64, Error> {
            Ok(100)
        }
        fn boot_id(&mut self) -> Result<String, Error> {
            Ok("boot".into())
        }
        fn make_token(&mut self, _: &str, _: &Request) -> Result<String, Error> {
            Ok("token".into())
        }
        fn load_pending(&mut self) -> Result<Option<Pending>, Error> {
            Ok(self.pending.clone())
        }
        fn prepare_pending(&mut self, p: &Pending) -> Result<(), Error> {
            self.pending = Some(p.clone());
            Ok(())
        }
        fn await_ready(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn ready(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(false)
        }
        fn revalidate(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn not_revoked(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn apply(&mut self, _: &Pending) -> Result<(), Error> {
            self.applied = true;
            Ok(())
        }
        fn mark_applied(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn is_applied(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(false)
        }
        fn verify_active(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn health(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn confirm(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
    }
    let mut c = Coordinator::new(Fake::default());
    let request = Request {
        plan_id: "plan".into(),
        candidate_id: "candidate".into(),
        idempotency_key: "key".into(),
        generation: 1,
    };
    assert_eq!(c.apply(request), Err(Error::NotReady));
    assert!(!c.driver().applied);
    let pending = c.driver().pending.clone().unwrap();
    assert_eq!(
        c.confirm(&pending.transaction_id, &pending.confirm_token),
        Err(Error::NotReady)
    );
}

#[test]
fn confirmation_token_is_bound_to_transaction_and_retry_key() {
    use xkeen_ui::runtime::networking::transaction::confirmation_token;
    let mut key = [0u8; 32];
    for (n, byte) in key.iter_mut().enumerate() {
        *byte = n as u8;
    }
    assert_eq!(
        confirmation_token(&key, "tx", 7, "plan", "key"),
        "5d9614c4497bf259fc1384adb9b7bce8bcd6c4f2b38d135d702bf140171d9024"
    );
    assert_ne!(
        confirmation_token(&key, "tx", 7, "plan", "key"),
        confirmation_token(&key, "tx", 8, "plan", "key")
    );
}

#[test]
fn successful_apply_retries_same_transaction_and_requires_explicit_confirm() {
    use xkeen_ui::runtime::networking::transaction::{Coordinator, Driver, Error, Pending, Request};
    struct Lock(std::rc::Rc<std::cell::Cell<bool>>);
    impl Drop for Lock {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }
    struct Good {
        locked: std::rc::Rc<std::cell::Cell<bool>>,
        pending: Option<Pending>,
        applied: bool,
        confirmed: bool,
        executions: usize,
        manifest: xkeenwrt_recovery::Manifest,
        owned_nft: Vec<u8>,
        boot: String,
        attached: bool,
    }
    impl Default for Good {
        fn default() -> Self {
            let mut manifest = recovery_fixture().current;
            let ast = manifest.expected_nft_ast().unwrap();
            let owned_nft = serde_json::to_vec(&ast).unwrap();
            manifest.nft_semantic_sha256 = xkeenwrt_recovery::nft_semantic_digest(&owned_nft).unwrap();
            Self {
                locked: std::rc::Rc::new(std::cell::Cell::new(false)),
                pending: None,
                applied: false,
                confirmed: false,
                executions: 0,
                manifest,
                owned_nft,
                boot: "00000000-0000-4000-8000-000000000006".into(),
                attached: false,
            }
        }
    }
    impl Driver for Good {
        type Guard = Lock;
        fn idle_ready(&mut self, _: &Request, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn lock(&mut self) -> Result<Lock, Error> {
            assert!(!self.locked.replace(true));
            Ok(Lock(self.locked.clone()))
        }
        fn now_ms(&mut self) -> Result<u64, Error> {
            Ok(1_001)
        }
        fn boot_id(&mut self) -> Result<String, Error> {
            Ok(self.boot.clone())
        }
        fn make_token(&mut self, tx: &str, request: &Request) -> Result<String, Error> {
            Ok(xkeen_ui::runtime::networking::transaction::confirmation_token(
                &[7; 32],
                tx,
                request.generation,
                &request.plan_id,
                &request.idempotency_key,
            ))
        }
        fn load_pending(&mut self) -> Result<Option<Pending>, Error> {
            Ok(self.pending.clone())
        }
        fn prepare_pending(&mut self, p: &Pending) -> Result<(), Error> {
            self.pending = Some(p.clone());
            Ok(())
        }
        fn await_ready(&mut self, _: &Pending) -> Result<(), Error> {
            self.attached = true;
            Ok(())
        }
        fn attach_pending(&mut self, _: &Pending) -> Result<(), Error> {
            self.attached = true;
            Ok(())
        }
        fn ready(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(self.attached)
        }
        fn revalidate(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn not_revoked(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn apply(&mut self, _: &Pending) -> Result<(), Error> {
            self.executions += 1;
            Ok(())
        }
        fn mark_applied(&mut self, _: &Pending) -> Result<(), Error> {
            self.applied = true;
            Ok(())
        }
        fn is_applied(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(self.applied)
        }
        fn verify_active(&mut self, pending: &Pending) -> Result<bool, Error> {
            let digest = xkeenwrt_recovery::nft_semantic_digest(&self.owned_nft).map_err(|_| Error::Conflict)?;
            let routes_match = xkeen_ui::runtime::networking::status::routing_matches(
                &self.manifest,
                br#"[{"priority":10000,"src":"all","fwmark":"0x100/0x100","table":100}]"#,
                br#"[{"type":"local","dst":"default","dev":"lo","table":100}]"#,
            )
            .map_err(|_| Error::Conflict)?;
            Ok(pending.request.generation == self.manifest.generation
                && digest == self.manifest.nft_semantic_sha256
                && xkeen_ui::runtime::networking::collector::hook_topology_for_current(
                    &self.owned_nft,
                    Some(&self.manifest),
                )
                .map_err(|_| Error::Conflict)?
                && routes_match)
        }
        fn health(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn confirmed_for(&mut self, request: &Request) -> Result<Option<String>, Error> {
            if !self.confirmed {
                return Ok(None);
            }
            let p = self.pending.as_ref().ok_or(Error::Conflict)?;
            if &p.request != request {
                return Err(Error::Conflict);
            }
            Ok(Some(p.transaction_id.clone()))
        }
        fn confirm(&mut self, _: &Pending) -> Result<(), Error> {
            self.confirmed = true;
            Ok(())
        }
    }
    let mut c = Coordinator::new(Good::default());
    let request = Request {
        plan_id: "00000000-0000-4000-8000-000000000003".into(),
        candidate_id: "candidate-1".into(),
        idempotency_key: "synthetic-idempotency".into(),
        generation: 2,
    };
    let pending = c.apply(request.clone()).unwrap();
    assert_eq!(pending.deadline_ms, 121_001);
    assert!(!c.driver().confirmed);
    assert_eq!(c.apply(request.clone()).unwrap(), pending);
    assert_eq!(c.driver().executions, 1);
    assert_eq!(c.confirm(&pending.transaction_id, "wrong"), Err(Error::Conflict));
    assert!(!c.driver().confirmed);

    // Rebuild the pending token from the durable journal, then confirm with a
    // fresh driver as Runtime does after restart. Verification parses the exact
    // owned nft table and real route/rule shape instead of trusting a boolean.
    use sha2::{Digest, Sha256};
    let key = [7; 32];
    let mut journal = recovery_fixture();
    journal.state = xkeenwrt_recovery::State::Pending;
    journal.applied = true;
    journal.tx_id = pending.transaction_id.clone();
    journal.created_boottime_ms = 1_001;
    journal.deadline_boottime_ms = pending.deadline_ms;
    journal.current = c.driver().manifest.clone();
    journal.confirm_token_sha256 = Sha256::digest(pending.confirm_token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let reloaded =
        xkeen_ui::runtime::networking::transaction::pending_from_journal(&journal, &key, &journal.boot_id, 1_001)
            .unwrap();
    assert_eq!(reloaded, pending);
    let restarted = Good {
        pending: Some(reloaded),
        applied: true,
        ..Good::default()
    };
    let mut after_restart = Coordinator::new(restarted);
    assert_eq!(after_restart.apply(request.clone()).unwrap(), pending);
    after_restart
        .confirm(&pending.transaction_id, &pending.confirm_token)
        .unwrap();
    assert!(after_restart.driver().confirmed);

    journal.state = xkeenwrt_recovery::State::Confirmed;
    assert_eq!(
        after_restart.apply_or_replay(request).unwrap(),
        xkeen_ui::runtime::networking::transaction::ApplyOutcome::Confirmed {
            transaction_id: pending.transaction_id.clone()
        }
    );
    assert_eq!(c.driver().executions, 1);
    assert_eq!(after_restart.driver().executions, 0);
    let active = xkeenwrt_recovery::active::active_manifest(&journal).unwrap();
    let digest = active.nft_semantic_sha256.clone();
    let evidence = xkeen_ui::runtime::networking::status::OperationalEvidence {
        nft_semantic_sha256: &digest,
        route_and_rule_match: true,
        core_healthy: true,
        fence_absent: true,
        network_absent: false,
    };
    assert_eq!(
        xkeen_ui::runtime::networking::status::classify(&journal, &journal.boot_id, 1_002, Some(&evidence), false,),
        xkeen_ui::runtime::networking::status::NetworkState::Active
    );
}

#[test]
fn ready_marker_must_match_live_procd_instance_and_transaction() {
    use std::os::unix::fs::PermissionsExt;
    use xkeen_ui::runtime::networking::helper::{SupervisorIdentity, ready_matches};
    if unsafe { nix::libc::geteuid() } != 0 {
        return;
    }
    let path = std::env::temp_dir().join(format!("xkeenwrt-marker-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, br#"{"version":1,"owner_id":"owner","boot_id":"boot","pid":42,"starttime":99,"nonce":"nonce","exe_sha256":"digest","tx_id":"tx","generation":9}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let id = SupervisorIdentity {
        version: 1,
        owner_id: "owner".into(),
        boot_id: "boot".into(),
        pid: 42,
        starttime: 99,
        nonce: "nonce".into(),
        exe_sha256: "digest".into(),
    };
    assert!(ready_matches(&path, "tx", 9, &id).unwrap());
    assert!(!ready_matches(&path, "tx", 10, &id).unwrap());
    let mut different = id.clone();
    different.nonce = "replacement".into();
    assert!(!ready_matches(&path, "tx", 9, &different).unwrap());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ready_matches(&path, "tx", 9, &id).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn client_mac_requires_unambiguous_neighbour_and_lease_evidence() {
    use xkeen_ui::runtime::networking::inventory::resolve_client_mac;
    let neighbours = br#"[{"dst":"192.168.1.5","dev":"br-lan","lladdr":"02:00:00:00:00:05","state":["REACHABLE"]},{"dst":"192.168.1.2","dev":"br-lan","lladdr":"02:00:00:00:00:02","state":["STALE"]}]"#;
    let leases = b"0 02:00:00:00:00:05 192.168.1.5 client *\n0 02:00:00:00:00:02 192.168.1.2 admin *\n";
    assert_eq!(
        resolve_client_mac(
            neighbours,
            leases,
            "br-lan",
            "192.168.1.5".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            100
        )
        .unwrap(),
        "02:00:00:00:00:05"
    );
    let conflicting = b"0 02:00:00:00:00:06 192.168.1.5 client *\n0 02:00:00:00:00:02 192.168.1.2 admin *\n";
    assert_eq!(
        resolve_client_mac(
            neighbours,
            conflicting,
            "br-lan",
            "192.168.1.5".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            100
        ),
        Err(InventoryError::Unsupported)
    );
}

#[test]
fn ethernet_identity_rejects_tunnels_and_unknown_links() {
    use xkeen_ui::runtime::networking::inventory::ethernet_like;
    let links = br#"[{"ifname":"br-lan","link_type":"ether","linkinfo":{"info_kind":"bridge"}},{"ifname":"wg0","link_type":"none","linkinfo":{"info_kind":"wireguard"}}]"#;
    assert!(ethernet_like(links, "br-lan").unwrap());
    assert!(!ethernet_like(links, "wg0").unwrap());
    assert!(!ethernet_like(links, "missing").unwrap());
}

fn recovery_fixture() -> xkeenwrt_recovery::Journal {
    xkeenwrt_recovery::Journal {
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
        state: xkeenwrt_recovery::State::Pending,
        completion: None,
        current: xkeenwrt_recovery::Manifest {
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
        network_evidence: None,
        previous_network_evidence: None,
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
fn pending_reconstruction_rejects_changed_key_and_expired_boot() {
    use sha2::{Digest, Sha256};
    use xkeen_ui::runtime::networking::transaction::{confirmation_token, pending_from_journal};
    let mut j = recovery_fixture();
    let key = [5u8; 32];
    let token = confirmation_token(&key, &j.tx_id, j.generation, &j.plan_id, &j.idempotency_key);
    j.confirm_token_sha256 = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = pending_from_journal(&j, &key, "00000000-0000-4000-8000-000000000006", 1_001).unwrap();
    assert_eq!(p.confirm_token, token);
    assert!(pending_from_journal(&j, &[6; 32], "00000000-0000-4000-8000-000000000006", 1_001).is_err());
    assert!(pending_from_journal(&j, &key, "boot-2", 1_001).is_err());
    assert!(pending_from_journal(&j, &key, "00000000-0000-4000-8000-000000000006", 121_000).is_err());
}

#[test]
fn recovery_pid_requires_single_running_expected_procd_instance() {
    use xkeen_ui::runtime::networking::helper::procd_pid;
    let one = br#"{"xkeenwrt-rescue":{"instances":{"instance1":{"running":true,"pid":42,"command":["/etc/xkeenwrt/rescue/xkeenwrt-recovery","supervise"]}}}}"#;
    assert_eq!(procd_pid(one).unwrap(), 42);
    let bad = br#"{"xkeenwrt-rescue":{"instances":{"a":{"running":true,"pid":42,"command":["/tmp/recovery"]}}}}"#;
    assert!(procd_pid(bad).is_err());
    let many = br#"{"xkeenwrt-rescue":{"instances":{"a":{"running":true,"pid":42,"command":["/etc/xkeenwrt/rescue/xkeenwrt-recovery","supervise"]},"b":{"running":true,"pid":43,"command":["/etc/xkeenwrt/rescue/xkeenwrt-recovery","supervise"]}}}}"#;
    assert!(procd_pid(many).is_err());
}

#[test]
fn nft_simple_masked_match_only_reserves_compared_bits() {
    use xkeen_ui::runtime::networking::inventory::occupied_nft;
    let rules = br#"{"nftables":[{"rule":{"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},65280]},"right":256}}]}}]}"#;
    assert_eq!(occupied_nft(rules).unwrap().used_mark_mask, 0xff00);
}

#[test]
fn dnsmasq_split_upstreams_preserve_local_resolution() {
    use xkeen_ui::runtime::networking::inventory::dnsmasq_facts;
    let config = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1","/corp.example/192.0.2.53"]}}}"#;
    let facts = dnsmasq_facts(config).unwrap();
    assert_eq!(
        facts.upstreams,
        vec![xkeenwrt_recovery::evidence::Endpoint {
            address: "1.1.1.1".parse().unwrap(),
            port: 53
        }]
    );
    assert!(facts.local_zones.contains(&"+.corp.example".to_string()));
    assert!(facts.local_zones.contains(&"+.lan".to_string()));
    let changed=br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1","/corp.example/192.0.2.54"]}}}"#;
    assert_ne!(facts, dnsmasq_facts(changed).unwrap());
    assert!(dnsmasq_facts(br#"{"values":{"dns":{".type":"dnsmasq","server":["1.1.1.1"]}}}"#).is_err());
}

#[test]
fn address_inventory_binds_lan_and_collects_local_networks() {
    use xkeen_ui::runtime::networking::inventory::address_facts;
    let data = br#"[{"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24},{"family":"inet6","local":"fd00::1","prefixlen":64}]},{"ifname":"wan","addr_info":[{"family":"inet","local":"198.51.100.2","prefixlen":24}]}]"#;
    let facts = address_facts(data, "br-lan").unwrap();
    assert_eq!(facts.lan_address, "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(facts.lan_cidrs, vec!["192.0.2.1/24"]);
    assert!(facts.local_ipv4.contains(&"198.51.100.2/24".to_owned()));
    assert_eq!(facts.local_ipv6, vec!["fd00::1/64"]);
    assert!(address_facts(data, "missing").is_err());
}

#[test]
fn empty_foreign_rule_does_not_prove_a_damaging_conflict() {
    use xkeen_ui::runtime::networking::collector::hook_topology_safe;
    let safe = br#"{"nftables":[{"table":{"family":"inet","name":"fw4"}}]}"#;
    let foreign = br#"{"nftables":[{"chain":{"family":"inet","table":"fw4","name":"dstnat","hook":"prerouting","prio":-100}},{"rule":{"family":"inet","table":"fw4","chain":"dstnat","expr":[]}}]}"#;
    assert!(hook_topology_safe(safe).unwrap());
    assert!(hook_topology_safe(foreign).unwrap());
}

#[test]
fn stock_fw4_empty_helper_jump_is_safe_but_nonempty_target_blocks() {
    use xkeen_ui::runtime::networking::collector::hook_topology_safe;
    // Captured nft JSON shape from OpenWrt 25.12.6 fw4 with no conntrack helpers configured.
    let stock_fw4 = br#"{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"chain":{"family":"inet","table":"fw4","name":"prerouting","handle":4,"type":"filter","hook":"prerouting","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"fw4","name":"helper_lan","handle":10}},{"rule":{"family":"inet","table":"fw4","chain":"prerouting","handle":240,"comment":"!fw4: Handle lan IPv4/IPv6 helper assignment","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"jump":{"target":"helper_lan"}}]}}]}"#;
    let helper_with_rule = br#"{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"chain":{"family":"inet","table":"fw4","name":"prerouting","handle":4,"type":"filter","hook":"prerouting","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"fw4","name":"helper_lan","handle":10}},{"rule":{"family":"inet","table":"fw4","chain":"prerouting","handle":240,"comment":"!fw4: Handle lan IPv4/IPv6 helper assignment","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"jump":{"target":"helper_lan"}}]}},{"rule":{"family":"inet","table":"fw4","chain":"helper_lan","handle":241,"expr":[{"accept":null}]}}]}"#;

    assert!(hook_topology_safe(stock_fw4).unwrap());
    assert!(hook_topology_safe(helper_with_rule).unwrap());
}

#[test]
fn stock_fw4_empty_helper_jump_requires_one_same_table_empty_target() {
    use xkeen_ui::runtime::networking::collector::hook_topology_safe;
    let mut stock: serde_json::Value = serde_json::from_slice(br#"{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"chain":{"family":"inet","table":"fw4","name":"prerouting","handle":4,"type":"filter","hook":"prerouting","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"fw4","name":"helper_lan","handle":10}},{"rule":{"family":"inet","table":"fw4","chain":"prerouting","handle":240,"comment":"!fw4: Handle lan IPv4/IPv6 helper assignment","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"jump":{"target":"helper_lan"}}]}}]}"#).unwrap();
    let mut missing = stock.clone();
    missing["nftables"].as_array_mut().unwrap().remove(2);
    assert!(
        hook_topology_safe(&serde_json::to_vec(&missing).unwrap()).unwrap(),
        "unknown jump warns"
    );

    let mut duplicate = stock.clone();
    duplicate["nftables"].as_array_mut().unwrap().insert(
        3,
        serde_json::json!({"chain":{"family":"inet","table":"fw4","name":"helper_lan","handle":11}}),
    );
    assert!(
        hook_topology_safe(&serde_json::to_vec(&duplicate).unwrap()).is_err(),
        "malformed duplicate inventory is unavailable"
    );

    let mut different_table = stock.clone();
    different_table["nftables"].as_array_mut().unwrap()[2]["chain"]["table"] = serde_json::json!("other");
    assert!(hook_topology_safe(&serde_json::to_vec(&different_table).unwrap()).unwrap());

    stock["nftables"][3]["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .insert(1, serde_json::json!({"mangle":{"key":{"meta":"mark"},"value":1}}));
    assert!(hook_topology_safe(&serde_json::to_vec(&stock).unwrap()).unwrap());
}

#[test]
fn occupied_listener_ports_are_not_available_for_pilot() {
    use xkeen_ui::runtime::networking::{
        collector::{listener_ports_free, occupied_listener_port},
        inventory::InventoryError,
    };
    let empty = b"sl local_address rem_address st\n";
    let occupied = b"sl local_address rem_address st\n0: 00000000:1ED5 00000000:0000 0A\n";
    assert!(listener_ports_free(empty).unwrap());
    assert!(!listener_ports_free(occupied).unwrap());
    assert_eq!(occupied_listener_port(occupied).unwrap(), Some(7893));
    assert_eq!(
        occupied_listener_port(b"sl local_address rem_address st\n0: 00000000:041D 00000000:0000 07\n").unwrap(),
        Some(1053)
    );
    assert_eq!(
        occupied_listener_port(b"sl local_address rem_address st\n0: 00000000:1ED2 00000000:0000 0A\n").unwrap(),
        None
    );
    assert_eq!(
        occupied_listener_port(b"sl local_address rem_address st\n0: invalid:1ED5 00000000:0000 0A\n"),
        Err(InventoryError::Unsupported)
    );
    assert!(listener_ports_free(b"invalid\ninvalid entry\n").is_err());
}

#[test]
fn fw4_dns_redirect_coexists_without_admitting_other_nat() {
    use serde_json::json;
    use xkeen_ui::runtime::networking::collector::hook_topology_safe;
    // OpenWrt 25.12.6's LAN DNS redirect, behind the stock dstnat jump.
    let rules = json!({"nftables":[
        {"chain":{"family":"inet","table":"fw4","name":"dstnat","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
        {"chain":{"family":"inet","table":"fw4","name":"dstnat_lan"}},
        {"rule":{"family":"inet","table":"fw4","chain":"dstnat","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},
            {"jump":{"target":"dstnat_lan"}}
        ]}},
        {"rule":{"family":"inet","table":"fw4","chain":"dstnat_lan","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":53}},
            {"counter":{"packets":42,"bytes":3000}}, {"redirect":{"port":53}}
        ]}},
        {"rule":{"family":"inet","table":"fw4","chain":"dstnat_lan","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},
            {"counter":{"packets":42,"bytes":3000}}, {"redirect":{"port":53}}
        ]}}
    ]});
    let safe = |v: &serde_json::Value| hook_topology_safe(&serde_json::to_vec(v).unwrap()).unwrap();
    assert!(safe(&rules));
    let mut bad = rules.clone();
    bad["nftables"][0]["chain"]["prio"] = json!(-152);
    assert!(!safe(&bad));
    let mut bad = rules.clone();
    bad["nftables"][3]["rule"]["expr"][1]["match"]["right"] = json!(443);
    assert!(!safe(&bad));
    let mut bad = rules.clone();
    bad["nftables"][3]["rule"]["expr"][3] = json!({"dnat":{"addr":"192.0.2.50","port":53}});
    assert!(!safe(&bad));
    let mut bad = rules.clone();
    bad["nftables"][4]["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}));
    assert!(
        safe(&bad),
        "harmless early mark or unknown traversal is not a proven conflict"
    );
    let mut bad = rules.clone();
    bad["nftables"][3]["rule"]["expr"] = json!([{"jump":{"target":"dstnat_lan"}}]);
    assert!(
        safe(&bad),
        "harmless early mark or unknown traversal is not a proven conflict"
    );
    let mut bad = rules.clone();
    bad["nftables"].as_array_mut().unwrap().remove(1);
    assert!(
        safe(&bad),
        "harmless early mark or unknown traversal is not a proven conflict"
    );
}
#[test]
fn ipv6_diagnostics_come_from_the_same_trusted_mac() {
    use xkeen_ui::runtime::networking::inventory::ipv6_for_mac;
    let neighbours = br#"[{"dst":"fd00::5","dev":"br-lan","lladdr":"02:00:00:00:00:05","state":["STALE"]},{"dst":"fd00::2","dev":"br-lan","lladdr":"02:00:00:00:00:02","state":["REACHABLE"]}]"#;
    assert_eq!(
        ipv6_for_mac(neighbours, "br-lan", "02:00:00:00:00:05").unwrap(),
        vec!["fd00::5".parse::<std::net::Ipv6Addr>().unwrap()]
    );
}

#[test]
fn durable_identity_never_reuses_generation_or_recreates_lost_counter() {
    use std::os::unix::fs::PermissionsExt;
    use xkeen_ui::runtime::networking::identity::reserve;
    if unsafe { nix::libc::geteuid() } != 0 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("xkeenwrt-identity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = dir.join("owner-id");
    let counter = dir.join("network-generation");
    std::fs::write(&owner, "00000000-0000-4000-8000-000000000001").unwrap();
    std::fs::write(&counter, "0\n").unwrap();
    std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&counter, std::fs::Permissions::from_mode(0o600)).unwrap();
    let first = reserve(&dir).unwrap();
    let second = reserve(&dir).unwrap();
    assert_eq!(first.owner_id, second.owner_id);
    assert_eq!(second.generation, first.generation + 1);
    std::fs::remove_file(dir.join("network-generation")).unwrap();
    assert!(reserve(&dir).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_identity_extracts_starttime_even_with_parentheses_in_name() {
    use xkeen_ui::runtime::networking::helper::runtime_identity_from_stat;
    let stat = "42 (worker ) test) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 0 0\n";
    assert_eq!(runtime_identity_from_stat(stat).unwrap(), (42, 999));
    assert!(runtime_identity_from_stat("42 (broken) S 1 2").is_err());
}

#[test]
fn network_status_does_not_treat_an_expired_pending_transaction_as_active() {
    use xkeen_ui::runtime::networking::status::{NetworkState, classify};
    let j = recovery_fixture();
    assert_eq!(
        classify(&j, "00000000-0000-4000-8000-000000000006", 1_001, None, false),
        NetworkState::Pending
    );
    assert_eq!(
        classify(&j, "00000000-0000-4000-8000-000000000006", 121_000, None, false),
        NetworkState::Recovering
    );
    assert_eq!(
        classify(&j, "different-boot", 1_001, None, false),
        NetworkState::Recovering
    );
}

#[test]
fn active_status_requires_owned_semantics_routes_core_and_absent_fence() {
    use xkeen_ui::runtime::networking::status::{NetworkState, OperationalEvidence, classify};
    let mut j = recovery_fixture();
    j.state = xkeenwrt_recovery::State::Confirmed;
    j.applied = true;
    assert_eq!(
        classify(&j, "00000000-0000-4000-8000-000000000006", 1_001, None, false),
        NetworkState::Degraded
    );
    let mut evidence = OperationalEvidence {
        nft_semantic_sha256: &j.current.nft_semantic_sha256,
        route_and_rule_match: true,
        core_healthy: true,
        fence_absent: true,
        network_absent: false,
    };
    assert_eq!(
        classify(
            &j,
            "00000000-0000-4000-8000-000000000006",
            1_001,
            Some(&evidence),
            false
        ),
        NetworkState::Active
    );
    evidence.fence_absent = false;
    assert_eq!(
        classify(
            &j,
            "00000000-0000-4000-8000-000000000006",
            1_001,
            Some(&evidence),
            false
        ),
        NetworkState::Degraded
    );
    assert_eq!(
        classify(&j, "new-boot", 1_001, Some(&evidence), false),
        NetworkState::Recovering
    );
}

#[test]
fn routing_evidence_rejects_missing_or_extra_rules() {
    use xkeen_ui::runtime::networking::status::routing_matches;
    let j = recovery_fixture();
    let rules = br#"[{"priority":10000,"src":"all","fwmark":"0x100/0x100","table":100}]"#;
    let routes = br#"[{"type":"local","dst":"default","dev":"lo","table":100}]"#;
    assert!(routing_matches(&j.current, rules, routes).unwrap());
    assert!(!routing_matches(&j.current, br#"[]"#, routes).unwrap());
    let duplicate = br#"[{"priority":10000,"src":"all","fwmark":"0x100/0x100","table":100},{"priority":10000,"src":"all","fwmark":"0x100/0x100","table":100}]"#;
    assert!(!routing_matches(&j.current, duplicate, routes).unwrap());
}

#[test]
fn first_pilot_consumes_never_enabled_marker_only_once() {
    use std::os::unix::fs::PermissionsExt;
    use xkeen_ui::runtime::networking::identity::consume_never_enabled;
    if unsafe { nix::libc::geteuid() } != 0 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("xkeenwrt-marker-dir-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = dir.join("network-never-enabled");
    std::fs::write(&marker, b"xkeenwrt-no-network-v1\n").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    consume_never_enabled(&dir).unwrap();
    assert!(!marker.exists());
    assert!(consume_never_enabled(&dir).is_err());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn post_start_listeners_must_belong_to_exact_core_process() {
    use xkeen_ui::runtime::networking::collector::listeners_owned;
    let tcp = b"sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n0: 010200C0:1ED5 00000000:0000 0A 0:0 0:0 0 0 0 11\n1: 010200C0:041D 00000000:0000 0A 0:0 0:0 0 0 0 12\n";
    let udp = b"sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n0: 010200C0:1ED5 00000000:0000 07 0:0 0:0 0 0 0 13\n1: 010200C0:041D 00000000:0000 07 0:0 0:0 0 0 0 14\n";
    let empty = b"sl local_address rem_address st\n";
    let lan = "192.0.2.1".parse().unwrap();
    assert!(listeners_owned([tcp, udp, empty, empty], lan, &[11, 12, 13, 14]).unwrap());
    assert!(!listeners_owned([tcp, udp, empty, empty], lan, &[11, 12, 13]).unwrap());
}

#[test]
fn dns_tcp_connections_do_not_hide_the_verified_listeners() {
    use xkeen_ui::runtime::networking::collector::{listener_ports_free, listeners_owned};
    let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n";
    let tcp = format!(
        "{header}0: 010200C0:1ED5 00000000:0000 0A 0:0 0:0 0 0 0 11\n1: 010200C0:041D 00000000:0000 0A 0:0 0:0 0 0 0 12\n2: 010200C0:041D 020200C0:A123 01 0:0 0:0 0 0 0 15\n3: 010200C0:041D 020200C0:A124 06 0:0 0:0 0 0 0 0\n"
    );
    let udp = format!(
        "{header}0: 010200C0:1ED5 00000000:0000 07 0:0 0:0 0 0 0 13\n1: 010200C0:041D 00000000:0000 07 0:0 0:0 0 0 0 14\n"
    );
    let lan = "192.0.2.1".parse().unwrap();
    assert!(
        listeners_owned(
            [tcp.as_bytes(), udp.as_bytes(), header.as_bytes(), header.as_bytes()],
            lan,
            &[11, 12, 13, 14, 15]
        )
        .unwrap()
    );
    // An unowned live connection remains a conflict; TIME_WAIT has no owner.
    assert!(
        !listeners_owned(
            [tcp.as_bytes(), udp.as_bytes(), header.as_bytes(), header.as_bytes()],
            lan,
            &[11, 12, 13, 14]
        )
        .unwrap()
    );
    let stale = format!("{header}0: 010200C0:041D 020200C0:A124 06 0:0 0:0 0 0 0 0\n");
    assert!(listener_ports_free(stale.as_bytes()).unwrap());
    assert!(!listener_ports_free(stale.replace(" 06 ", " 01 ").as_bytes()).unwrap());
}

#[test]
fn foreign_prerouting_rule_is_safe_when_first_match_excludes_lan() {
    use xkeen_ui::runtime::networking::collector::hook_topology_for_ingress;
    let nft = br#"{"nftables":[{"chain":{"family":"inet","table":"fw4","name":"dstnat","hook":"prerouting","prio":-100}},{"rule":{"family":"inet","table":"fw4","chain":"dstnat","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wan"}},{"jump":{"target":"dstnat_wan"}}]}}]}"#;
    assert!(hook_topology_for_ingress(nft, &["br-lan", "eth1"]).unwrap());
    assert!(
        hook_topology_for_ingress(nft, &["br-lan", "wan"]).unwrap(),
        "missing target is an unknown warning"
    );
}

#[test]
fn confirmed_owned_prerouting_table_does_not_disable_network_capability() {
    use xkeen_ui::runtime::networking::collector::hook_topology_for_current;
    let mut manifest = recovery_fixture().current;
    let expected = manifest.expected_nft_ast().unwrap();
    manifest.nft_semantic_sha256 =
        xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&expected).unwrap()).unwrap();
    let owned = serde_json::to_vec(&expected).unwrap();

    assert!(hook_topology_for_current(&owned, Some(&manifest)).unwrap());
    assert!(!hook_topology_for_current(&owned, None).unwrap());

    let mut changed = expected.clone();
    changed["nftables"][0]["table"]["comment"] = serde_json::json!("foreign-owner");
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(hook_topology_for_current(&changed, Some(&manifest)).is_err());

    let mut with_foreign_hook = expected;
    let rules = with_foreign_hook["nftables"].as_array_mut().unwrap();
    rules.extend([
        serde_json::json!({"table":{"family":"inet","name":"fw4"}}),
        serde_json::json!({"chain":{"family":"inet","table":"fw4","name":"dstnat","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}}),
        serde_json::json!({"rule":{"family":"inet","table":"fw4","chain":"dstnat","expr":[{"accept":null}]}}),
    ]);
    let with_foreign_hook = serde_json::to_vec(&with_foreign_hook).unwrap();
    assert!(
        hook_topology_for_current(&with_foreign_hook, Some(&manifest)).unwrap(),
        "accept does not override later base hooks"
    );

    let mut with_stock_fw4: serde_json::Value = serde_json::from_slice(&owned).unwrap();
    let stock_fw4: serde_json::Value = serde_json::from_slice(br#"{"nftables":[{"chain":{"family":"inet","table":"fw4","name":"prerouting","handle":4,"type":"filter","hook":"prerouting","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"fw4","name":"helper_lan","handle":10}},{"rule":{"family":"inet","table":"fw4","chain":"prerouting","handle":240,"comment":"!fw4: Handle lan IPv4/IPv6 helper assignment","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"jump":{"target":"helper_lan"}}]}}]}"#).unwrap();
    with_stock_fw4["nftables"]
        .as_array_mut()
        .unwrap()
        .extend(stock_fw4["nftables"].as_array().unwrap().iter().cloned());
    assert!(hook_topology_for_current(&serde_json::to_vec(&with_stock_fw4).unwrap(), Some(&manifest)).unwrap());
}

#[test]
fn confirmed_retry_accepts_exact_token_after_pending_deadline_only_without_fence() {
    use sha2::{Digest, Sha256};
    use xkeen_ui::runtime::networking::transaction::{confirmation_token, confirmed_token_matches};
    let mut j = recovery_fixture();
    j.state = xkeenwrt_recovery::State::Confirmed;
    j.applied = true;
    let key = [7u8; 32];
    let token = confirmation_token(&key, &j.tx_id, j.generation, &j.plan_id, &j.idempotency_key);
    j.confirm_token_sha256 = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(confirmed_token_matches(&j, &key, &j.tx_id, &token, true));
    assert!(!confirmed_token_matches(&j, &key, &j.tx_id, &token, false));
    assert!(!confirmed_token_matches(&j, &key, &j.tx_id, "wrong", true));
}

#[test]
fn retired_generation_cannot_be_reused_while_any_owned_reservation_remains() {
    use xkeen_ui::network::Inventory;
    use xkeen_ui::runtime::networking::status::retired_resources_absent;
    let mut j = recovery_fixture();
    j.state = xkeenwrt_recovery::State::RolledBack;
    let mut inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ..Default::default()
    };
    assert!(retired_resources_absent(&j, &inventory));
    inventory.occupied_priorities.push(j.current.priority);
    assert!(!retired_resources_absent(&j, &inventory));
    inventory.occupied_priorities.clear();
    inventory.occupied_marks.push((0, j.current.mask));
    assert!(!retired_resources_absent(&j, &inventory));
}

#[test]
fn network_overlay_uses_the_dns_plan_as_its_single_source() {
    use xkeen_ui::network::dns::{DnsInventory, DnsPlan};
    use xkeen_ui::runtime::networking::dns::overlay_from_dns_plan;
    let dns = DnsPlan::new(&DnsInventory {
        dnsmasq_instances: 1,
        incompatible_manager: false,
        local_names: vec!["+.lan".into()],
        upstreams: vec!["127.0.0.1#5053".into()],
        split_upstreams: vec![],
        verified_loopback_chain_sha256: Some("a".repeat(64)),
        bootstrap: vec!["127.0.0.1".parse().unwrap()],
    })
    .unwrap();
    let overlay = overlay_from_dns_plan(
        "br-lan",
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        &dns,
    )
    .unwrap();
    assert_eq!(
        overlay.nameservers,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(overlay.local_zones, vec!["+.lan".to_string()]);
    let actual = overlay.dns().unwrap();
    assert_eq!(actual["nameserver"][0], "127.0.0.1:53");
}

#[test]
fn dns_loopback_chain_preserves_custom_ports_and_requires_owned_udp_listener() {
    use xkeenwrt_recovery::evidence::inventory::{dnsmasq_facts, verified_loopback_chain};
    let dns = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["127.0.0.1#5053","127.0.0.1#5054","/ru/77.88.8.8#53"]}}}"#;
    let proxy = br#"{"values":{"cfg":{".type":"https-dns-proxy","enabled":"1","listen_addr":"127.0.0.1","listen_port":"5053","resolver_url":"https://cloudflare-dns.com/dns-query","bootstrap_dns":"1.1.1.1,1.0.0.1"}}}"#;
    let service = br#"{"https-dns-proxy":{"instances":{"cfg":{"running":true,"pid":42,"command":["/usr/sbin/https-dns-proxy"]}}}}"#;
    let tcp = b" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:13BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 501\n";
    let udp = b" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:13BD 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 502\n";
    let empty = b" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    let facts = dnsmasq_facts(dns).unwrap();
    let digest = verified_loopback_chain(&facts, dns, proxy, service, [tcp, udp, empty, empty], &[501, 502]).unwrap();
    assert!(digest.is_some());
    assert_eq!(facts.upstreams[0].port, 5053);
    assert_eq!(facts.upstreams[1].port, 5054);
    assert_eq!(
        facts.split_upstreams[0].1.as_ref().unwrap().address.to_string(),
        "77.88.8.8"
    );
    let foreign_udp = std::str::from_utf8(udp).unwrap().replace("502", "999");
    assert!(
        verified_loopback_chain(
            &facts,
            dns,
            proxy,
            service,
            [tcp, foreign_udp.as_bytes(), empty, empty],
            &[501, 502]
        )
        .is_err()
    );
    let reverse = br#"{"values":{"cfg":{".type":"https-dns-proxy","enabled":"1","listen_addr":"127.0.0.1","listen_port":"5053","resolver_url":"https://127.0.0.1/dns-query","bootstrap_dns":"1.1.1.1"}}}"#;
    assert!(verified_loopback_chain(&facts, dns, reverse, service, [tcp, udp, empty, empty], &[501, 502]).is_err());
}

#[test]
fn direct_dns_needs_no_proxy_and_split_loopback_still_requires_one() {
    use xkeenwrt_recovery::evidence::{
        Endpoint,
        inventory::{dnsmasq_facts, validate_dns_targets, verified_loopback_chain},
    };
    let dns = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["10.0.0.3#53","/corp.example/192.0.2.54"]}}}"#;
    let facts = dnsmasq_facts(dns).unwrap();
    assert!(!facts.has_loopback_upstream());
    assert_eq!(
        verified_loopback_chain(&facts, dns, b"", b"", [b""; 4], &[]).unwrap(),
        None
    );
    validate_dns_targets(&facts, &[], &[], None).unwrap();

    let mut split_loopback = facts;
    split_loopback.split_upstreams[0].1 = Some(Endpoint {
        address: "127.0.0.1".parse().unwrap(),
        port: 5053,
    });
    assert!(split_loopback.has_loopback_upstream());
    assert!(verified_loopback_chain(&split_loopback, dns, b"", b"", [b""; 4], &[]).is_err());
}

#[test]
fn disable_request_is_durable_generation_bound_and_idempotent() {
    use std::os::unix::fs::PermissionsExt;
    use xkeen_ui::runtime::networking::active::request;
    use xkeenwrt_recovery::{State, active::Kind};
    if unsafe { nix::libc::geteuid() } != 0 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("xkeenwrt-disable-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = dir.join("mutation.lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut j = recovery_fixture();
    j.boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    j.state = State::Confirmed;
    j.applied = true;
    let current_boot = j.boot_id.clone();
    j.boot_id = "00000000-0000-4000-8000-000000000099".into();
    xkeenwrt_recovery::write_journal(&dir, &j).unwrap();
    assert!(
        request(
            &dir,
            &lock,
            &j.current.owner_id,
            j.generation,
            Kind::DisableRequested,
            Some("disable-key"),
            None
        )
        .is_err()
    );
    j.boot_id = current_boot;
    xkeenwrt_recovery::write_journal(&dir, &j).unwrap();
    let mut failed =
        xkeenwrt_recovery::active::ActiveRecord::new(&j, &uuid::Uuid::new_v4().to_string(), Kind::CoreFailed, None)
            .unwrap();
    failed.phase = xkeenwrt_recovery::active::Phase::Error;
    failed.failed_phase = Some(xkeenwrt_recovery::active::Phase::Requested);
    failed.error_code = Some("HEALTH".into());
    std::fs::write(
        dir.join("active-reconcile.json"),
        xkeenwrt_recovery::active::encode(&failed).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(
        dir.join("active-reconcile.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let first = request(
        &dir,
        &lock,
        &j.current.owner_id,
        j.generation,
        Kind::DisableRequested,
        Some("disable-key"),
        None,
    )
    .unwrap();
    let again = request(
        &dir,
        &lock,
        &j.current.owner_id,
        j.generation,
        Kind::DisableRequested,
        Some("disable-key"),
        None,
    )
    .unwrap();
    assert_eq!(first.event_id, again.event_id);
    assert_eq!(
        xkeen_ui::runtime::networking::active::current_status(&dir, &lock, &first.event_id)
            .unwrap()
            .state,
        xkeen_ui::runtime::networking::active::ReceiptState::Pending
    );
    assert!(
        request(
            &dir,
            &lock,
            &j.current.owner_id,
            j.generation,
            Kind::DisableRequested,
            Some("other-key"),
            None
        )
        .is_err()
    );
    assert!(
        request(
            &dir,
            &lock,
            &j.current.owner_id,
            j.generation + 1,
            Kind::DisableRequested,
            Some("disable-key"),
            None
        )
        .is_err()
    );
    let mut done = first.clone();
    done.phase = xkeenwrt_recovery::active::Phase::Completed;
    done.action = Some(xkeenwrt_recovery::active::Action::Disable);
    done.outcome = Some(xkeenwrt_recovery::active::Outcome::Disabled);
    j.state = State::Disabled;
    xkeenwrt_recovery::write_journal(&dir, &j).unwrap();
    std::fs::write(
        dir.join("active-reconcile.json"),
        xkeenwrt_recovery::active::encode(&done).unwrap(),
    )
    .unwrap();
    let replay = request(
        &dir,
        &lock,
        &j.current.owner_id,
        j.generation,
        Kind::DisableRequested,
        Some("disable-key"),
        None,
    )
    .unwrap();
    assert_eq!(replay.event_id, done.event_id);
    assert_eq!(replay.outcome, Some(xkeenwrt_recovery::active::Outcome::Disabled));
    assert_eq!(
        xkeen_ui::runtime::networking::active::current_status(&dir, &lock, &first.event_id)
            .unwrap()
            .state,
        xkeen_ui::runtime::networking::active::ReceiptState::Completed
    );
    assert_eq!(
        xkeen_ui::runtime::networking::active::latest_status(&dir, &lock)
            .unwrap()
            .unwrap()
            .event_id,
        first.event_id
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fresh_network_evidence_rejects_identity_and_dns_drift() {
    use xkeenwrt_recovery::evidence::{
        FixedInputs, NetworkEvidence, NftExpectation, OwnedExpectation, RoutingExpectation,
    };
    let mut m = recovery_fixture().current;
    m.local_ipv4 = vec!["192.0.2.1/24".into()];
    m.local_ipv6 = vec!["2001:db8::1/64".into()];
    let links = br#"[{"ifname":"br-test","link_type":"ether","linkinfo":{"info_kind":"bridge"}}]"#;
    let addresses = br#"[{"ifname":"br-test","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24},{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]"#;
    let neighbours = br#"[{"dst":"192.0.2.2","dev":"br-test","lladdr":"02:00:00:00:00:02","state":["STALE"]},{"dst":"192.0.2.3","dev":"br-test","lladdr":"02:00:00:00:00:03","state":["STALE"]},{"dst":"2001:db8::3","dev":"br-test","lladdr":"02:00:00:00:00:03","state":["STALE"]}]"#;
    let leases = b"0 02:00:00:00:00:02 192.0.2.2 client *\n0 02:00:00:00:00:03 192.0.2.3 admin *\n";
    let netifd = br#"{"interface":[{"interface":"lan","up":true,"l3_device":"br-test","ipv4-address":[{"address":"192.0.2.1"}]}]}"#;
    let dns = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1","/corp.example/192.0.2.53"]}}}"#;
    let mut input = FixedInputs {
        flowtables: None,
        links,
        addresses,
        neighbours,
        leases,
        netifd,
        dnsconfig: dns,
        proxyconfig: b"",
        proxyservice: b"",
        tcp4: b"",
        udp4: b"",
        tcp6: b"",
        udp6: b"",
        nft: br#"{"nftables":[]}"#,
        rules4: b"[]",
        rules6: b"[]",
        routes4: b"[]",
        routes6: b"[]",
        now_unix: 100,
    };
    let capture = |i: &FixedInputs<'_>| {
        NetworkEvidence::capture_fixed(
            i,
            OwnedExpectation {
                manifest: &m,
                scope_manifest: None,
                nft: NftExpectation::Absent,
                routing: RoutingExpectation::Absent,
            },
        )
    };
    let initial = capture(&input).unwrap();
    let mut old_flow = initial.clone();
    old_flow.version = 2;
    old_flow.flowtables = Some(vec![xkeenwrt_recovery::flow_offload::FlowTable {
        family: 1,
        table: "foreign".into(),
        name: "ft".into(),
        flags: 0,
        hook: 0,
        priority: 0,
        devices: vec!["lan0".into(), "wan0".into()],
        handle: 1,
    }]);
    let mut recreated = old_flow.clone();
    recreated.flowtables.as_mut().unwrap()[0].handle = 99;
    assert!(recreated.compatible_with(&old_flow));
    recreated.flowtables.as_mut().unwrap()[0].flags = 1;
    assert!(!recreated.compatible_with(&old_flow));
    recreated.flowtables.as_mut().unwrap()[0].flags = 0;
    recreated.flowtables.as_mut().unwrap()[0]
        .devices
        .push("foreign0".into());
    assert!(!recreated.compatible_with(&old_flow));

    assert_eq!(initial, capture(&input).unwrap());
    let own_ast = serde_json::to_vec(&m.expected_nft_ast().unwrap()).unwrap();
    let own_digest = xkeenwrt_recovery::nft_semantic_digest(&own_ast).unwrap();
    input.nft = &own_ast;
    let own = NetworkEvidence::capture_fixed(
        &input,
        OwnedExpectation {
            manifest: &m,
            scope_manifest: None,
            nft: NftExpectation::Digest(&own_digest),
            routing: RoutingExpectation::Absent,
        },
    )
    .unwrap();
    assert_eq!(initial, own);
    assert!(
        NetworkEvidence::capture_fixed(
            &input,
            OwnedExpectation {
                manifest: &m,
                scope_manifest: None,
                nft: NftExpectation::Digest(&"0".repeat(64)),
                routing: RoutingExpectation::Absent
            }
        )
        .is_err()
    );
    input.nft = br#"{"nftables":[]}"#;
    input.routes4 = br#"[{"type":"local","dst":"default","dev":"lo","table":100}]"#;
    let partial = NetworkEvidence::capture_fixed(
        &input,
        OwnedExpectation {
            manifest: &m,
            scope_manifest: None,
            nft: NftExpectation::Absent,
            routing: RoutingExpectation::RouteOnly,
        },
    )
    .unwrap();
    assert_eq!(initial, partial);
    assert!(capture(&input).is_err());
    input.rules4 = br#"[{"priority":10000,"table":100,"fwmark":"0x100/0x100"}]"#;
    assert!(
        NetworkEvidence::capture_fixed(
            &input,
            OwnedExpectation {
                manifest: &m,
                scope_manifest: None,
                nft: NftExpectation::Absent,
                routing: RoutingExpectation::RouteOnly
            }
        )
        .is_err()
    );
    input.rules4 = b"[]";
    input.routes4 = b"[]";
    input.rules4 = br#"[{"priority":10000,"table":100,"fwmark":"0x100/0x100"}]"#;
    let partial = NetworkEvidence::capture_fixed(
        &input,
        OwnedExpectation {
            manifest: &m,
            scope_manifest: None,
            nft: NftExpectation::Absent,
            routing: RoutingExpectation::RuleOnly,
        },
    )
    .unwrap();
    assert_eq!(initial, partial);
    assert!(capture(&input).is_err());
    input.rules4 = br#"[{"priority":10000,"table":100,"fwmark":"0x100/0x100"},{"priority":10000,"table":100,"fwmark":"0x100/0x100"}]"#;
    assert!(
        NetworkEvidence::capture_fixed(
            &input,
            OwnedExpectation {
                manifest: &m,
                scope_manifest: None,
                nft: NftExpectation::Absent,
                routing: RoutingExpectation::RuleOnly
            }
        )
        .is_err()
    );
    input.rules4 = b"[]";
    input.dnsconfig = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1","192.0.2.1#5053"]}}}"#;
    assert!(capture(&input).is_err());
    input.dnsconfig = dns;
    input.dnsconfig = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1","/corp.example/192.0.2.54"]}}}"#;
    assert_ne!(initial, capture(&input).unwrap());
    input.dnsconfig = dns;
    input.nft = br#"{"nftables":[{"table":{"family":"inet","name":"foreign","handle":7}}]}"#;
    let foreign = capture(&input).unwrap();
    assert_ne!(initial, foreign);
    input.nft = br#"{"nftables":[{"table":{"family":"inet","name":"foreign","handle":8}}]}"#;
    assert_eq!(foreign, capture(&input).unwrap());
    input.nft = br#"{"nftables":[{"table":{"family":"inet","name":"foreign","handle":8,"comment":"changed"}}]}"#;
    assert_ne!(foreign, capture(&input).unwrap());
    input.nft = br#"{"nftables":[{"table":{"family":"inet","name":"xkeenwrt"}}]}"#;
    assert!(capture(&input).is_err());
    input.nft = br#"{"nftables":[]}"#;
    input.leases = b"0 02:00:00:00:00:04 192.0.2.2 client *\n0 02:00:00:00:00:03 192.0.2.3 admin *\n";
    assert!(capture(&input).is_err());
}

#[test]
fn profile_commit_crash_windows_keep_the_exact_decision_through_cleanup_and_retirement() {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        sync::{Arc, Mutex},
    };
    use xkeen_ui::configuration::{Activation, ActivationError, ConfigStore, ManualCore, Validator};
    struct Capture(Arc<Mutex<String>>);
    impl Validator for Capture {
        fn validate(&self, c: &str) -> Result<(), ActivationError> {
            *self.0.lock().unwrap() = c.into();
            Ok(())
        }
    }
    #[derive(Default)]
    struct Core(Vec<String>);
    impl ManualCore for Core {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(false)
        }
        fn replace(&mut self, c: Option<&str>) -> Result<(), ActivationError> {
            self.0.push(c.unwrap_or("stopped").into());
            Ok(())
        }
    }
    let private = |path: &std::path::Path, bytes: &[u8]| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    };
    for case in ["confirmed-disable", "confirmed-boot", "pending-boot", "confirmed-retired"] {
        let root = std::env::temp_dir().join(format!("profile-commit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = ConfigStore::new(root.join("profiles")).unwrap();
        let first = store.save("home", "mode: rule\n", None).unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let mut activation = Activation::new(store, Capture(captured.clone()), "synthetic-secret".into());
        let mut core = Core::default();
        let candidate = activation.validate("home", &first.revision).unwrap();
        activation
            .apply(
                &root,
                &mut core,
                "home",
                &first.revision,
                &candidate.candidate_id,
                "first",
            )
            .unwrap();
        let store = ConfigStore::new(root.join("profiles")).unwrap();
        let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
        let candidate = activation.validate("home", &second.revision).unwrap();
        let mut network = recovery_fixture();
        network.profile_id = "home".into();
        network.revision = second.revision.clone();
        network.idempotency_key = "network-apply".into();
        let mut manual: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("transaction.json")).unwrap()).unwrap();
        // Preserve the legacy crash-journal contract explicitly. New payload
        // corruption/partial publication is covered by the storage seam tests.
        let digest = manual["current"]["payload"]["digest"].as_str().unwrap();
        let config = std::fs::read_to_string(root.join("payloads").join(digest).join("config.yaml")).unwrap();
        manual["version"] = serde_json::json!(1);
        manual["current"].as_object_mut().unwrap().remove("payload");
        manual["current"].as_object_mut().unwrap().remove("provider_metadata");
        manual["current"]["config"] = serde_json::json!(config);
        let mut pending = manual["current"].clone();
        pending["tx"]["id"] = serde_json::json!(network.tx_id);
        pending["tx"]["revision"] = serde_json::json!(second.revision);
        pending["candidate_id"] = serde_json::json!(candidate.candidate_id);
        pending["key"] = serde_json::json!(network.idempotency_key);
        pending["config"] = serde_json::json!(captured.lock().unwrap().clone());
        pending["network_tx_id"] = serde_json::json!(network.tx_id);
        manual["pending"] = pending;
        if case != "pending-boot" {
            network.applied = true;
            network.state = xkeenwrt_recovery::State::Confirmed;
            network.profile_acceptance = Some(xkeenwrt_recovery::ProfileAcceptance {
                candidate_id: candidate.candidate_id,
            });
        }
        if case == "confirmed-disable" {
            network.finish_disable();
        } else if case.ends_with("boot") {
            network.finish_boot_cleanup("00000000-0000-4000-8000-000000000099");
        }
        assert_ne!(
            network.decision(&network.boot_id, 1001, false),
            xkeenwrt_recovery::Decision::Invalid
        );
        if case == "confirmed-retired" {
            std::fs::create_dir(root.join("network-history")).unwrap();
            std::fs::set_permissions(root.join("network-history"), std::fs::Permissions::from_mode(0o700)).unwrap();
            private(
                &root.join("network-history").join(format!("{}.json", network.tx_id)),
                &serde_json::to_vec(&network).unwrap(),
            );
            network.tx_id = "00000000-0000-4000-8000-000000000098".into();
            network.profile_acceptance = None;
        }
        private(&root.join("recovery.json"), &serde_json::to_vec(&network).unwrap());
        private(&root.join("transaction.json"), &serde_json::to_vec(&manual).unwrap());
        activation.recover(&root, &mut core).unwrap();
        activation.recover(&root, &mut core).unwrap();
        assert!(core.0.is_empty(), "settlement must not start/replace core");
        activation.start(&root, &mut core).unwrap();
        let config = profile_policy::parse_document(core.0.last().unwrap()).unwrap();
        assert_eq!(
            config["mode"],
            if case == "pending-boot" { "rule" } else { "direct" },
            "{case}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unsafe_replacement_rollback_has_a_terminal_direct_receipt_without_erasing_history() {
    use xkeen_ui::runtime::networking::status::{NetworkState, OperationalEvidence, classify};
    let mut j = recovery_fixture();
    let mut previous = j.current.clone();
    previous.generation = 1;
    previous.route_table = 101;
    previous.priority = 10001;
    previous.mark = 0x200;
    previous.mask = 0x200;
    j.previous_good = Some(previous);
    j.previous_core = j.current_core.clone();
    let explicit = profile_policy::ExplicitOverlay {
        lan_ifname: "br-test".into(),
        lan_ipv4: "192.0.2.1".parse().unwrap(),
        lan_scope: "192.0.2.0/24".into(),
        port: 7890,
        owner_id: j.current.owner_id.clone(),
        generation: 1,
    };
    j.baseline_core.overlay = profile_policy::ManagedOverlay::Composite(profile_policy::InputsOverlay {
        explicit: Some(explicit),
        gateway: None,
    });
    j.baseline_core.running = true;
    j.finish_rollback_direct(&j.boot_id.clone());
    assert_eq!(
        j.decision(&j.boot_id, 2000, false),
        xkeenwrt_recovery::Decision::Settled
    );
    assert!(j.rollback_direct_complete());
    assert!(j.previous_good.is_some());
    assert!(j.baseline_core.overlay.explicit().is_some());
    assert!(xkeenwrt_recovery::active::active_manifest(&j).is_none());
    let proof = OperationalEvidence {
        nft_semantic_sha256: "",
        route_and_rule_match: false,
        core_healthy: true,
        fence_absent: false,
        network_absent: true,
    };
    assert_eq!(
        classify(&j, &j.boot_id, 2000, Some(&proof), false),
        NetworkState::Inactive
    );
}

#[test]
fn selected_inputs_commit_ack_survives_disable_and_does_not_replay_over_new_user_choices() {
    use xkeenwrt_recovery::input_state::{Selection, settled_selection};
    let mut j = recovery_fixture();
    j.applied = true;
    j.state = xkeenwrt_recovery::State::Confirmed;
    j.profile_acceptance = Some(xkeenwrt_recovery::ProfileAcceptance {
        candidate_id: "manual-source".into(),
    });
    let explicit = profile_policy::ExplicitOverlay {
        lan_ifname: "br-test".into(),
        lan_ipv4: "192.0.2.1".parse().unwrap(),
        lan_scope: "192.0.2.0/24".into(),
        port: 7890,
        owner_id: j.current.owner_id.clone(),
        generation: 2,
    };
    j.current_core.overlay = profile_policy::ManagedOverlay::Composite(profile_policy::InputsOverlay {
        explicit: Some(explicit.clone()),
        gateway: j.current_core.overlay.gateway().cloned(),
    });
    let accepted = settled_selection(&Selection::default(), &j).unwrap();
    assert_eq!(accepted.explicit, Some(explicit));
    assert!(accepted.gateway);
    assert_eq!(accepted.network_commit.as_deref(), Some(j.tx_id.as_str()));
    // Disable persists its intent with the same ack before asking rescue.
    let mut disabled = accepted.clone();
    disabled.gateway = false;
    j.finish_disable();
    assert!(settled_selection(&disabled, &j).is_none());
    // An explicit owner choice after that commit retains the same ack, too.
    disabled.explicit = None;
    assert!(settled_selection(&disabled, &j).is_none());
    // A torn write before acknowledgement is resolved from the typed decision,
    // including when boot cleanup already stopped all runtime inputs.
    j.finish_boot_cleanup("00000000-0000-4000-8000-000000000099");
    assert_eq!(settled_selection(&Selection::default(), &j), Some(accepted));
    j.profile_acceptance = None;
    assert!(settled_selection(&Selection::default(), &j).is_none());
}

#[test]
fn failed_remote_probe_blocks_confirm_and_leaves_the_transaction_pending() {
    use xkeen_ui::runtime::networking::transaction::{Coordinator, Driver, Error, Pending, Request};
    struct Fake {
        pending: Option<Pending>,
        applied: bool,
        confirmed: bool,
        remote: Option<Error>,
        remote_calls: usize,
    }
    impl Driver for Fake {
        type Guard = ();
        fn idle_ready(&mut self, _: &Request, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn lock(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn now_ms(&mut self) -> Result<u64, Error> {
            Ok(1_001)
        }
        fn boot_id(&mut self) -> Result<String, Error> {
            Ok("00000000-0000-4000-8000-000000000006".into())
        }
        fn make_token(&mut self, tx: &str, request: &Request) -> Result<String, Error> {
            Ok(xkeen_ui::runtime::networking::transaction::confirmation_token(
                &[7; 32],
                tx,
                request.generation,
                &request.plan_id,
                &request.idempotency_key,
            ))
        }
        fn load_pending(&mut self) -> Result<Option<Pending>, Error> {
            Ok(self.pending.clone())
        }
        fn prepare_pending(&mut self, p: &Pending) -> Result<(), Error> {
            self.pending = Some(p.clone());
            Ok(())
        }
        fn await_ready(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn ready(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn revalidate(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn not_revoked(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn apply(&mut self, _: &Pending) -> Result<(), Error> {
            Ok(())
        }
        fn mark_applied(&mut self, _: &Pending) -> Result<(), Error> {
            self.applied = true;
            Ok(())
        }
        fn is_applied(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(self.applied)
        }
        fn verify_active(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn health(&mut self, _: &Pending) -> Result<bool, Error> {
            Ok(true)
        }
        fn remote_check(&mut self, _: &Pending) -> Result<(), Error> {
            self.remote_calls += 1;
            match self.remote.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        fn confirm(&mut self, _: &Pending) -> Result<(), Error> {
            self.confirmed = true;
            Ok(())
        }
    }
    let request = Request {
        plan_id: "00000000-0000-4000-8000-000000000003".into(),
        candidate_id: "candidate-1".into(),
        idempotency_key: "synthetic-idempotency".into(),
        generation: 2,
    };
    for (failure, expected) in [
        (Some(Error::RemoteDns), Err(Error::RemoteDns)),
        (Some(Error::RemoteEgress), Err(Error::RemoteEgress)),
        (None, Ok(())),
    ] {
        let succeeds = failure.is_none();
        let mut c = Coordinator::new(Fake {
            pending: None,
            applied: false,
            confirmed: false,
            remote: failure,
            remote_calls: 0,
        });
        let pending = c.apply(request.clone()).unwrap();
        assert_eq!(c.confirm(&pending.transaction_id, &pending.confirm_token), expected);
        assert_eq!(c.driver().remote_calls, 1, "probes run once, under the confirm checks");
        assert_eq!(c.driver().confirmed, succeeds);
        // A refused remote confirm keeps the journal Pending: rescue revokes it.
        assert_eq!(c.driver().pending.as_ref(), Some(&pending));
    }
}
