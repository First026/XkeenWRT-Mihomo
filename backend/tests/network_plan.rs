#[path = "../src/network/mod.rs"]
mod network;
use network::*;

#[test]
fn missing_tproxy_capability_cannot_produce_a_plan() {
    let inventory = Inventory::default();
    let policy = TrafficPolicy::default();
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Unsupported));
}

#[test]
fn occupied_table_or_overlapping_mark_is_a_conflict() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        tproxy_available: true,
        socket_available: true,
        occupied_tables: vec![52],
        occupied_marks: vec![(0x80000, 0xff0000)],
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 52,
        mark: 0x10000,
        mark_mask: 0x10000,
        ..Default::default()
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Conflict));
}

#[test]
fn foreign_mark_mask_alone_conflicts() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        occupied_marks: vec![(0x80000, 0xff0000)],
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 0x10000,
        mark_mask: 0x10000,
        ..Default::default()
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Conflict));
}

#[test]
fn zero_or_out_of_mask_mark_is_rejected() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 0x200,
        mark_mask: 0x100,
        ..Default::default()
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::InvalidPolicy));
}

#[test]
fn apparently_free_resources_do_not_enable_unverified_capture() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 0x100,
        mark_mask: 0x100,
        ..Default::default()
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::InvalidPolicy));
}

#[test]
fn valid_pilot_yields_only_owned_plan_with_exact_scope() {
    let mut inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        local_ipv4: vec!["192.0.2.0/24".into()],
        local_ipv6: vec!["2001:db8::/64".into()],
        lan_ifname: Some("br-test".into()),
        lan_address: Some("192.0.2.1".parse().unwrap()),
        lan_cidrs: vec!["192.0.2.0/24".into()],
        ..Default::default()
    };
    let mut policy = TrafficPolicy {
        table: 100,
        mark: 0x100,
        mark_mask: 0x100,
        priority: 10000,
        lan_ifname: "br-test".into(),
        lan_scope: None,
        capture_version: None,
        selected_mac: "02:00:00:00:00:02".into(),
        lan_address: "192.0.2.1".parse().unwrap(),
        client_ipv4: "192.0.2.2".parse().unwrap(),
        management_ipv4: "192.0.2.3".parse().unwrap(),
        local_ipv4: vec!["192.0.2.0/24".into()],
        selected_ipv6: vec!["2001:db8::2/128".into()],
        management_ipv6: Some(vec!["2001:db8::3".parse().unwrap()]),
        management_channel: None,
        local_ipv6: vec!["2001:db8::/64".into()],
        candidate_id: "pilot-1".into(),
        previous_table: None,
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 2,
        failure_policy: Some(FailurePolicy::DirectOnFailure),
        dns: Some(network::dns::DnsInventory {
            dnsmasq_instances: 1,
            incompatible_manager: false,
            local_names: vec!["+.lan".into()],
            upstreams: vec!["127.0.0.1#5053".into()],
            split_upstreams: vec![],
            verified_loopback_chain_sha256: Some("a".repeat(64)),
            bootstrap: vec!["1.1.1.2".parse().unwrap()],
        }),
    };
    let plan = Network::plan(&inventory, &policy).unwrap();
    assert_eq!(plan.manifest().table_name, "xkeenwrt");
    assert_eq!(plan.failure_policy(), FailurePolicy::DirectOnFailure);
    assert_eq!(plan.dns().upstreams, ["127.0.0.1#5053"]);
    assert!(plan.nft_batch().contains("192.0.2.2"));
    assert!(plan.nft_batch().contains("1053"));
    let commands: serde_json::Value = serde_json::from_str(plan.nft_batch()).unwrap();
    let rules = commands["nftables"].as_array().unwrap();
    assert!(rules.iter().any(|item| item["add"]["rule"]["chain"] == "dns"
        && item.to_string().contains("02:00:00:00:00:02")
        && item.to_string().contains("192.0.2.2")));
    assert!(!plan.nft_batch().contains("\"hook\":\"output\""));
    assert_eq!(plan.source_ipv4(), policy.client_ipv4);
    struct RejectCheck {
        calls: Vec<&'static str>,
    }
    impl network::executor::NetworkIo for RejectCheck {
        fn check_nft(&mut self, _: &str) -> bool {
            self.calls.push("check");
            false
        }
        fn add_route(&mut self, _: &RoutingPlan) -> bool {
            self.calls.push("route");
            true
        }
        fn add_rule(&mut self, _: &RoutingPlan) -> bool {
            self.calls.push("rule");
            true
        }
        fn install_nft(&mut self, _: &str) -> bool {
            self.calls.push("install");
            true
        }
    }
    let mut io = RejectCheck { calls: vec![] };
    let error = network::executor::apply(&plan, &mut io).unwrap_err();
    assert_eq!(error.stage, network::executor::Stage::CheckNft);
    assert!(!error.may_have_mutated);
    assert_eq!(io.calls, ["check"]);
    inventory.xkeenwrt_table_exists = true;
    inventory.existing_table = Some(ExistingTable {
        owner_id: policy.owner_id.clone(),
        generation: 1,
        semantic_sha256: "a".repeat(64),
    });
    policy.previous_table = Some((1, "a".repeat(64)));
    let next = Network::plan(&inventory, &policy).unwrap();
    let commands: serde_json::Value = serde_json::from_str(next.nft_batch()).unwrap();
    assert_eq!(commands["nftables"][0]["delete"]["table"]["name"], "xkeenwrt");
    policy.previous_table = Some((1, "b".repeat(64)));
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Conflict));
    inventory.xkeenwrt_table_exists = false;
    inventory.existing_table = None;
    policy.previous_table = None;
    policy.selected_ipv6.clear();
    let privacy = Network::plan(&inventory, &policy).unwrap();
    assert!(privacy.nft_batch().contains("02:00:00:00:00:02"));
    assert!(privacy.nft_batch().contains("\"nfproto\""));
    inventory.management_macs = Some(vec!["02:00:00:00:00:02".into()]);
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Unsupported));
}

#[test]
fn ipv6_selected_client_must_not_include_management_address() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        local_ipv4: vec!["192.0.2.0/24".into()],
        local_ipv6: vec!["2001:db8::/64".into()],
        lan_ifname: Some("br-test".into()),
        lan_address: Some("192.0.2.1".parse().unwrap()),
        lan_cidrs: vec!["192.0.2.0/24".into()],
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 0x100,
        mark_mask: 0x100,
        priority: 10000,
        lan_ifname: "br-test".into(),
        lan_scope: None,
        capture_version: None,
        selected_mac: "02:00:00:00:00:02".into(),
        lan_address: "192.0.2.1".parse().unwrap(),
        client_ipv4: "192.0.2.2".parse().unwrap(),
        management_ipv4: "192.0.2.3".parse().unwrap(),
        local_ipv4: vec!["192.0.2.0/24".into()],
        selected_ipv6: vec!["2001:db8::2/128".into()],
        local_ipv6: vec!["2001:db8::/64".into()],
        management_ipv6: Some(vec!["2001:db8::2".parse().unwrap()]),
        management_channel: None,
        candidate_id: "pilot".into(),
        previous_table: None,
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 2,
        failure_policy: Some(FailurePolicy::DirectOnFailure),
        dns: Some(network::dns::DnsInventory {
            dnsmasq_instances: 1,
            incompatible_manager: false,
            local_names: vec!["+.lan".into()],
            upstreams: vec!["127.0.0.1#5053".into()],
            split_upstreams: vec![],
            verified_loopback_chain_sha256: Some("a".repeat(64)),
            bootstrap: vec!["1.1.1.2".parse().unwrap()],
        }),
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::Conflict));
}

#[test]
fn broad_default_route_is_not_treated_as_a_local_exclusion() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        client_mac: Some("02:00:00:00:00:02".into()),
        management_macs: Some(vec!["02:00:00:00:00:03".into()]),
        tproxy_available: true,
        socket_available: true,
        local_ipv4: vec!["0.0.0.0/0".into()],
        local_ipv6: vec!["2001:db8::/64".into()],
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 0x100,
        mark_mask: 0x100,
        priority: 10000,
        lan_ifname: "br-test".into(),
        lan_scope: None,
        capture_version: None,
        selected_mac: "02:00:00:00:00:02".into(),
        lan_address: "192.0.2.1".parse().unwrap(),
        client_ipv4: "192.0.2.2".parse().unwrap(),
        management_ipv4: "192.0.2.3".parse().unwrap(),
        local_ipv4: vec!["0.0.0.0/0".into()],
        selected_ipv6: vec!["2001:db8::2/128".into()],
        management_ipv6: Some(vec![]),
        management_channel: None,
        local_ipv6: vec!["2001:db8::/64".into()],
        candidate_id: "pilot".into(),
        previous_table: None,
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 2,
        failure_policy: Some(FailurePolicy::DirectOnFailure),
        dns: None,
    };
    assert_eq!(Network::plan(&inventory, &policy), Err(PlanError::InvalidPolicy));
}

#[test]
fn allocation_skips_occupied_tables_masks_and_priorities() {
    let inventory = Inventory {
        complete: true,
        occupied_tables: vec![100, 52],
        occupied_marks: vec![(1, 1), (0x80000, 0xff0000), (0x50000000, 0x50000000)],
        occupied_priorities: vec![10000],
        ..Default::default()
    };
    let allocation = inventory.allocate().unwrap();
    assert_eq!(allocation.table, 101);
    assert_eq!(allocation.mark, 2);
    assert_eq!(allocation.mark_mask, 2);
    assert_eq!(allocation.priority, 10001);
}

#[test]
fn incomplete_inventory_cannot_allocate_resources() {
    assert_eq!(Inventory::default().allocate(), Err(PlanError::Unsupported));
}

#[test]
fn whole_lan_plan_uses_observed_subnet_and_includes_administrator_in_internet_routing() {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        tproxy_available: true,
        socket_available: true,
        lan_ifname: Some("br-lan".into()),
        lan_address: Some("192.0.2.1".parse().unwrap()),
        lan_cidrs: vec!["192.0.2.1/24".into()],
        local_ipv4: vec!["192.0.2.0/24".into()],
        local_ipv6: vec!["fe80::/10".into()],
        client_mac: Some(String::new()),
        management_macs: Some(vec![]),
        ..Default::default()
    };
    let mut policy = TrafficPolicy {
        table: 100,
        mark: 1,
        mark_mask: 1,
        priority: 10000,
        lan_ifname: "br-lan".into(),
        lan_address: "192.0.2.1".parse().unwrap(),
        lan_scope: Some("192.0.2.0/24".into()),
        client_ipv4: "192.0.2.3".parse().unwrap(),
        management_ipv4: "192.0.2.3".parse().unwrap(),
        management_ipv6: Some(vec![]),
        local_ipv4: inventory.local_ipv4.clone(),
        local_ipv6: inventory.local_ipv6.clone(),
        candidate_id: "synthetic-candidate".into(),
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 1,
        failure_policy: Some(network::FailurePolicy::DirectOnFailure),
        dns: Some(network::dns::DnsInventory {
            dnsmasq_instances: 1,
            incompatible_manager: false,
            local_names: vec!["+.lan".into()],
            upstreams: vec!["1.1.1.1#53".into()],
            split_upstreams: vec![],
            verified_loopback_chain_sha256: None,
            bootstrap: vec!["1.1.1.1".parse().unwrap()],
        }),
        ..Default::default()
    };
    let plan = Network::plan(&inventory, &policy).expect("trusted whole LAN should be supported");
    assert_eq!(plan.manifest().lan_scope.as_deref(), Some("192.0.2.0/24"));
    policy.lan_scope = Some("192.0.0.0/16".into());
    assert!(
        Network::plan(&inventory, &policy).is_err(),
        "HTTP policy cannot expand trusted LAN scope"
    );
}

/// A working router's whole-LAN shape; `management` is the authenticated peer.
fn whole_lan(management: &str, channel: Option<xkeenwrt_recovery::ManagementChannel>) -> (Inventory, TrafficPolicy) {
    let inventory = Inventory {
        complete: true,
        hook_topology_verified: true,
        ethernet_like: true,
        tproxy_available: true,
        socket_available: true,
        lan_ifname: Some("br-lan".into()),
        lan_address: Some("192.0.2.1".parse().unwrap()),
        lan_cidrs: vec!["192.0.2.1/24".into()],
        local_ipv4: vec!["192.0.2.0/24".into()],
        local_ipv6: vec!["fe80::/10".into()],
        client_mac: Some(String::new()),
        management_macs: Some(vec![]),
        ..Default::default()
    };
    let policy = TrafficPolicy {
        table: 100,
        mark: 1,
        mark_mask: 1,
        priority: 10000,
        lan_ifname: "br-lan".into(),
        lan_address: "192.0.2.1".parse().unwrap(),
        lan_scope: Some("192.0.2.0/24".into()),
        client_ipv4: management.parse().unwrap(),
        management_ipv4: management.parse().unwrap(),
        management_ipv6: Some(vec![]),
        management_channel: channel,
        local_ipv4: inventory.local_ipv4.clone(),
        local_ipv6: inventory.local_ipv6.clone(),
        candidate_id: "synthetic-candidate".into(),
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        generation: 1,
        failure_policy: Some(network::FailurePolicy::DirectOnFailure),
        dns: Some(network::dns::DnsInventory {
            dnsmasq_instances: 1,
            incompatible_manager: false,
            local_names: vec!["+.lan".into()],
            upstreams: vec!["1.1.1.1#53".into()],
            split_upstreams: vec![],
            verified_loopback_chain_sha256: None,
            bootstrap: vec!["1.1.1.1".parse().unwrap()],
        }),
        ..Default::default()
    };
    (inventory, policy)
}

#[test]
fn tailscale_whole_lan_plan_records_the_channel_and_captures_like_a_lan_start() {
    use xkeenwrt_recovery::ManagementChannel::Tailscale;
    let (inventory, policy) = whole_lan("100.64.20.2", Some(Tailscale));
    let plan = Network::plan(&inventory, &policy).expect("whole LAN started over Tailscale");
    assert_eq!(plan.manifest().management_channel, Some(Tailscale));
    assert_eq!(
        plan.manifest().management_ipv4,
        "100.64.20.2".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let (inventory, policy) = whole_lan("192.0.2.3", None);
    let lan = Network::plan(&inventory, &policy).unwrap();
    assert_eq!(lan.manifest().management_channel, None);
    assert_eq!(
        lan.nft_batch().replace("\"192.0.2.3\"", "\"100.64.20.2\""),
        plan.nft_batch()
    );
}

#[test]
fn tailscale_plan_rejects_pilot_block_policy_lan_peer_and_missing_channel() {
    use xkeenwrt_recovery::ManagementChannel::Tailscale;
    let (inventory, mut policy) = whole_lan("100.64.20.2", Some(Tailscale));
    policy.failure_policy = Some(network::FailurePolicy::BlockSelectedOnFailure);
    assert!(Network::plan(&inventory, &policy).is_err(), "block policy");
    let (inventory, mut policy) = whole_lan("100.64.20.2", Some(Tailscale));
    policy.lan_scope = None;
    assert!(Network::plan(&inventory, &policy).is_err(), "pilot client");
    let (inventory, policy) = whole_lan("192.0.2.3", Some(Tailscale));
    assert!(
        Network::plan(&inventory, &policy).is_err(),
        "LAN peer with Tailscale channel"
    );
    let (inventory, policy) = whole_lan("100.64.20.2", None);
    assert!(
        Network::plan(&inventory, &policy).is_err(),
        "Tailscale peer without channel"
    );
}
