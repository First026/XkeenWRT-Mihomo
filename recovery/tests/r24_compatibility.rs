use serde_json::json;
use xkeenwrt_recovery::topology::topology_conflict;

#[test]
fn declaration_alone_is_not_a_proven_flow_interception_conflict() {
    let nft = json!({"nftables":[
        {"table":{"family":"inet","name":"untrusted_name"}},
        {"flowtable":{"family":"inet","table":"untrusted_name","name":"idle","hook":"ingress","prio":0,"dev":["lan0","wan0"]}}
    ]});
    let conflict = topology_conflict(&serde_json::to_vec(&nft).unwrap(), &["br-lan"]).unwrap();
    assert!(
        conflict.is_none(),
        "a declaration is not proof of a harmful LAN overlap: {conflict:?}"
    );
}

#[test]
fn unknown_syntax_warns_and_all_known_conflicts_remain_visible() {
    use xkeenwrt_recovery::topology::{Severity, compatibility_report};
    let nft = json!({"nftables":[
        {"chain":{"family":"inet","table":"arbitrary","name":"early","type":"filter","hook":"prerouting","prio":-100,"policy":"accept"}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"new_unknown_expression":{"value":42}}]}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"tproxy":{"port":9999}}]}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"redirect":{"port":9998}}]}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"guest"}},{"drop":null}]}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"tproxy":{"port":9997}}]}},
        {"rule":{"family":"inet","table":"arbitrary","chain":"early","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"set":[]}}},{"dnat":{"addr":"203.0.113.2"}}]}}
    ]});
    let report =
        compatibility_report(&serde_json::to_vec(&nft).unwrap(), &["br-lan"], &[]).unwrap();
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count(),
        1
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Blocker)
            .count(),
        2
    );
    assert!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Blocker)
            .all(|f| f.detail.priority == Some(-100) && f.detail.rule_id.starts_with("sha256-"))
    );
}

#[test]
fn hardware_flags_omitted_by_nft_json_still_block_transition() {
    use xkeenwrt_recovery::flow_offload::{FlowTable, verify_tables};
    let nft = json!({"nftables":[{"flowtable":{"family":"inet","table":"foreign","name":"ft","hook":"ingress","prio":0,"dev":["eth0","eth1"]}}]});
    let mut table = FlowTable {
        family: 1,
        table: "foreign".into(),
        name: "ft".into(),
        flags: 0,
        hook: 0,
        priority: 0,
        devices: vec!["eth0".into(), "eth1".into()],
        handle: 12,
    };
    assert!(verify_tables(&serde_json::to_vec(&nft).unwrap(), &[table.clone()]).is_ok());
    table.flags = 1;
    assert_eq!(
        verify_tables(&serde_json::to_vec(&nft).unwrap(), &[table])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
}
#[test]
fn declared_late_nat_still_runs_at_the_kernel_dnat_hook_before_capture() {
    let nft = json!({"nftables":[{"chain":{"family":"inet","table":"foreign","name":"nat","type":"nat","hook":"prerouting","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"foreign","chain":"nat","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"redirect":{"port":8080}}]}}]});
    assert!(
        topology_conflict(&serde_json::to_vec(&nft).unwrap(), &["br-lan"])
            .unwrap()
            .is_some()
    );
}
#[test]
fn a_proven_disjoint_source_prefix_does_not_invent_a_lan_conflict() {
    use xkeenwrt_recovery::topology::compatibility_report;
    let nft = json!({"nftables":[{"chain":{"family":"inet","table":"foreign","name":"early","type":"filter","hook":"prerouting","prio":-100,"policy":"accept"}},{"rule":{"family":"inet","table":"foreign","chain":"early","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"203.0.113.0","len":24}}}},{"tproxy":{"port":9999}}]}}]});
    let addresses=serde_json::to_vec(&json!([{"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24},{"family":"inet6","local":"fd00::1","prefixlen":64}]}])).unwrap();
    assert!(
        !compatibility_report(&serde_json::to_vec(&nft).unwrap(), &["br-lan"], &addresses)
            .unwrap()
            .blocked()
    );
}
#[test]
fn complements_are_intersected_with_the_complete_captured_protocol_and_ingress_set() {
    for (left, right, blocked) in [
        (json!({"meta":{"key":"iifname"}}), json!("br-lan"), false),
        (json!({"meta":{"key":"iifname"}}), json!("guest"), true),
        (json!({"meta":{"key":"nfproto"}}), json!("ipv4"), false),
        (json!({"meta":{"key":"nfproto"}}), json!("ipv6"), true),
        (
            json!({"meta":{"key":"l4proto"}}),
            json!({"set":["tcp","udp"]}),
            false,
        ),
        (json!({"meta":{"key":"l4proto"}}), json!("tcp"), true),
    ] {
        let nft = json!({"nftables":[{"chain":{"family":"inet","table":"foreign","name":"early","hook":"prerouting","type":"filter","prio":-100,"policy":"accept"}},{"rule":{"family":"inet","table":"foreign","chain":"early","expr":[{"match":{"op":"!=","left":left,"right":right}},{"drop":null}]}}]});
        assert_eq!(
            topology_conflict(&serde_json::to_vec(&nft).unwrap(), &["br-lan"])
                .unwrap()
                .is_some(),
            blocked
        );
    }
}
