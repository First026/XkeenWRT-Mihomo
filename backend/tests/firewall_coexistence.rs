use serde_json::{Value, json};
use xkeen_ui::runtime::networking::collector::hook_topology_safe;

fn helpers() -> Value {
    json!({"nftables":[
        {"chain":{"family":"inet","table":"fw4","name":"prerouting","type":"filter","hook":"prerouting","prio":0,"policy":"accept"}},
        {"chain":{"family":"inet","table":"fw4","name":"helper_lan"}},
        {"chain":{"family":"inet","table":"fw4","name":"helper_zmvpn"}},
        {"rule":{"family":"inet","table":"fw4","chain":"prerouting","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":{"set":["br-lan","tailscale0"]}}},
            {"jump":{"target":"helper_lan"}}
        ]}},
        {"rule":{"family":"inet","table":"fw4","chain":"prerouting","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":{"set":["zm_vpn","zmv_test"]}}},
            {"jump":{"target":"helper_zmvpn"}}
        ]}}
    ]})
}

#[test]
fn fw4_empty_helpers_accept_and_unknown_selectors_do_not_invent_conflicts() {
    let fixture = helpers();
    assert!(
        hook_topology_safe(&serde_json::to_vec(&fixture).unwrap()).unwrap(),
        "Start must admit both fw4 empty helper jumps with inline interface sets"
    );
    let mut nonempty = fixture.clone();
    nonempty["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"rule":{"family":"inet","table":"fw4","chain":"helper_lan","expr":[{"accept":null}]}}));
    assert!(
        hook_topology_safe(&serde_json::to_vec(&nonempty).unwrap()).unwrap(),
        "accept has no harmful interception effect"
    );
    for rhs in [
        json!({"set":[]}),
        json!({"set":["br-lan",42]}),
        json!({"set":["br-lan*","tailscale0"]}),
        json!("@interfaces"),
        json!({"set":[{"prefix":{"addr":"lan","len":3}}]}),
    ] {
        let mut bad = fixture.clone();
        bad["nftables"][3]["rule"]["expr"][0]["match"]["right"] = rhs;
        assert!(
            hook_topology_safe(&serde_json::to_vec(&bad).unwrap()).unwrap(),
            "unknown or empty selector is not a proven conflict"
        );
    }
}

#[test]
fn self_bitwise_mark_updates_reserve_only_touched_bits() {
    use xkeenwrt_recovery::evidence::inventory::occupied_nft;
    let meta = json!({"meta":{"key":"mark"}});
    let ct = json!({"ct":{"key":"mark"}});
    let input = json!({"nftables":[
        {"rule":{"expr":[{"mangle":{"key":meta,"value":{"|":[meta,0x50000000u32]}}}]}},
        {"rule":{"expr":[{"mangle":{"key":ct,"value":{"|":[ct,0x40000000u32]}}}]}},
        {"rule":{"expr":[{"match":{"op":"!=","left":{"&":[ct,0x40000000u32]},"right":0}}]}},
        {"rule":{"expr":[{"mangle":{"key":meta,"value":{"&":[meta,0xdfffffffu32]}}}]}}
    ]});
    assert_eq!(
        occupied_nft(&serde_json::to_vec(&input).unwrap())
            .unwrap()
            .used_mark_mask,
        0x70000000
    );
    for (value, expected) in [(json!(1), 1), (ct, 0), (json!({"|":[meta, {"meta":{"key":"priority"}}]}), 0)] {
        let bad = json!({"nftables":[{"rule":{"expr":[{"mangle":{"key":meta,"value":value}}]}}]});
        assert_eq!(
            occupied_nft(&serde_json::to_vec(&bad).unwrap()).unwrap().used_mark_mask,
            expected
        );
    }
}

#[test]
fn stgws_and_zapret_rules_coexist_only_with_proven_scoped_traversal() {
    use xkeen_ui::runtime::networking::collector::hook_topology_for_ingress;
    let input = include_bytes!("fixtures/firewall/coexistence.json");
    assert!(hook_topology_for_ingress(input, &["br-lan"]).unwrap());
    let mut fixture: Value = serde_json::from_slice(input).unwrap();
    let rules = fixture["nftables"].as_array_mut().unwrap();
    rules.push(
        json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"tproxy":{"port":9999}}]}}),
    );
    assert!(!hook_topology_for_ingress(&serde_json::to_vec(&fixture).unwrap(), &["br-lan"]).unwrap());
}

#[test]
fn conflicts_identify_hook_and_table_and_do_not_trust_service_names() {
    use xkeen_ui::runtime::networking::collector::topology_conflict;
    let original: Value = serde_json::from_slice(include_bytes!("fixtures/firewall/coexistence.json")).unwrap();
    for expr in [json!({"tproxy":{"port":9999}}), json!({"drop":null})] {
        let mut changed = original.clone();
        changed["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[expr]}}));
        let failure = topology_conflict(&serde_json::to_vec(&changed).unwrap(), &["br-lan"])
            .unwrap()
            .unwrap();
        assert_eq!(failure.table, "stgws");
        assert_eq!(failure.chain, "prerouting_mark");
        assert_eq!(failure.hook, "prerouting");
    }
    let mut late = original.clone();
    late["nftables"][0]["chain"]["prio"] = json!(-89);
    late["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":0}}]}}));
    assert!(
        topology_conflict(&serde_json::to_vec(&late).unwrap(), &["br-lan"])
            .unwrap()
            .is_some()
    );
    let mut same = original.clone();
    for object in same["nftables"].as_array_mut().unwrap() {
        if let Some(body) = object.as_object_mut().unwrap().values_mut().next()
            && body["table"] == "stgws"
        {
            body["table"] = json!("renamed_service");
        }
    }
    assert!(
        topology_conflict(&serde_json::to_vec(&same).unwrap(), &["br-lan"])
            .unwrap()
            .is_none()
    );
}

#[test]
fn foreign_snapshot_ignores_counters_but_detects_rules_added_after_plan() {
    use xkeenwrt_recovery::evidence::foreign_nft_digest;
    let input = include_bytes!("fixtures/firewall/coexistence.json");
    let original = foreign_nft_digest(input).unwrap();
    let mut updated: Value = serde_json::from_slice(input).unwrap();
    for obj in updated["nftables"].as_array_mut().unwrap() {
        if let Some(r) = obj.get_mut("rule") {
            r["handle"] = json!(123);
            for x in r["expr"].as_array_mut().unwrap() {
                if x.get("counter").is_some() {
                    x["counter"] = json!({"packets":999,"bytes":50000});
                }
            }
        }
    }
    assert_eq!(
        foreign_nft_digest(&serde_json::to_vec(&updated).unwrap()).unwrap(),
        original
    );
    updated["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"counter":{"packets":0,"bytes":0}}]}}));
    assert_ne!(
        foreign_nft_digest(&serde_json::to_vec(&updated).unwrap()).unwrap(),
        original
    );
}

fn exact_r20_without(table: &str, chain: &str) -> Value {
    let mut f: Value = serde_json::from_slice(include_bytes!("fixtures/firewall/r20-exact.json")).unwrap();
    f["nftables"].as_array_mut().unwrap().retain(|o| {
        !o.get("rule")
            .is_some_and(|r| r["table"] == table && r["chain"] == chain)
    });
    f
}

#[test]
fn exact_r20_scoped_mark_and_terminal_return_are_compatible() {
    use xkeen_ui::runtime::networking::collector::topology_conflict;
    let mut f = exact_r20_without("stgws", "tgws_redirect");
    f["nftables"].as_array_mut().unwrap().retain(|o| {
        !o.get("rule")
            .is_some_and(|r| r["table"] == "zapret2" && r["chain"] == "prerouting_hook")
    });
    let conflict = topology_conflict(&serde_json::to_vec(&f).unwrap(), &["br-lan"]).unwrap();
    assert!(
        conflict.is_none(),
        "exact scoped OR+counter+return refused: {conflict:?}"
    );
}

#[test]
fn exact_r20_nat_mark_has_proven_earlier_address_scoped_source() {
    use xkeen_ui::runtime::networking::collector::topology_conflict;
    let mut f = exact_r20_without("zapret2", "prerouting_hook");
    for o in f["nftables"].as_array_mut().unwrap() {
        if let Some(r) = o.get_mut("rule") {
            if r["chain"] == "prerouting_mark" {
                r["expr"].as_array_mut().unwrap().retain(|e| e.get("return").is_none());
            }
            if r["chain"] == "tgws_redirect" {
                r["expr"].as_array_mut().unwrap().retain(|e| e.get("dnat").is_none());
            }
        }
    }
    // Remove the deliberately stripped DNAT rule, leaving only the exact mark redirect.
    f["nftables"].as_array_mut().unwrap().retain(|o| {
        !o.get("rule").is_some_and(|r| {
            r["chain"] == "tgws_redirect"
                && !r["expr"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e.get("redirect").is_some())
        })
    });
    let conflict = topology_conflict(&serde_json::to_vec(&f).unwrap(), &["br-lan"]).unwrap();
    assert!(conflict.is_none(), "exact mark-based redirect refused: {conflict:?}");
}

#[test]
fn exact_r20_icmp_time_exceeded_ct_state_in_invalid_is_compatible() {
    use xkeen_ui::runtime::networking::collector::topology_conflict;
    let mut f = exact_r20_without("stgws", "tgws_redirect");
    f["nftables"]
        .as_array_mut()
        .unwrap()
        .retain(|o| !o.get("rule").is_some_and(|r| r["chain"] == "prerouting_mark"));
    let conflict = topology_conflict(&serde_json::to_vec(&f).unwrap(), &["br-lan"]).unwrap();
    assert!(conflict.is_none(), "exact ct state in invalid refused: {conflict:?}");
}

#[test]
fn exact_topology_uses_real_local_address_inventory_and_rejects_unsafe_variants() {
    use xkeen_ui::runtime::networking::collector::topology_conflict_with_inventory;
    let original: Value = serde_json::from_slice(include_bytes!("fixtures/firewall/r20-exact.json")).unwrap();
    let addresses = serde_json::to_vec(&json!([{"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.0.2.2","prefixlen":24},{"family":"inet6","local":"fd00::2","prefixlen":64}]}])).unwrap();
    let classify =
        |f: &Value| topology_conflict_with_inventory(&serde_json::to_vec(f).unwrap(), &["br-lan"], &addresses).unwrap();
    assert!(
        classify(&original).is_none(),
        "exact real-service topology must be admitted: {:?}",
        classify(&original)
    );
    for mutation in [
        "foreign-bit-write",
        "nonlocal-dnat",
        "late-source",
        "broadened-drop",
        "foreign-tproxy",
        "source-other-ingress",
        "unknown-source",
    ] {
        let mut f = original.clone();
        let items = f["nftables"].as_array_mut().unwrap();
        match mutation {
            "foreign-bit-write" => items.push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"|":[{"meta":{"key":"mark"}},268435456]}}}]}})),
            "nonlocal-dnat" => { for r in items.iter_mut().filter_map(|o| o.get_mut("rule")) { if r["expr"].as_array().unwrap().iter().any(|e|e.get("dnat").is_some()) { for e in r["expr"].as_array_mut().unwrap() { if let Some(d) = e.get_mut("dnat") { d["addr"] = json!("192.0.2.99"); }
 if e["match"]["left"] == json!({"meta":{"key":"iifname"}}) {e["match"]["right"]=json!("br-lan");} } } } },
            "late-source" => { for c in items.iter_mut().filter_map(|o| o.get_mut("chain")) { if c["name"] == "prerouting_mark" { c["prio"] = json!(-98); } } },
            "broadened-drop" => { for r in items.iter_mut().filter_map(|o| o.get_mut("rule")) { if r["chain"] == "prerouting_hook" { r["expr"].as_array_mut().unwrap().retain(|e| e["match"]["left"] != json!({"payload":{"protocol":"icmp","field":"type"}})); } } },
            "foreign-tproxy" => items.push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"tproxy":{"port":9999}}]}})),
            "source-other-ingress" => { for r in items.iter_mut().filter_map(|o| o.get_mut("rule")) { if r["chain"] == "prerouting_mark" && r["expr"][0]["match"]["right"] == "br-lan" { r["expr"][0]["match"]["right"] = json!("guest"); } } },
            "unknown-source" => items.retain(|o| !o.get("rule").is_some_and(|r| r["chain"] == "prerouting_mark")),
            "unscoped-return" => items.push(json!({"rule":{"family":"inet","table":"stgws","chain":"prerouting_mark","expr":[{"counter":{"packets":0,"bytes":0}},{"return":null}]}})),
            _ => unreachable!(),
        }
        assert!(classify(&f).is_some(), "unsafe {mutation} admitted");
    }
}
