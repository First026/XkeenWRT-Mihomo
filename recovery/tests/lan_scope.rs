use serde_json::{Value, json};
use xkeenwrt_recovery::Manifest;

fn lan_manifest() -> Value {
    json!({
        "owner_id":"00000000-0000-4000-8000-000000000001", "generation":1,
        "nft_semantic_sha256":"0".repeat(64), "failure_policy":"direct_on_failure",
        "lan_interface":"br-lan", "lan_address":"192.0.2.1", "lan_scope":"192.0.2.0/24",
        "selected_mac":"", "management_macs":[], "source_ipv4":"192.0.2.3",
        "management_ipv4":"192.0.2.3", "management_ipv6":[], "selected_ipv6":[],
        "local_ipv4":["192.0.2.0/24"], "local_ipv6":["fe80::/10"],
        "route_table":100, "mark":1, "mask":1, "priority":10000
    })
}

#[test]
fn whole_lan_scope_captures_subnet_without_binding_to_one_client_mac() {
    let m: Manifest =
        serde_json::from_value(lan_manifest()).expect("whole LAN manifest must be accepted");
    let ast = m.expected_nft_ast().unwrap();
    let rules: Vec<_> = ast["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x.get("rule"))
        .collect();
    let dns = rules.iter().find(|x| x["chain"] == "dns").unwrap();
    assert!(dns["expr"].as_array().unwrap().contains(&json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}})));
    // New and existing DHCP clients have different MACs; neither may be pinned.
    assert!(!serde_json::to_string(&ast).unwrap().contains("\"ether\""));
    assert!(rules.iter().any(|x| x["chain"] == "capture" && x["expr"].as_array().unwrap().contains(&json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}}))));
    assert!(m.expected_failblock_ast(&m).is_ok());
}

#[test]
fn lan_scope_cannot_expand_to_default_route_or_another_subnet() {
    for scope in [
        "0.0.0.0/0",
        "198.51.100.0/24",
        "192.0.2.0/32",
        "192.0.2.1/24",
    ] {
        let mut v = lan_manifest();
        v["lan_scope"] = json!(scope);
        let m: Manifest = serde_json::from_value(v).unwrap();
        assert!(m.nft_json_batch(false).is_err(), "invalid scope {scope}");
    }
}

#[test]
fn late_capture_preserves_prior_dnat_and_legacy_manifests_keep_their_rules() {
    let old: Manifest = serde_json::from_value(lan_manifest()).unwrap();
    let mut updated = lan_manifest();
    updated["capture_version"] = json!(1);
    let new: Manifest = serde_json::from_value(updated).expect("versioned late capture manifest");
    let ast = new.expected_nft_ast().unwrap();
    let entries = ast["nftables"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|x| x["chain"]["name"] == "capture" && x["chain"]["prio"] == -90)
    );
    let own_tproxy = entries
        .iter()
        .position(|x| {
            x["rule"]["expr"]
                .as_array()
                .is_some_and(|xs| xs.iter().any(|x| x.get("tproxy").is_some()))
        })
        .unwrap();
    let prior_nat = entries
        .iter()
        .position(|x| {
            x["rule"]["expr"].as_array().is_some_and(|xs| {
                xs.contains(
                    &json!({"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}}),
                )
            })
        })
        .unwrap();
    assert!(prior_nat < own_tproxy);
    assert!(
        old.expected_nft_ast().unwrap()["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["chain"]["name"] == "capture" && x["chain"]["prio"] == -150)
    );
}

// r26.1: whole-LAN capture started over the Tailscale overlay (decision 024).
fn tailscale_manifest() -> Value {
    let mut v = lan_manifest();
    v["management_channel"] = json!("tailscale");
    v["source_ipv4"] = json!("100.64.20.2");
    v["management_ipv4"] = json!("100.64.20.2");
    v
}

#[test]
fn tailscale_managed_whole_lan_differs_from_lan_start_only_by_management_return() {
    let lan: Manifest = serde_json::from_value(lan_manifest()).unwrap();
    let overlay: Manifest = serde_json::from_value(tailscale_manifest()).unwrap();
    let lan_ast = lan.expected_nft_ast().unwrap().to_string();
    let overlay_ast = overlay
        .expected_nft_ast()
        .expect("Tailscale-managed whole LAN is a valid manifest")
        .to_string();
    assert!(lan_ast.contains("\"192.0.2.3\""));
    assert_eq!(
        lan_ast.replace("\"192.0.2.3\"", "\"100.64.20.2\""),
        overlay_ast
    );
    assert!(overlay.expected_failblock_ast(&overlay).is_ok());
}

type Case = (&'static str, fn(&mut Value));

#[test]
fn tailscale_channel_rejects_lan_router_foreign_or_pilot_management() {
    let cases: [Case; 7] = [
        ("management inside LAN", |v| {
            v["source_ipv4"] = json!("192.0.2.3");
            v["management_ipv4"] = json!("192.0.2.3");
        }),
        ("management is the router", |v| {
            v["source_ipv4"] = json!("192.0.2.1");
            v["management_ipv4"] = json!("192.0.2.1");
        }),
        ("management outside 100.64.0.0/10", |v| {
            v["source_ipv4"] = json!("198.51.100.7");
            v["management_ipv4"] = json!("198.51.100.7");
        }),
        ("source differs from management", |v| {
            v["source_ipv4"] = json!("100.64.20.3")
        }),
        ("block policy", |v| {
            v["failure_policy"] = json!("block_selected_on_failure")
        }),
        ("pilot client instead of whole LAN", |v| {
            v.as_object_mut().unwrap().remove("lan_scope");
            v["selected_mac"] = json!("02:00:00:00:00:02");
            v["management_macs"] = json!(["02:00:00:00:00:03"]);
        }),
        ("Tailscale address without the channel", |v| {
            v.as_object_mut().unwrap().remove("management_channel");
        }),
    ];
    for (name, mutate) in cases {
        let mut v = tailscale_manifest();
        mutate(&mut v);
        let m: Manifest = serde_json::from_value(v).unwrap();
        assert!(m.expected_nft_ast().is_err(), "must reject: {name}");
    }
}

#[test]
fn lan_manifest_serialization_is_unchanged_without_a_channel() {
    let lan: Manifest = serde_json::from_value(lan_manifest()).unwrap();
    // A LAN start keeps r26 bytes, so an installed r26 rescue still reads it.
    assert_eq!(serde_json::to_value(&lan).unwrap(), lan_manifest());
    assert!(
        !serde_json::to_string(&lan)
            .unwrap()
            .contains("management_channel")
    );
}

#[test]
fn overlay_scope_rule_is_shared_by_plan_manifest_and_evidence() {
    use xkeenwrt_recovery::{ManagementChannel, valid_whole_lan_management};
    let (scope, router) = ("192.0.2.0/24", "192.0.2.1".parse().unwrap());
    let ts = Some(ManagementChannel::Tailscale);
    assert!(valid_whole_lan_management(
        scope,
        router,
        "192.0.2.3".parse().unwrap(),
        None
    ));
    assert!(!valid_whole_lan_management(
        scope,
        router,
        "100.64.20.2".parse().unwrap(),
        None
    ));
    assert!(valid_whole_lan_management(
        scope,
        router,
        "100.64.20.2".parse().unwrap(),
        ts
    ));
    for peer in ["100.63.255.255", "100.128.0.1", "192.0.2.3", "192.0.2.1"] {
        assert!(
            !valid_whole_lan_management(scope, router, peer.parse().unwrap(), ts),
            "{peer}"
        );
    }
    // Overlay scope never widens the LAN: same scope rules as a LAN start.
    for bad in [
        "0.0.0.0/0",
        "192.0.2.0/32",
        "192.0.2.1/24",
        "198.51.100.0/24",
    ] {
        assert!(
            !valid_whole_lan_management(bad, router, "100.64.20.2".parse().unwrap(), ts),
            "{bad}"
        );
    }
}
