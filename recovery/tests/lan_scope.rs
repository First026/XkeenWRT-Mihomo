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
