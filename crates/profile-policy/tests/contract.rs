use profile_policy::{complete, parse_document, proxy_payload_complete, Asset};
use serde_json::{json, Value};
fn config() -> Value {
    json!({"mixed-port":7890,"port":0,"socks-port":0,"redir-port":0,"tproxy-port":0,"allow-lan":false,"bind-address":"127.0.0.1", "external-controller":"127.0.0.1:9090","external-controller-tls":"","external-controller-unix":"","external-controller-pipe":"","external-doh-server":"","external-ui":"","external-ui-url":"","external-ui-name":"","secret":"synthetic","ss-config":"","vmess-config":"","routing-mark":0,"external-controller-routing-mark":0,"interface-name":"","listeners":[],"tunnels":[],"geo-auto-update":false,"tun":{"enable":false,"auto-route":false,"auto-redirect":false,"auto-detect-interface":false,"dns-hijack":[]},"iptables":{"enable":false,"dns-redirect":false},"ntp":{"enable":false,"write-to-system":false},"tuic-server":{"enable":false},"dns":{"enable":false,"enhanced-mode":"normal","listen":"","use-system-hosts":false,"fallback-filter":{"geoip":false}},"profile":{"store-selected":false,"store-fake-ip":false},"proxies":[{"name":"sample","type":"vless","server":"example.org","port":443,"uuid":"00000000-0000-4000-8000-000000000000"}],"rules":["MATCH,DIRECT"]})
}
#[test]
fn supported_inline_profiles_do_not_need_assets() {
    for kind in ["wireguard", "vless", "vmess", "trojan", "ss", "hysteria2"] {
        let mut c = config();
        c["proxies"][0]["type"] = json!(kind);
        assert!(complete(&c.to_string(), &[]), "{kind}");
    }
}
#[test]
fn rejects_unreviewed_files_rules_and_ambiguous_yaml() {
    assert!(parse_document("proxies: []\nproxies: []\n").is_err());
    assert!(parse_document("a: &x value\nb: *x\n").is_err());
    assert!(parse_document("a: yes\n").is_err());
    let mut c = config();
    c["proxies"][0]["private-key-file"] = json!("/etc/shadow");
    assert!(!complete(&c.to_string(), &[]));
    let mut c = config();
    c["rules"] = json!(["IP-ASN,123,DIRECT"]);
    assert!(!complete(&c.to_string(), &[]));
}
#[test]
fn staged_provider_must_match_managed_path_and_reviewed_payload() {
    let mut c = config();
    c["proxy-providers"] =
        json!({"example":{"type":"file","path":"providers/proxies/0.yaml","filter":"sample"}});
    let content=b"proxies:\n  - name: sample\n    type: trojan\n    server: example.org\n    port: 443\n    password: synthetic\n".to_vec();
    assert!(proxy_payload_complete(&content));
    let asset = Asset {
        path: "providers/proxies/0.yaml".into(),
        content,
    };
    assert!(complete(&c.to_string(), std::slice::from_ref(&asset)));
    assert!(!complete(&c.to_string(), &[]));
    assert!(!complete(
        &c.to_string(),
        &[Asset {
            path: "../escape".into(),
            ..asset
        }]
    ));
}
#[test]
fn rule_provider_assets_are_bound_to_their_configured_behavior() {
    let mut c = config();
    c["rule-providers"] = json!({"blocklist":{"type":"file","path":"providers/rules/0.yaml","behavior":"domain","format":"yaml"}});
    c["rules"] = json!(["RULE-SET,blocklist,DIRECT", "MATCH,DIRECT"]);
    let asset = Asset {
        path: "providers/rules/0.yaml".into(),
        content: b"payload:\n  - '+.example.org'\n".to_vec(),
    };
    assert!(complete(&c.to_string(), std::slice::from_ref(&asset)));
    assert!(!complete(&c.to_string(), &[]));
    c["rules"] = json!(["RULE-SET,other,DIRECT"]);
    assert!(!complete(&c.to_string(), &[asset]));
}
#[test]
fn websocket_transport_paths_are_admitted_only_in_transport_options() {
    let mut c = config();
    c["proxies"][0]["network"] = json!("ws");
    c["proxies"][0]["ws-opts"] = json!({"path":"/ws","headers":{"Host":"example.org"}});
    assert!(complete(&c.to_string(), &[]));
    c["proxies"][0]["path"] = json!("/etc/shadow");
    assert!(!complete(&c.to_string(), &[]));
}
#[test]
fn ambiguous_plain_scalars_are_rejected() {
    for source in [
        "x: 2026-11-12\n",
        "x: 1_000\n",
        "x: 0X10\n",
        "x: 18446744073709551616\n",
        "x: .inf\n",
    ] {
        assert!(parse_document(source).is_err(), "{source}");
    }
    assert!(parse_document("x: '2026-11-12'\n").is_ok());
}
#[test]
fn imported_amnezia_fixtures_pass_asset_admission() {
    for source in [
        include_str!("../../../tests/lab/amnezia-legacy.yaml"),
        include_str!("../../../tests/lab/amnezia-v3.yaml"),
    ] {
        let imported = parse_document(source).unwrap();
        let mut effective = config();
        effective["proxies"] = imported["proxies"].clone();
        assert!(complete(&effective.to_string(), &[]));
    }
}
#[test]
fn network_overlay_requires_the_exact_trusted_dns_and_listener_values() {
    use profile_policy::{complete_for, ManagedOverlay, NetworkOverlay};
    let overlay = NetworkOverlay {
        lan_ifname: "br-lan".into(),
        lan_ipv4: "192.168.7.1".parse().unwrap(),
        selected_ipv4: "192.168.7.2".parse().unwrap(),
        tproxy_port: 7893,
        dns_port: 1053,
        nameservers: vec!["1.1.1.1".parse().unwrap()],
        bootstrap: vec!["9.9.9.9".parse().unwrap()],
        local_zones: vec!["+.lan".into()],
    };
    let mut c = config();
    c["mixed-port"] = json!(0);
    c["tproxy-port"] = json!(7893);
    c["allow-lan"] = json!(true);
    c["bind-address"] = json!("192.168.7.1");
    c["dns"] = overlay.dns().unwrap();
    assert_eq!(c["dns"]["nameserver"][0], "1.1.1.1:53");
    assert!(!complete(&c.to_string(), &[]));
    assert!(complete_for(
        &c.to_string(),
        &[],
        &ManagedOverlay::Network(overlay.clone())
    ));
    c["mixed-port"] = json!(7890);
    assert!(!complete_for(
        &c.to_string(),
        &[],
        &ManagedOverlay::Network(overlay.clone())
    ));
    c["mixed-port"] = json!(0);
    c["dns"]["listen"] = json!("0.0.0.0:1053");
    assert!(!complete_for(
        &c.to_string(),
        &[],
        &ManagedOverlay::Network(overlay)
    ));
}

#[test]
fn global_user_agent_is_preserved_and_bounded() {
    let mut c = config();
    c["global-ua"] = json!("Synthetic-Client/1.0");
    assert!(complete(&c.to_string(), &[]));
    c["global-ua"] = json!("x".repeat(513));
    assert!(!complete(&c.to_string(), &[]));
}
