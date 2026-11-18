//! A cable on a bridge port changes physical carrier, not the trusted LAN
//! topology. Interception on the bridge must survive it, while membership,
//! identity, administrative state and addressing changes remain drift.
use serde_json::{Value, json};
use xkeenwrt_recovery::{
    Manifest,
    evidence::{
        FixedInputs, NetworkEvidence, NftExpectation, OwnedExpectation, RoutingExpectation,
    },
};

fn whole_lan_manifest() -> Manifest {
    serde_json::from_value(json!({
        "owner_id":"00000000-0000-4000-8000-000000000001", "generation":7,
        "nft_semantic_sha256":"0".repeat(64), "failure_policy":"direct_on_failure",
        "lan_interface":"br-lan", "lan_address":"192.168.5.1",
        "lan_scope":"192.168.5.0/24", "capture_version":1,
        "selected_mac":"", "management_macs":[], "source_ipv4":"192.168.5.20",
        "management_ipv4":"192.168.5.20", "management_ipv6":[], "selected_ipv6":[],
        "local_ipv4":["127.0.0.1/8","192.168.5.0/24","192.168.5.1/24"],
        "local_ipv6":["::1/128","fe80::1/64"],
        "route_table":100, "mark":256, "mask":256, "priority":10000
    }))
    .expect("synthetic whole-LAN manifest")
}

fn link(index: u32, name: &str, mac: &str, master: Option<&str>, carrier: bool) -> Value {
    let mut flags = vec!["BROADCAST", "MULTICAST", "UP"];
    if carrier {
        flags.push("LOWER_UP");
    } else {
        flags.insert(0, "NO-CARRIER");
    }
    let mut v = json!({
        "ifindex":index, "ifname":name, "flags":flags, "mtu":1500, "qdisc":"mq",
        "operstate": if carrier { "UP" } else { "DOWN" }, "linkmode":"DEFAULT",
        "group":"default", "txqlen":1000, "link_type":"ether", "address":mac,
        "broadcast":"ff:ff:ff:ff:ff:ff"
    });
    if let Some(master) = master {
        v["master"] = json!(master);
    }
    v
}

/// A working router's shape: `eth1` and the Wi-Fi AP are ports of `br-lan`; an associated
/// Wi-Fi client keeps the bridge carrier up while the cable changes.
fn router(eth1_carrier: bool) -> Vec<Value> {
    vec![
        json!({"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,
               "qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default",
               "txqlen":1000,"link_type":"loopback","address":"00:00:00:00:00:00",
               "broadcast":"00:00:00:00:00:00"}),
        link(2, "eth0", "02:00:00:00:10:01", None, false),
        link(3, "eth1", "02:00:00:00:10:02", Some("br-lan"), eth1_carrier),
        link(6, "br-lan", "02:00:00:00:10:02", None, true),
        link(9, "phy1-ap0", "02:00:00:00:10:03", Some("br-lan"), true),
    ]
}

fn addresses_for(links: &[Value]) -> Value {
    Value::Array(
        links
            .iter()
            .map(|l| {
                let mut v = l.clone();
                v["addr_info"] = match l["ifname"].as_str() {
                    Some("lo") => json!([
                        {"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo",
                         "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64},
                        {"family":"inet6","local":"::1","prefixlen":128,"scope":"host","noprefixroute":true,
                         "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64}
                    ]),
                    Some("br-lan") => json!([
                        {"family":"inet","local":"192.168.5.1","prefixlen":24,"broadcast":"192.168.5.255",
                         "scope":"global","label":"br-lan",
                         "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64},
                        {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link",
                         "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64}
                    ]),
                    _ => json!([]),
                };
                v
            })
            .collect(),
    )
}

const LAN_ROUTE: &str = r#"[{"dst":"192.168.5.0/24","dev":"br-lan","protocol":"kernel","scope":"link","prefsrc":"192.168.5.1","flags":[]}]"#;

fn capture(m: &Manifest, links: &[Value], addresses: &Value) -> std::io::Result<NetworkEvidence> {
    capture_routes(m, links, addresses, LAN_ROUTE)
}

fn capture_routes(
    m: &Manifest,
    links: &[Value],
    addresses: &Value,
    routes4: &str,
) -> std::io::Result<NetworkEvidence> {
    let links = serde_json::to_vec(links).unwrap();
    let addresses = serde_json::to_vec(addresses).unwrap();
    let input = FixedInputs {
        flowtables: None,
        links: &links,
        addresses: &addresses,
        neighbours: b"[]",
        leases: b"",
        netifd: br#"{"interface":[{"interface":"lan","up":true,"l3_device":"br-lan","ipv4-address":[{"address":"192.168.5.1","mask":24}]}]}"#,
        dnsconfig: br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1"]}}}"#,
        proxyconfig: b"",
        proxyservice: b"",
        tcp4: b"",
        udp4: b"",
        tcp6: b"",
        udp6: b"",
        nft: br#"{"nftables":[]}"#,
        rules4: b"[]",
        rules6: b"[]",
        routes4: routes4.as_bytes(),
        routes6: b"[]",
        now_unix: 100,
    };
    NetworkEvidence::capture_fixed(
        &input,
        OwnedExpectation {
            manifest: m,
            scope_manifest: None,
            nft: NftExpectation::Absent,
            routing: RoutingExpectation::Absent,
        },
    )
}

#[test]
fn bridge_port_cable_changes_keep_the_pinned_lan_topology() {
    let m = whole_lan_manifest();
    for pinned_carrier in [false, true] {
        let links = router(pinned_carrier);
        let pinned = capture(&m, &links, &addresses_for(&links)).unwrap();
        assert_eq!(pinned.version, 2);
        let links = router(!pinned_carrier);
        let fresh = capture(&m, &links, &addresses_for(&links)).unwrap();
        assert!(
            fresh.compatible_with(&pinned),
            "eth1 carrier {pinned_carrier} -> {} must not be topology drift",
            !pinned_carrier
        );
        // Start compares two fresh captures for equality; a flap between
        // them is the same physical event and must not refuse the snapshot.
        assert_eq!(fresh, pinned);
    }
}

#[test]
fn bridge_membership_identity_admin_state_and_addresses_still_drift() {
    let m = whole_lan_manifest();
    let links = router(false);
    let pinned = capture(&m, &links, &addresses_for(&links)).unwrap();
    // A changed fingerprint, not an unrelated parse failure, must reject these.
    let drifted = |name: &str, links: Vec<Value>, addresses: Value| {
        let fresh = capture(&m, &links, &addresses)
            .unwrap_or_else(|e| panic!("{name}: fresh capture must succeed: {e}"));
        assert!(
            !fresh.compatible_with(&pinned),
            "{name} must remain topology drift"
        );
    };

    let mut v = router(true);
    v[2].as_object_mut().unwrap().remove("master");
    drifted("eth1 leaving br-lan", v.clone(), addresses_for(&v));

    let mut v = router(true);
    v[1]["master"] = json!("br-lan");
    drifted("a new br-lan port", v.clone(), addresses_for(&v));

    let mut v = router(true);
    v[2]["address"] = json!("02:00:00:00:10:99");
    drifted("a changed port MAC", v.clone(), addresses_for(&v));

    let mut v = router(false);
    v[2]["flags"] = json!(["BROADCAST", "MULTICAST"]);
    drifted("administrative down of eth1", v.clone(), addresses_for(&v));

    let mut v = router(true);
    v[4]["ifindex"] = json!(12);
    drifted("a recreated Wi-Fi port", v.clone(), addresses_for(&v));

    let mut v = router(true);
    v.push(link(
        13,
        "phy0-ap1",
        "02:00:00:00:10:04",
        Some("br-lan"),
        true,
    ));
    drifted("an added Wi-Fi port", v.clone(), addresses_for(&v));

    let v = router(true);
    let mut a = addresses_for(&v);
    a[3]["addr_info"].as_array_mut().unwrap().push(json!(
        {"family":"inet6","local":"fd00:5::1","prefixlen":64,"scope":"global",
         "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64}
    ));
    assert!(
        capture(&m, &v, &a).is_err(),
        "a new LAN address must not match the pinned local scope"
    );

    let v = router(true);
    let mut a = addresses_for(&v);
    a[3]["addr_info"][1]["dadfailed"] = json!(true);
    drifted("an address flag change", v, a);

    let mut v = router(true);
    v[3]["mtu"] = json!(1400);
    drifted("a changed bridge MTU", v.clone(), addresses_for(&v));

    // Without any associated port the bridge itself loses carrier; the kernel
    // then marks its connected routes `linkdown`, which stays drift.
    let mut v = router(false);
    v[3] = link(6, "br-lan", "02:00:00:00:10:02", None, false);
    v[4] = link(9, "phy1-ap0", "02:00:00:00:10:03", Some("br-lan"), false);
    let fresh = capture_routes(
        &m,
        &v,
        &addresses_for(&v),
        &LAN_ROUTE.replace(r#""flags":[]"#, r#""flags":["linkdown"]"#),
    )
    .unwrap();
    assert!(
        !fresh.compatible_with(&pinned),
        "a LAN bridge without carrier must remain topology drift"
    );
}

#[test]
fn tailscale_managed_whole_lan_evidence_carries_the_channel_and_stays_valid() {
    let lan = whole_lan_manifest();
    let mut v = serde_json::to_value(&lan).unwrap();
    v["management_channel"] = json!("tailscale");
    v["source_ipv4"] = json!("100.64.20.2");
    v["management_ipv4"] = json!("100.64.20.2");
    let overlay: Manifest = serde_json::from_value(v).unwrap();
    let links = router(true);
    let evidence = capture(&overlay, &links, &addresses_for(&links))
        .expect("evidence for a Tailscale-managed whole LAN");
    assert!(evidence.valid());
    assert_eq!(
        evidence.scope.management_channel,
        Some(xkeenwrt_recovery::ManagementChannel::Tailscale)
    );
    assert_eq!(
        evidence.scope.management_ipv4,
        "100.64.20.2".parse::<std::net::Ipv4Addr>().unwrap()
    );
    // The LAN evidence of the same router keeps no channel (r26 bytes).
    let plain = capture(&lan, &links, &addresses_for(&links)).unwrap();
    assert!(plain.valid() && plain.scope.management_channel.is_none());
    assert!(
        !serde_json::to_string(&plain)
            .unwrap()
            .contains("management_channel")
    );
}
