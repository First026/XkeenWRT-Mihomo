//! Feeds real per-step `ip -j` captures from the netns lab through the public
//! NetworkEvidence API and reports compatibility with the pinned step.
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path};
use xkeenwrt_recovery::{
    Manifest,
    evidence::{
        FixedInputs, NetworkEvidence, NftExpectation, OwnedExpectation, RoutingExpectation,
        inventory,
    },
};

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap()
}
/// The lab kernel boots with ipv6.disable=1. Identical synthetic IPv6 loopback
/// and LAN link-local entries are added to every step; IPv6 is not exercised.
fn addresses(dir: &Path) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&read(dir, "addresses.json")).unwrap();
    for link in v.as_array_mut().unwrap() {
        let add = match link["ifname"].as_str() {
            Some("lo") => json!({"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}),
            Some("br-lan") => {
                json!({"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"})
            }
            _ => continue,
        };
        link["addr_info"].as_array_mut().unwrap().push(add);
    }
    serde_json::to_vec(&v).unwrap()
}
const NETIFD: &[u8] = br#"{"interface":[{"interface":"lan","up":true,"l3_device":"br-lan","ipv4-address":[{"address":"192.168.5.1","mask":24}]}]}"#;
const DNS: &[u8] = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","server":["1.1.1.1"]}}}"#;

fn capture(m: &Manifest, dir: &Path) -> std::io::Result<NetworkEvidence> {
    let (links, addrs, neigh, r4, r6) = (
        read(dir, "links.json"),
        addresses(dir),
        read(dir, "neighbours.json"),
        read(dir, "routes4.json"),
        read(dir, "routes6.json"),
    );
    let input = FixedInputs {
        flowtables: None,
        links: &links,
        addresses: &addrs,
        neighbours: &neigh,
        leases: b"",
        netifd: NETIFD,
        dnsconfig: DNS,
        proxyconfig: b"",
        proxyservice: b"",
        tcp4: b"",
        udp4: b"",
        tcp6: b"",
        udp6: b"",
        nft: br#"{"nftables":[]}"#,
        rules4: b"[]",
        rules6: b"[]",
        routes4: &r4,
        routes6: &r6,
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

fn main() {
    let root = std::env::args().nth(1).expect("captures dir");
    let mut steps: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    steps.sort();
    let pinned_dir = &steps[0];
    let facts = inventory::address_facts(&addresses(pinned_dir), "br-lan").unwrap();
    let mut tables = BTreeSet::new();
    let mut local4: BTreeSet<String> = facts.local_ipv4.into_iter().collect();
    let mut local6: BTreeSet<String> = facts.local_ipv6.into_iter().collect();
    inventory::route_facts(
        &read(pinned_dir, "routes4.json"),
        false,
        &mut tables,
        &mut local4,
    )
    .unwrap();
    inventory::route_facts(
        &read(pinned_dir, "routes6.json"),
        true,
        &mut tables,
        &mut local6,
    )
    .unwrap();
    let m: Manifest = serde_json::from_value(json!({
        "owner_id":"00000000-0000-4000-8000-000000000001", "generation":7,
        "nft_semantic_sha256":"0".repeat(64), "failure_policy":"direct_on_failure",
        "lan_interface":"br-lan", "lan_address":"192.168.5.1", "lan_scope":"192.168.5.0/24",
        "capture_version":1, "selected_mac":"", "management_macs":[], "source_ipv4":"192.168.5.20",
        "management_ipv4":"192.168.5.20", "management_ipv6":[], "selected_ipv6":[],
        "local_ipv4":local4, "local_ipv6":local6,
        "route_table":100, "mark":256, "mask":256, "priority":10000
    }))
    .unwrap();
    let pinned = capture(&m, pinned_dir).expect("pinned capture");
    let mut mismatches = 0;
    for dir in &steps {
        let expect = String::from_utf8(read(dir, "expect"))
            .unwrap()
            .trim()
            .to_owned();
        let wifi = String::from_utf8(read(dir, "wifi-client"))
            .unwrap()
            .trim()
            .to_owned();
        let got = match capture(&m, dir) {
            Ok(e) if e.compatible_with(&pinned) => "same".to_owned(),
            Ok(_) => "drift".to_owned(),
            Err(_) => "drift(capture-refused)".to_owned(),
        };
        let ok = got.starts_with(&expect);
        if !ok {
            mismatches += 1;
        }
        println!(
            "{:<28} wifi={:<4} expected={:<5} got={:<22} {}",
            dir.file_name().unwrap().to_string_lossy(),
            wifi,
            expect,
            got,
            if ok { "OK" } else { "MISMATCH" }
        );
    }
    println!("mismatches={mismatches}");
}
