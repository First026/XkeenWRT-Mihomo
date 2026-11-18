//! Offline replay through the production evaluator. No snapshot data is built in.
use std::{collections::BTreeSet, path::PathBuf};
use xkeen_ui::runtime::networking::{
    compatibility::{Application, Inputs, evaluate, main_lan},
    inventory,
};
use xkeenwrt_recovery::flow_offload::FlowTable;
fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("snapshot directory"));
    let read = |name: &str| std::fs::read(root.join(name)).expect(name);
    let nft = read("nft-ruleset.json");
    let value: serde_json::Value = serde_json::from_slice(&nft).unwrap();
    let text = String::from_utf8(read("nft-flowtable-fw4-ft.txt")).unwrap();
    let tables: Vec<_> = value["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i.get("flowtable"))
        .map(|f| FlowTable {
            family: match f["family"].as_str().unwrap() {
                "inet" => 1,
                "ip" => 2,
                "ip6" => 10,
                _ => panic!("unsupported family"),
            },
            table: f["table"].as_str().unwrap().into(),
            name: f["name"].as_str().unwrap().into(),
            flags: if text.contains("flags offload") {
                1
            } else {
                panic!("no authoritative flags proof in supplied snapshot")
            },
            hook: 0,
            priority: f["prio"].as_i64().unwrap() as i32,
            devices: f["dev"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            handle: f["handle"].as_u64().unwrap_or(0),
        })
        .collect();
    let raw = read("ubus-uci-dhcp.json");
    let dns = xkeenwrt_recovery::dns_snapshot::with_resolver(&raw, &read("resolv.conf.auto")).unwrap();
    let input = Inputs {
        links: read("ip-link.json"),
        addresses: read("ip-address.json"),
        neighbours: read("ip-neigh.json"),
        leases: Vec::new(),
        netifd: read("ubus-network-interface-dump.json"),
        dnsconfig: dns,
        proxyconfig: Vec::new(),
        proxyservice: Vec::new(),
        rules4: read("ip-rule-v4.json"),
        rules6: read("ip-rule-v6.json"),
        routes4: read("ip-route-v4-all.json"),
        routes6: read("ip-route-v6-all.json"),
        nft,
        modules: read("modules.txt"),
        sockets: [
            read("net-tcp-bound.txt"),
            read("net-udp-bound.txt"),
            read("net-tcp6-bound.txt"),
            read("net-udp6-bound.txt"),
        ],
        flowtables: Some(tables),
        ipv6_offloaded: None,
        owned_listeners: false,
        tailscale: None,
    };
    let lan = main_lan(&input.netifd).unwrap();
    let address = inventory::address_facts(&input.addresses, &lan).unwrap();
    let peer = std::net::Ipv4Addr::from(u32::from(address.lan_address) ^ 0x10);
    let supplement = PathBuf::from(
        std::env::args()
            .nth(2)
            .expect("timestamped resource supplement directory"),
    );
    let mem = std::fs::read_to_string(supplement.join("meminfo.txt")).unwrap();
    let memory = mem
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .unwrap()
        * 1024;
    let df = std::fs::read_to_string(supplement.join("df-k.txt")).unwrap();
    let available = |mount: &str| {
        df.lines()
            .find_map(|l| {
                let f: Vec<_> = l.split_whitespace().collect();
                if f.last().copied() == Some(mount) {
                    f.get(3)?.parse::<u64>().ok().map(|n| n * 1024)
                } else {
                    None
                }
            })
            .unwrap()
    };
    let tmp = available("/tmp");
    let flash = available("/overlay");
    // Same approved large synthetic bundle budget, not a private target profile.
    let synthetic_bundle_bytes = 2_850_000;
    let forecast = xkeen_ui::runtime::networking::compatibility::resource_forecast(
        memory,
        0,
        tmp,
        flash,
        synthetic_bundle_bytes,
        synthetic_bundle_bytes,
    );
    let resources = forecast.admitted();
    let app = Application {
        journal_readable: true,
        packages_verified: true,
        rescue_verified: true,
        accepted_profile: true,
        resources: forecast,
        lifecycle_clear: true,
    };
    let report = evaluate(&input, &app, peer, None);
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "scope":"offline production evaluator; no native router access",
        "complete":false,
        "resource_supplement":{"timestamp":"2026-11-16T12:53:45Z","not_concurrent_with_topology":"2026-11-16T11:49:14Z","mem_available_bytes":memory,"tmp_available_bytes":tmp,"overlay_available_bytes":flash,"synthetic_bundle_budget_bytes":synthetic_bundle_bytes,"same_product_capacity_predicate":resources,"history_bytes":0,"history_provenance":"snapshot target uninstalled; no target app payload/history supplied"},
        "not_checked":[
            {"prerequisite":"old IPv6 OFFLOAD conntrack entries","status":"NOT_CHECKED","readonly_command":"bounded native ctnetlink aggregate through r24 GET /api/network/compatibility after authorized installation; snapshot has no CT dump"},
            {"prerequisite":"target filesystem allocation-unit rounding and current concurrent headroom at actual Start","status":"NOT_CHECKED","readonly_command":"stat -f /overlay /tmp; GET /api/network/compatibility at actual Start"},
            {"prerequisite":"installed exact r24 pair, helper package hash/build/inode and persistent ready supervisor","status":"CONDITIONAL_VM_ONLY","readonly_command":"apk info -v xkeenwrt-core xkeenwrt-ui; GET /api/network/compatibility after authorized installation"},
            {"prerequisite":"accepted profile payload integrity and controller lifecycle state on target","status":"NOT_CHECKED","readonly_command":"GET /api/control and GET /api/network/compatibility after authorized Apply"},
            {"prerequisite":"native admin roundtrip and packet behavior on target","status":"NOT_CHECKED","readonly_command":"no read-only command substitutes native acceptance; no router test authorized"},
            {"prerequisite":"hardware teardown completion barrier on MediaTek PPE","status":"LIMIT","readonly_command":"no supported targeted completion barrier found; no available hardware rig"}
        ], "application_conditions":{"value":app,"provenance":"application/helper/profile conditions remain conditional VM prerequisites; target capacities use a separate timestamped resource supplement"},
        "management_peer":"synthetic address within the main IPv4 LAN; not a real admin session",
        "flowtable_flags":"hardware flag taken from supplied nft text because nft1.1.6 JSON omitted it; identity/devices/priority from matching JSON",
        "leases":"not required by whole-LAN scope; no DHCP lease snapshot supplied", "report":report
    })).unwrap());
}
