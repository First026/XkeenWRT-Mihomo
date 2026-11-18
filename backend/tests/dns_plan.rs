#[path = "../src/network/dns.rs"]
mod dns;
use dns::*;

#[test]
fn local_names_and_reverse_use_original_dnsmasq_without_rewriting_upstreams() {
    let inventory = DnsInventory {
        dnsmasq_instances: 1,
        incompatible_manager: false,
        local_names: vec!["+.lan".into(), "printer".into(), "+.2.0.192.in-addr.arpa".into()],
        upstreams: vec!["127.0.0.1#5053".into(), "127.0.0.1#5054".into()],
        split_upstreams: vec![("+.ru".into(), Some("77.88.8.8#53".into()))],
        verified_loopback_chain_sha256: Some("a".repeat(64)),
        bootstrap: vec!["1.1.1.2".parse().unwrap()],
    };
    let plan = DnsPlan::new(&inventory).unwrap();
    assert_eq!(plan.nameservers, ["127.0.0.1:53"]);
    assert_eq!(plan.local_policy["printer"], "127.0.0.1:53");
    assert_eq!(plan.local_policy["+.lan"], "127.0.0.1:53");
    assert_eq!(plan.split_upstreams, [("+.ru".into(), Some("77.88.8.8#53".into()))]);
    assert_eq!(plan.upstreams, ["127.0.0.1#5053", "127.0.0.1#5054"]);
    assert_eq!(inventory.upstreams, ["127.0.0.1#5053", "127.0.0.1#5054"]);
}

#[test]
fn multiple_dnsmasq_instances_do_not_produce_an_overlay() {
    let inventory = DnsInventory {
        dnsmasq_instances: 2,
        incompatible_manager: false,
        local_names: vec![],
        upstreams: vec![],
        split_upstreams: vec![],
        verified_loopback_chain_sha256: None,
        bootstrap: vec![],
    };
    assert_eq!(DnsPlan::new(&inventory), Err(DnsError::Unsupported));
}
