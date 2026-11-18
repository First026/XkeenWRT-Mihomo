use xkeenwrt_recovery::{dns_snapshot, evidence::inventory::dnsmasq_facts};

#[test]
fn stock_openwrt_resolvers_are_observed_without_rewriting_dhcp() {
    let config = br#"{"values":{"dns":{".type":"dnsmasq","local":"/lan/","resolvfile":"/tmp/resolv.conf.d/resolv.conf.auto"}}}"#;
    assert!(
        dnsmasq_facts(config).is_err(),
        "unobserved resolver file must not be trusted"
    );
    let snapshot = dns_snapshot::with_resolver(
        config,
        b"# Interface wan\nnameserver 192.0.2.53\nsearch provider.example\nnameserver 2001:db8::53\n",
    )
    .unwrap();
    let facts = dnsmasq_facts(&snapshot).unwrap();
    assert_eq!(facts.upstreams.len(), 2);
    assert!(
        dns_snapshot::with_resolver(config, b"nameserver 127.0.0.1\n")
            .and_then(|s| dnsmasq_facts(&s).map_err(|_| std::io::Error::other("loop")))
            .is_err()
    );
    let arbitrary = String::from_utf8(config.to_vec())
        .unwrap()
        .replace("/tmp/resolv.conf.d/resolv.conf.auto", "/etc/shadow");
    assert!(dns_snapshot::with_resolver(arbitrary.as_bytes(), b"nameserver 192.0.2.53\n").is_err());
}

#[test]
fn no_resolv_ignores_inactive_path_and_keeps_explicit_upstreams() {
    let config = br#"{"values":{"dns":{".type":"dnsmasq","noresolv":"1","local":"/lan/","resolvfile":"/tmp/resolv.conf.d/resolv.conf.auto","server":["1.1.1.1"]}}}"#;
    let snapshot = dns_snapshot::with_resolver(config, b"nameserver 127.0.0.1\n").unwrap();
    assert_eq!(
        dnsmasq_facts(&snapshot).unwrap().upstreams[0]
            .address
            .to_string(),
        "1.1.1.1"
    );
}
