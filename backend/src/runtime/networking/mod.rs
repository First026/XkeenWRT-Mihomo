pub mod active;
pub mod cgroup;
pub mod collector;
pub mod compatibility;
pub mod dns;
pub(crate) mod driver;
pub mod helper;
pub mod identity;
pub mod incarnation;
pub mod inventory;
pub mod key;
pub(crate) mod planning;
pub(crate) mod plans;
pub mod read;
pub mod status;
pub mod transaction;

/// Report a native network path only when its global, current prerequisites
/// are present. Client/LAN bindings are checked again by every plan request.
pub(crate) fn capability(cgroup: &std::fs::File) -> bool {
    readiness(cgroup).is_ok()
}
pub(crate) fn readiness(cgroup: &std::fs::File) -> Result<(), &'static str> {
    use std::{io::Read, os::fd::AsRawFd};
    if !crate::platform::Platform::compatible_packages_in(Some(cgroup.as_raw_fd())) {
        return Err("NETWORK_PREREQUISITES");
    }
    let Some((_, digest, build_id)) = crate::platform::Platform::verified_recovery(cgroup.as_raw_fd()) else {
        return Err("NETWORK_PREREQUISITES");
    };
    if xkeenwrt_recovery::rescue::verify(&digest, build_id).is_err() {
        return Err("NETWORK_PREREQUISITES");
    }
    let Ok(mut modules) = std::fs::File::open("/proc/modules") else {
        return Err("NETWORK_PREREQUISITES");
    };
    let mut bytes = Vec::new();
    if modules.by_ref().take(1_048_577).read_to_end(&mut bytes).is_err() || bytes.len() > 1_048_576 {
        return Err("NETWORK_PREREQUISITES");
    }
    let Ok(modules) = std::str::from_utf8(&bytes) else {
        return Err("NETWORK_PREREQUISITES");
    };
    let has_module = |name: &str| {
        modules
            .lines()
            .any(|line| line.split_ascii_whitespace().next() == Some(name))
    };
    if !has_module("nft_tproxy") || !has_module("nft_socket") {
        return Err("NETWORK_MODULES_MISSING");
    }
    let journal = match driver::OpenWrtDriver::<crate::runtime::validator::ProcessValidator>::secure_journal() {
        Ok(journal) => journal,
        Err(_) => return Err("NETWORK_PREREQUISITES"),
    };
    let existing = journal
        .as_ref()
        .and_then(driver::OpenWrtDriver::<crate::runtime::validator::ProcessValidator>::capability_manifest);
    let Ok(nft) = read::query(read::Query::NftRuleset, cgroup) else {
        return Err("NETWORK_PREREQUISITES");
    };
    if firewall_check(&nft, existing, cgroup).is_err() {
        return Err("NETWORK_FIREWALL_CONFLICT");
    }
    if let Some(manifest) = existing {
        let Ok(rules) = read::query(read::Query::Rules4, cgroup) else {
            return Err("NETWORK_PREREQUISITES");
        };
        let Ok(routes) = read::query(read::Query::Routes4, cgroup) else {
            return Err("NETWORK_PREREQUISITES");
        };
        if !status::routing_matches(manifest, &rules, &routes).is_ok_and(|matches| matches) {
            return Err("NETWORK_PREREQUISITES");
        }
    }
    let Ok(dns) = read::query(read::Query::DnsConfig, cgroup) else {
        return Err("NETWORK_PREREQUISITES");
    };
    let Ok(facts) = xkeenwrt_recovery::evidence::inventory::dnsmasq_facts(&dns) else {
        return Err("NETWORK_DNS_UNSUPPORTED");
    };
    let (proxy, service, proxy_inodes, sockets) = if facts.has_loopback_upstream() {
        let Ok(proxy) = read::query(read::Query::ProxyConfig, cgroup) else {
            return Err("NETWORK_PREREQUISITES");
        };
        let Ok(service) = read::query(read::Query::ProxyService, cgroup) else {
            return Err("NETWORK_PREREQUISITES");
        };
        let Ok(proxy_inodes) = xkeenwrt_recovery::evidence::inventory::https_dns_proxy_socket_inodes(&service) else {
            return Err("NETWORK_PREREQUISITES");
        };
        let mut sockets = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"] {
            let Ok(file) = std::fs::File::open(path) else {
                return Err("NETWORK_PREREQUISITES");
            };
            let mut bytes = Vec::new();
            if std::io::Read::take(file, 1_048_577).read_to_end(&mut bytes).is_err() || bytes.len() > 1_048_576 {
                return Err("NETWORK_PREREQUISITES");
            }
            sockets.push(bytes);
        }
        (proxy, service, proxy_inodes, sockets)
    } else {
        (Vec::new(), Vec::new(), Vec::new(), vec![Vec::new(); 4])
    };
    xkeenwrt_recovery::evidence::inventory::verified_loopback_chain(
        &facts,
        &dns,
        &proxy,
        &service,
        [&sockets[0], &sockets[1], &sockets[2], &sockets[3]],
        &proxy_inodes,
    )
    .map(|_| ())
    .map_err(|_| "NETWORK_DNS_UNSUPPORTED")
}

/// Keep the status/disable panel visible while a durable network journal
/// exists, even when prerequisites for a new plan or apply have drifted.
/// Mutating requests still call `capability` and revalidate their exact state.
pub(crate) fn control_visible(cgroup: &std::fs::File) -> bool {
    if capability(cgroup) {
        return true;
    }
    driver::OpenWrtDriver::<crate::runtime::validator::ProcessValidator>::secure_journal()
        .is_ok_and(|journal| journal.is_some())
}

/// Trusted netifd chooses the routing ingress. HTTP never supplies an allowlist.
fn firewall_check(
    nft: &[u8], existing: Option<&xkeenwrt_recovery::Manifest>, cgroup: &std::fs::File,
) -> Result<(), String> {
    let net = read::query(read::Query::NetworkStatus, cgroup).map_err(|_| "LAN inventory unavailable".to_string())?;
    let net: serde_json::Value = serde_json::from_slice(&net).map_err(|_| "LAN inventory invalid".to_string())?;
    let entries = net["interface"].as_array().ok_or("LAN inventory missing")?;
    let lan: Vec<_> = entries
        .iter()
        .filter(|i| i["interface"] == "lan" && i["up"] == true)
        .collect();
    let [lan] = lan.as_slice() else {
        return Err("Trusted LAN is ambiguous".into());
    };
    let lan = lan["l3_device"].as_str().ok_or("LAN interface missing")?;
    let foreign = match existing {
        Some(m) => collector::strip_owned_nft(nft, m).map_err(|_| "Owned firewall verification failed".to_string())?,
        None => nft.to_vec(),
    };
    let ingress = if existing.is_none_or(|m| m.capture_version == Some(1)) {
        vec![lan]
    } else {
        vec![]
    };
    let addresses =
        read::query(read::Query::Addresses, cgroup).map_err(|_| "Address inventory unavailable".to_string())?;
    match collector::topology_conflict_with_inventory(&foreign, &ingress, &addresses) {
        Ok(None) => Ok(()),
        Ok(Some(c)) => Err(c.message()),
        Err(_) => Err("Неподдерживаемая структура nft JSON. Перехват не включён.".into()),
    }
}
