//! Trusted read-only inventory for a deliberately restricted first pilot.
use super::{
    inventory::{self, DnsFacts, InventoryError},
    read::{self, Query},
};
use crate::network::Inventory;
use serde_json::Value;
use std::io::Read;
use std::{collections::BTreeSet, net::Ipv4Addr};

pub struct Observed {
    pub network: Inventory,
    pub dns: DnsFacts,
    pub foreign_nft_sha256: String,
    pub selected_ipv6: Vec<std::net::Ipv6Addr>,
    pub management_ipv6: Vec<std::net::Ipv6Addr>,
}

/// Gather fresh OS state. Inputs are the requested client and the TCP peer
/// management address, never resource allocations or prebuilt inventory.
pub fn collect(
    lan: &str, selected: Ipv4Addr, management: Ipv4Addr, channel: Option<xkeenwrt_recovery::ManagementChannel>,
    now_unix: u64, cgroup: &std::fs::File,
) -> Result<Observed, InventoryError> {
    collect_inner(lan, selected, management, channel, now_unix, None, None, cgroup)
}

/// Collect a fresh planner inventory. A currently accepted generation may be
/// excluded only after its full nft and routing semantics match the journal.
pub(crate) fn collect_for_generation(
    lan: &str, selected: Ipv4Addr, management: Ipv4Addr, channel: Option<xkeenwrt_recovery::ManagementChannel>,
    now_unix: u64, current: Option<&xkeenwrt_recovery::Manifest>, cgroup: &std::fs::File,
) -> Result<Observed, InventoryError> {
    if current.is_none() {
        return collect_inner(lan, selected, management, channel, now_unix, None, None, cgroup);
    }
    let previous = current.ok_or(InventoryError::Unsupported)?;
    let before = super::helper::core_identity(cgroup).map_err(|_| InventoryError::Unsupported)?;
    let observed = collect_inner(
        lan,
        selected,
        management,
        channel,
        now_unix,
        Some(before.0),
        Some(previous),
        cgroup,
    )?;
    let after = super::helper::core_identity(cgroup).map_err(|_| InventoryError::Unsupported)?;
    if before != after {
        return Err(InventoryError::Unsupported);
    }
    Ok(observed)
}

/// Recollect after core startup, allowing only sockets owned by its verified PID.
pub(crate) fn collect_after_core(
    lan: &str, selected: Ipv4Addr, management: Ipv4Addr, channel: Option<xkeenwrt_recovery::ManagementChannel>,
    now_unix: u64, previous: Option<&xkeenwrt_recovery::Manifest>, cgroup: &std::fs::File,
) -> Result<Observed, InventoryError> {
    let before = super::helper::core_identity(cgroup).map_err(|_| InventoryError::Unsupported)?;
    let observed = collect_inner(
        lan,
        selected,
        management,
        channel,
        now_unix,
        Some(before.0),
        previous,
        cgroup,
    )?;
    let after = super::helper::core_identity(cgroup).map_err(|_| InventoryError::Unsupported)?;
    if before != after {
        return Err(InventoryError::Unsupported);
    }
    Ok(observed)
}
#[allow(clippy::too_many_arguments)]
fn collect_inner(
    lan: &str, selected: Ipv4Addr, management: Ipv4Addr, channel: Option<xkeenwrt_recovery::ManagementChannel>,
    now_unix: u64, owned: Option<u32>, current: Option<&xkeenwrt_recovery::Manifest>, cgroup: &std::fs::File,
) -> Result<Observed, InventoryError> {
    let q = |which| read::query(which, cgroup).map_err(|_| InventoryError::Unsupported);
    let links = q(Query::Links)?;
    let addresses = q(Query::Addresses)?;
    let neighbours = q(Query::Neighbours)?;
    let leases = read::default_leases().map_err(|_| InventoryError::Unsupported)?;
    let netifd = q(Query::NetworkStatus)?;
    let dnsconfig = q(Query::DnsConfig)?;
    let dns_facts = inventory::dnsmasq_facts(&dnsconfig)?;
    let (proxyconfig, proxyservice) = if dns_facts.has_loopback_upstream() {
        (q(Query::ProxyConfig)?, q(Query::ProxyService)?)
    } else {
        (Vec::new(), Vec::new())
    };
    let rules4 = q(Query::Rules4)?;
    let rules6 = q(Query::Rules6)?;
    let routes4 = q(Query::Routes4)?;
    let routes6 = q(Query::Routes6)?;
    let (nft, flowtables) = xkeenwrt_recovery::flow_offload::capture_nft(|| read::query(Query::NftRuleset, cgroup))
        .map_err(|_| InventoryError::Unsupported)?;
    let mut modules = Vec::new();
    std::io::Read::take(
        std::fs::File::open("/proc/modules").map_err(|_| InventoryError::Unsupported)?,
        1_048_577,
    )
    .read_to_end(&mut modules)
    .map_err(|_| InventoryError::Unsupported)?;
    let mut sockets = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"] {
        let file = std::fs::File::open(path).map_err(|_| InventoryError::Unsupported)?;
        let mut data = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut data)
            .map_err(|_| InventoryError::Unsupported)?;
        sockets.push(data);
    }
    if let Some(pid) = owned {
        // Read descriptors beside the socket tables, after slow inventory
        // commands. A snapshot taken before core startup completes can miss
        // listeners which appear while those commands are running.
        let inodes = super::helper::process_socket_inodes(pid).map_err(|_| InventoryError::Unsupported)?;
        let lan_ip = inventory::address_facts(&addresses, lan)?.lan_address;
        if !listeners_owned([&sockets[0], &sockets[1], &sockets[2], &sockets[3]], lan_ip, &inodes)? {
            return Err(InventoryError::Unsupported);
        }
    } else {
        for (kind, table) in sockets.iter().enumerate() {
            if let Some(port) = occupied_listener_port(table)? {
                return Err(InventoryError::ResourceConflict {
                    port,
                    transport: if kind % 2 == 0 {
                        inventory::SocketTransport::Tcp
                    } else {
                        inventory::SocketTransport::Udp
                    },
                });
            }
        }
    }
    let mut nft_foreign = nft.clone();
    let mut rules4_foreign = rules4.clone();
    let mut routes4_foreign = routes4.clone();
    if let Some(manifest) = current {
        if !super::status::routing_matches(manifest, &rules4, &routes4).is_ok_and(|matches| matches) {
            return Err(InventoryError::Unsupported);
        }
        nft_foreign = strip_owned_nft(&nft, manifest)?;
        rules4_foreign = strip_owned_rules(&rules4, manifest)?;
        routes4_foreign = strip_owned_routes(&routes4, manifest)?;
    }
    let mut observed = assemble(
        lan,
        selected,
        management,
        channel,
        now_unix,
        &links,
        &addresses,
        &neighbours,
        &leases,
        &netifd,
        &dnsconfig,
        &proxyconfig,
        &proxyservice,
        &rules4_foreign,
        &rules6,
        &routes4_foreign,
        &routes6,
        &nft_foreign,
        &flowtables,
        &modules,
        [&sockets[0], &sockets[1], &sockets[2], &sockets[3]],
    )?;
    if let Some(manifest) = current {
        observed.network.xkeenwrt_table_exists = true;
        observed.network.existing_table = Some(crate::network::ExistingTable {
            owner_id: manifest.owner_id.clone(),
            generation: manifest.generation,
            semantic_sha256: manifest.nft_semantic_sha256.clone(),
        });
        observed.network.occupied_tables.push(manifest.route_table);
        observed.network.occupied_marks.push((manifest.mark, manifest.mask));
        observed.network.occupied_priorities.push(manifest.priority);
    }
    Ok(observed)
}

pub(super) fn strip_owned_nft(input: &[u8], manifest: &xkeenwrt_recovery::Manifest) -> Result<Vec<u8>, InventoryError> {
    let fail = || InventoryError::Unsupported;
    if input.len() > 1_048_576 {
        return Err(fail());
    }
    let mut root: Value = serde_json::from_slice(input).map_err(|_| fail())?;
    let items = root
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or_else(fail)?;
    let mut owned = Vec::new();
    let mut foreign = Vec::new();
    for item in std::mem::take(items) {
        let Some(object) = item.as_object() else {
            return Err(fail());
        };
        if object.len() != 1 {
            return Err(fail());
        }
        let Some((kind, body)) = object.iter().next() else {
            return Err(fail());
        };
        let Some(fields) = body.as_object() else {
            return Err(fail());
        };
        let project_table = if kind == "table" {
            fields.get("family").and_then(Value::as_str) == Some("inet")
                && fields.get("name").and_then(Value::as_str) == Some("xkeenwrt")
        } else {
            fields.get("family").and_then(Value::as_str) == Some("inet")
                && fields.get("table").and_then(Value::as_str) == Some("xkeenwrt")
        };
        if project_table {
            owned.push(item);
        } else {
            foreign.push(item);
        }
    }
    if owned.is_empty() {
        return Err(fail());
    }
    let actual = serde_json::json!({"nftables": owned});
    let expected = manifest.expected_nft_ast().map_err(|_| fail())?;
    let actual_digest = xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&actual).map_err(|_| fail())?)
        .map_err(|_| fail())?;
    let expected_digest = xkeenwrt_recovery::nft_semantic_digest(&serde_json::to_vec(&expected).map_err(|_| fail())?)
        .map_err(|_| fail())?;
    if actual_digest != manifest.nft_semantic_sha256 || expected_digest != manifest.nft_semantic_sha256 {
        return Err(fail());
    }
    *items = foreign;
    serde_json::to_vec(&root).map_err(|_| fail())
}

fn strip_owned_rules(input: &[u8], manifest: &xkeenwrt_recovery::Manifest) -> Result<Vec<u8>, InventoryError> {
    let fail = || InventoryError::Unsupported;
    if input.len() > 1_048_576 {
        return Err(fail());
    }
    let mut rules: Value = serde_json::from_slice(input).map_err(|_| fail())?;
    let items = rules.as_array_mut().ok_or_else(fail)?;
    items.retain(|rule| {
        let priority = rule.get("priority");
        let number = priority
            .and_then(Value::as_u64)
            .or_else(|| priority.and_then(Value::as_str).and_then(|v| v.parse().ok()));
        number != Some(manifest.priority as u64)
    });
    serde_json::to_vec(&rules).map_err(|_| fail())
}

fn strip_owned_routes(input: &[u8], manifest: &xkeenwrt_recovery::Manifest) -> Result<Vec<u8>, InventoryError> {
    let fail = || InventoryError::Unsupported;
    if input.len() > 1_048_576 {
        return Err(fail());
    }
    let mut routes: Value = serde_json::from_slice(input).map_err(|_| fail())?;
    let items = routes.as_array_mut().ok_or_else(fail)?;
    items.retain(|route| {
        let table = route.get("table");
        let number = table
            .and_then(Value::as_u64)
            .or_else(|| table.and_then(Value::as_str).and_then(|v| v.parse().ok()));
        number != Some(manifest.route_table as u64)
    });
    serde_json::to_vec(&routes).map_err(|_| fail())
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    lan: &str, selected: Ipv4Addr, management: Ipv4Addr, channel: Option<xkeenwrt_recovery::ManagementChannel>,
    now: u64, links: &[u8], addresses: &[u8], neighbours: &[u8], leases: &[u8], netifd: &[u8], dnsconfig: &[u8],
    proxyconfig: &[u8], proxyservice: &[u8], rules4: &[u8], rules6: &[u8], routes4: &[u8], routes6: &[u8], nft: &[u8],
    flowtables: &[xkeenwrt_recovery::flow_offload::FlowTable], modules: &[u8], sockets: [&[u8]; 4],
) -> Result<Observed, InventoryError> {
    let fail = || InventoryError::Unsupported;
    let address = inventory::address_facts(addresses, lan)?;
    let net: Value = serde_json::from_slice(netifd).map_err(|_| fail())?;
    let interfaces = net.get("interface").and_then(Value::as_array).ok_or_else(fail)?;
    let matches: Vec<_> = interfaces
        .iter()
        .filter(|v| v.get("interface").and_then(Value::as_str) == Some("lan"))
        .collect();
    if matches.len() != 1
        || matches[0].get("up").and_then(Value::as_bool) != Some(true)
        || matches[0].get("l3_device").and_then(Value::as_str) != Some(lan)
    {
        return Err(fail());
    }
    let netifd_addresses = matches[0]
        .get("ipv4-address")
        .and_then(Value::as_array)
        .ok_or_else(fail)?;
    if !netifd_addresses.iter().any(|entry| {
        entry
            .get("address")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
            == Some(address.lan_address)
    }) {
        return Err(fail());
    }
    if !inventory::ethernet_like(links, lan)? {
        return Err(fail());
    }
    let (client_mac, management_macs, selected_ipv6, management_ipv6) = if selected == management {
        let [scope] = address.lan_cidrs.as_slice() else {
            return Err(fail());
        };
        let scope = xkeenwrt_recovery::lan_network(scope).ok_or_else(fail)?;
        if !xkeenwrt_recovery::valid_whole_lan_management(&scope, address.lan_address, management, channel) {
            return Err(fail());
        }
        (String::new(), Vec::new(), Vec::new(), Vec::new())
    } else {
        if channel.is_some() {
            return Err(fail());
        }
        let (client, management) =
            inventory::resolve_client_and_management_mac(neighbours, leases, lan, selected, management, now)?;
        let selected_ipv6 = inventory::ipv6_for_mac(neighbours, lan, &client)?;
        let management_ipv6 = inventory::ipv6_for_mac(neighbours, lan, &management)?;
        (client, vec![management], selected_ipv6, management_ipv6)
    };
    let mut dns = inventory::dnsmasq_facts(dnsconfig)?;
    let has_loopback = dns.has_loopback_upstream();
    let proxy_inodes = if has_loopback {
        inventory::https_dns_proxy_socket_inodes(proxyservice)?
    } else {
        Vec::new()
    };
    dns.verified_loopback_chain_sha256 =
        inventory::verified_loopback_chain(&dns, dnsconfig, proxyconfig, proxyservice, sockets, &proxy_inodes)?;
    inventory::validate_dns_targets(
        &dns,
        &address.local_ipv4,
        &address.local_ipv6,
        dns.verified_loopback_chain_sha256.as_deref(),
    )?;

    let dns_json: Value = serde_json::from_slice(dnsconfig).map_err(|_| fail())?;
    let dns_sections = dns_json.get("values").and_then(Value::as_object).ok_or_else(fail)?;
    let dns_section = dns_sections
        .values()
        .find(|v| v.get(".type").and_then(Value::as_str) == Some("dnsmasq"))
        .ok_or_else(fail)?;
    if dns_section
        .get("leasefile")
        .is_some_and(|v| v.as_str() != Some("/tmp/dhcp.leases"))
    {
        return Err(fail());
    }
    let r4 = inventory::occupied_rules(rules4)?;
    let r6 = inventory::occupied_rules(rules6)?;
    xkeenwrt_recovery::flow_offload::verify_for_lan(nft, flowtables, links, lan).map_err(|_| fail())?;
    let nft_info = inventory::occupied_nft(nft)?;
    if nft_info.xkeenwrt_table_exists || topology_conflict_with_inventory(nft, &[lan], addresses)?.is_some() {
        return Err(fail());
    }
    if modules.len() > 1_048_576 {
        return Err(fail());
    }
    let modules = std::str::from_utf8(modules).map_err(|_| fail())?;
    let has_module = |name: &str| modules.lines().any(|l| l.split_ascii_whitespace().next() == Some(name));
    if !has_module("nft_tproxy") || !has_module("nft_socket") {
        return Err(fail());
    }
    let mut tables: BTreeSet<u32> = r4.tables.into_iter().chain(r6.tables).collect();
    let mut local4: BTreeSet<String> = address.local_ipv4.into_iter().collect();
    let mut local6: BTreeSet<String> = address.local_ipv6.into_iter().collect();
    inventory::route_facts(routes4, false, &mut tables, &mut local4)?;
    inventory::route_facts(routes6, true, &mut tables, &mut local6)?;
    let mut marks = r4.marks;
    marks.extend(r6.marks);
    if nft_info.used_mark_mask != 0 {
        marks.push((nft_info.used_mark_mask, nft_info.used_mark_mask));
    }
    let mut priorities = r4.priorities;
    priorities.extend(r6.priorities);
    Ok(Observed {
        foreign_nft_sha256: xkeenwrt_recovery::evidence::foreign_nft_digest(nft).map_err(|_| fail())?,
        network: Inventory {
            complete: true,
            hook_topology_verified: true,
            ethernet_like: true,
            client_mac: Some(client_mac),
            management_macs: Some(management_macs),
            lan_ifname: Some(lan.into()),
            lan_address: Some(address.lan_address),
            lan_cidrs: address.lan_cidrs,
            tproxy_available: true,
            socket_available: true,
            occupied_tables: tables.into_iter().collect(),
            occupied_marks: marks,
            occupied_priorities: priorities,
            xkeenwrt_table_exists: false,
            existing_table: None,
            local_ipv4: local4.into_iter().collect(),
            local_ipv6: local6.into_iter().collect(),
        },
        dns,
        selected_ipv6,
        management_ipv6,
    })
}

// Foreign prerouting requires a proof of coexistence. The stock fw4 DNS-only
// redirect runs after our selected-client DNS NAT; other DNAT remains unsafe.
pub fn hook_topology_safe(input: &[u8]) -> Result<bool, InventoryError> {
    hook_topology_for_ingress(input, &[])
}

pub use xkeenwrt_recovery::topology::{
    FirewallConflict, hook_topology_for_ingress, topology_conflict, topology_conflict_with_inventory,
};

/// Ignore the project table only when the journal manifest proves its full
/// owner, generation and canonical semantics. A table name or comment alone
/// is not enough to remove its hooks from the foreign-topology check.
pub fn hook_topology_for_current(
    input: &[u8], current: Option<&xkeenwrt_recovery::Manifest>,
) -> Result<bool, InventoryError> {
    let foreign = match current {
        Some(manifest) => strip_owned_nft(input, manifest)?,
        None => {
            if inventory::occupied_nft(input)?.xkeenwrt_table_exists {
                return Ok(false);
            }
            input.to_vec()
        }
    };
    let ingress: Vec<&str> = current
        .filter(|m| m.capture_version == Some(1))
        .map(|m| vec![m.lan_interface.as_str()])
        .unwrap_or_default();
    hook_topology_for_ingress(&foreign, &ingress)
}

fn connected_peer(fields: &[&str]) -> bool {
    fields
        .get(2)
        .and_then(|v| v.split_once(':'))
        .is_some_and(|(host, port)| {
            matches!(host.len(), 8 | 32)
                && host.bytes().all(|b| b.is_ascii_hexdigit())
                && port.len() == 4
                && u16::from_str_radix(port, 16).is_ok_and(|p| p != 0)
        })
}

fn time_wait(fields: &[&str]) -> bool {
    fields.get(3) == Some(&"06") && fields.get(9) == Some(&"0") && connected_peer(fields)
}

/// TIME_WAIT is a retired TCP connection with no process or listening socket.
/// Every live use of a reserved port still prevents initial admission.
pub fn listener_ports_free(input: &[u8]) -> Result<bool, InventoryError> {
    occupied_listener_port(input).map(|port| port.is_none())
}
pub fn occupied_listener_port(input: &[u8]) -> Result<Option<u16>, InventoryError> {
    if input.len() > 1_048_576 {
        return Err(InventoryError::Unsupported);
    }
    let content = std::str::from_utf8(input).map_err(|_| InventoryError::Unsupported)?;
    let mut lines = content.lines();
    if !lines
        .next()
        .is_some_and(|s| s.split_ascii_whitespace().any(|s| s == "local_address"))
    {
        return Err(InventoryError::Unsupported);
    }
    for line in lines {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let local = *fields.get(1).ok_or(InventoryError::Unsupported)?;
        let (host, port) = local.split_once(':').ok_or(InventoryError::Unsupported)?;
        if !matches!(host.len(), 8 | 32) || !host.bytes().all(|b| b.is_ascii_hexdigit()) || port.len() != 4 {
            return Err(InventoryError::Unsupported);
        }
        let port = u16::from_str_radix(port, 16).map_err(|_| InventoryError::Unsupported)?;
        if (port == 7893 || port == 1053) && !time_wait(&fields) {
            return Ok(Some(port));
        }
    }
    Ok(None)
}

/// Check all four listeners against inode ownership of one verified core PID.
/// Any same-port IPv6, wildcard, duplicate or foreign socket is a conflict.
pub fn listeners_owned(tables: [&[u8]; 4], lan: Ipv4Addr, owned_inodes: &[u64]) -> Result<bool, InventoryError> {
    let octets = lan.octets();
    let address = format!("{:02X}{:02X}{:02X}{:02X}", octets[3], octets[2], octets[1], octets[0]);
    let mut counts = [0u8; 4];
    for (kind, data) in tables.iter().enumerate() {
        if data.len() > 1_048_576 {
            return Err(InventoryError::Unsupported);
        }
        let text = std::str::from_utf8(data).map_err(|_| InventoryError::Unsupported)?;
        let mut lines = text.lines();
        if !lines
            .next()
            .is_some_and(|s| s.split_ascii_whitespace().any(|s| s == "local_address"))
        {
            return Err(InventoryError::Unsupported);
        }
        for line in lines {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let local = *fields.get(1).ok_or(InventoryError::Unsupported)?;
            let (host, port) = local.split_once(':').ok_or(InventoryError::Unsupported)?;
            if !matches!(host.len(), 8 | 32) || port.len() != 4 || !host.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InventoryError::Unsupported);
            }
            let port = u16::from_str_radix(port, 16).map_err(|_| InventoryError::Unsupported)?;
            if ![7893, 1053].contains(&port) {
                continue;
            }
            if kind % 2 == 0 && time_wait(&fields) {
                continue;
            }
            if kind >= 2 || !host.eq_ignore_ascii_case(&address) {
                return Ok(false);
            }
            let state = *fields.get(3).ok_or(InventoryError::Unsupported)?;
            let inode: u64 = fields
                .get(9)
                .ok_or(InventoryError::Unsupported)?
                .parse()
                .map_err(|_| InventoryError::Unsupported)?;
            if inode == 0 || !owned_inodes.contains(&inode) {
                return Ok(false);
            }
            if kind == 0 && matches!(state, "01" | "04" | "05" | "08" | "09" | "0B") && connected_peer(&fields) {
                continue;
            }
            if (kind == 0 && state != "0A") || (kind == 1 && state != "07") {
                return Ok(false);
            }
            let index = kind * 2 + usize::from(port == 1053);
            counts[index] = counts[index].checked_add(1).ok_or(InventoryError::Unsupported)?;
        }
    }
    Ok(counts == [1, 1, 1, 1])
}

/// Take a fresh, bounded evidence snapshot; callers compare two passes while
/// holding the mutation lock and check listener/core identity separately.
pub(crate) fn collect_evidence(
    manifest: &xkeenwrt_recovery::Manifest, nft: xkeenwrt_recovery::evidence::NftExpectation<'_>,
    routing: xkeenwrt_recovery::evidence::RoutingExpectation, cgroup: &std::fs::File,
) -> Result<xkeenwrt_recovery::evidence::NetworkEvidence, InventoryError> {
    collect_evidence_scoped(manifest, None, nft, routing, cgroup)
}

fn collect_evidence_scoped(
    manifest: &xkeenwrt_recovery::Manifest, scope: Option<&xkeenwrt_recovery::Manifest>,
    nft: xkeenwrt_recovery::evidence::NftExpectation<'_>, routing: xkeenwrt_recovery::evidence::RoutingExpectation,
    cgroup: &std::fs::File,
) -> Result<xkeenwrt_recovery::evidence::NetworkEvidence, InventoryError> {
    use xkeenwrt_recovery::evidence::{FixedInputs, NetworkEvidence, OwnedExpectation};
    let q = |query| read::query(query, cgroup).map_err(|_| InventoryError::Unsupported);
    let links = q(Query::Links)?;
    let addresses = q(Query::Addresses)?;
    let neighbours = q(Query::Neighbours)?;
    let leases = read::default_leases().map_err(|_| InventoryError::Unsupported)?;
    let netifd = q(Query::NetworkStatus)?;
    let dnsconfig = q(Query::DnsConfig)?;
    let dns_facts = inventory::dnsmasq_facts(&dnsconfig)?;
    let (proxyconfig, proxyservice) = if dns_facts.has_loopback_upstream() {
        (q(Query::ProxyConfig)?, q(Query::ProxyService)?)
    } else {
        (Vec::new(), Vec::new())
    };
    let (nft_data, flowtables) =
        xkeenwrt_recovery::flow_offload::capture_nft(|| read::query(Query::NftRuleset, cgroup))
            .map_err(|_| InventoryError::Unsupported)?;
    let rules4 = q(Query::Rules4)?;
    let rules6 = q(Query::Rules6)?;
    let routes4 = q(Query::Routes4)?;
    let routes6 = q(Query::Routes6)?;
    let mut sockets = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"] {
        let file = std::fs::File::open(path).map_err(|_| InventoryError::Unsupported)?;
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| InventoryError::Unsupported)?;
        if bytes.len() > 1_048_576 {
            return Err(InventoryError::Unsupported);
        }
        sockets.push(bytes);
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| InventoryError::Unsupported)?
        .as_secs();
    let inputs = FixedInputs {
        flowtables: Some(&flowtables),
        links: &links,
        addresses: &addresses,
        neighbours: &neighbours,
        leases: &leases,
        netifd: &netifd,
        dnsconfig: &dnsconfig,
        proxyconfig: &proxyconfig,
        proxyservice: &proxyservice,
        tcp4: &sockets[0],
        udp4: &sockets[1],
        tcp6: &sockets[2],
        udp6: &sockets[3],
        nft: &nft_data,
        rules4: &rules4,
        rules6: &rules6,
        routes4: &routes4,
        routes6: &routes6,
        now_unix,
    };
    NetworkEvidence::capture_fixed(
        &inputs,
        OwnedExpectation {
            manifest,
            scope_manifest: scope,
            nft,
            routing,
        },
    )
    .map_err(|_| InventoryError::Unsupported)
}

/// Capture foreign state while the previous generation remains installed,
/// binding the snapshot to the candidate's new client scope.
pub(crate) fn collect_replacement_evidence(
    previous: &xkeenwrt_recovery::Manifest, current: &xkeenwrt_recovery::Manifest, cgroup: &std::fs::File,
) -> Result<xkeenwrt_recovery::evidence::NetworkEvidence, InventoryError> {
    use xkeenwrt_recovery::evidence::{NftExpectation, RoutingExpectation};
    let first = collect_evidence_scoped(
        previous,
        Some(current),
        NftExpectation::Digest(&previous.nft_semantic_sha256),
        RoutingExpectation::Exact,
        cgroup,
    )?;
    let second = collect_evidence_scoped(
        previous,
        Some(current),
        NftExpectation::Digest(&previous.nft_semantic_sha256),
        RoutingExpectation::Exact,
        cgroup,
    )?;
    if first != second {
        return Err(InventoryError::Unsupported);
    }
    Ok(first)
}

/// No network objects for the new generation may exist before pending. Two
/// independently collected snapshots must agree before the journal is written.
pub(crate) fn collect_initial_evidence(
    manifest: &xkeenwrt_recovery::Manifest, cgroup: &std::fs::File,
) -> Result<xkeenwrt_recovery::evidence::NetworkEvidence, InventoryError> {
    use xkeenwrt_recovery::evidence::{NftExpectation, RoutingExpectation};
    let first = collect_evidence(manifest, NftExpectation::Absent, RoutingExpectation::Absent, cgroup)?;
    let second = collect_evidence(manifest, NftExpectation::Absent, RoutingExpectation::Absent, cgroup)?;
    if first != second {
        return Err(InventoryError::Unsupported);
    }
    Ok(first)
}
