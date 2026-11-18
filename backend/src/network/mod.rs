//! Pure network plan; applying it requires the independent recovery gate.
pub mod dns;
pub mod executor;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default)]
pub struct Inventory {
    pub complete: bool,
    /// Set only by trusted inventory after all foreign prerouting hooks are assessed.
    pub hook_topology_verified: bool,
    pub ethernet_like: bool,
    pub client_mac: Option<String>,
    pub management_macs: Option<Vec<String>>,
    pub lan_ifname: Option<String>,
    pub lan_address: Option<Ipv4Addr>,
    pub lan_cidrs: Vec<String>,
    pub tproxy_available: bool,
    pub socket_available: bool,
    pub occupied_tables: Vec<u32>,
    pub occupied_marks: Vec<(u32, u32)>,
    pub occupied_priorities: Vec<u32>,
    pub xkeenwrt_table_exists: bool,
    pub existing_table: Option<ExistingTable>,
    pub local_ipv4: Vec<String>,
    pub local_ipv6: Vec<String>,
}
#[derive(Debug)]
pub struct ExistingTable {
    pub owner_id: String,
    pub generation: u64,
    pub semantic_sha256: String,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Allocation {
    pub table: u32,
    pub mark: u32,
    pub mark_mask: u32,
    pub priority: u32,
}
/// Shared planner/preflight resource ranges and mark semantics.
pub fn allocation_candidates(
    tables: &[u32], marks: &[(u32, u32)], priorities: &[u32],
) -> (Option<u32>, Option<u32>, Option<u32>) {
    let table = (100..=252).find(|v| !tables.contains(v));
    let used = marks.iter().fold(0u32, |bits, (_, mask)| bits | mask);
    let mark = (0..32).map(|bit| 1u32 << bit).find(|bit| bit & used == 0);
    let priority = (10000..=32000).find(|v| !priorities.contains(v));
    (table, mark, priority)
}
impl Inventory {
    pub fn allocate(&self) -> Result<Allocation, PlanError> {
        if !self.complete {
            return Err(PlanError::Unsupported);
        }
        let (table, mark, priority) =
            allocation_candidates(&self.occupied_tables, &self.occupied_marks, &self.occupied_priorities);
        let table = table.ok_or(PlanError::Conflict)?;
        let mark = mark.ok_or(PlanError::Conflict)?;
        let priority = priority.ok_or(PlanError::Conflict)?;
        Ok(Allocation {
            table,
            mark,
            mark_mask: mark,
            priority,
        })
    }
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    #[default]
    DirectOnFailure,
    BlockSelectedOnFailure,
}
#[derive(Debug)]
pub struct TrafficPolicy {
    pub table: u32,
    pub mark: u32,
    pub mark_mask: u32,
    pub priority: u32,
    pub lan_ifname: String,
    pub lan_address: Ipv4Addr,
    pub lan_scope: Option<String>,
    pub capture_version: Option<u8>,
    pub selected_mac: String,
    pub client_ipv4: Ipv4Addr,
    pub management_ipv4: Ipv4Addr,
    pub local_ipv4: Vec<String>,
    pub selected_ipv6: Vec<String>,
    pub management_ipv6: Option<Vec<Ipv6Addr>>,
    pub local_ipv6: Vec<String>,
    pub candidate_id: String,
    pub previous_table: Option<(u64, String)>,
    pub owner_id: String,
    pub generation: u64,
    pub failure_policy: Option<FailurePolicy>,
    pub dns: Option<dns::DnsInventory>,
}
impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            table: 0,
            mark: 0,
            mark_mask: 0,
            priority: 0,
            lan_ifname: String::new(),
            lan_address: Ipv4Addr::UNSPECIFIED,
            lan_scope: None,
            capture_version: None,
            selected_mac: String::new(),
            client_ipv4: Ipv4Addr::UNSPECIFIED,
            management_ipv4: Ipv4Addr::UNSPECIFIED,
            local_ipv4: vec![],
            selected_ipv6: vec![],
            management_ipv6: None,
            local_ipv6: vec![],
            candidate_id: String::new(),
            previous_table: None,
            owner_id: String::new(),
            generation: 0,
            failure_policy: None,
            dns: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedManifest {
    pub owner_id: String,
    pub generation: u64,
    pub candidate_id: String,
    pub lan_interface: String,
    pub lan_address: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_version: Option<u8>,
    pub selected_mac: String,
    pub management_macs: Vec<String>,
    pub source_ipv4: Ipv4Addr,
    pub management_ipv4: Ipv4Addr,
    pub management_ipv6: Vec<Ipv6Addr>,
    pub local_ipv4: Vec<String>,
    pub selected_ipv6: Vec<String>,
    pub local_ipv6: Vec<String>,
    pub failure_policy: FailurePolicy,
    pub table_name: String,
    pub route_table: u32,
    pub mark: u32,
    pub mask: u32,
    pub priority: u32,
}
/// Exact policy routing objects. Adapter must install only these objects.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPlan {
    pub table: u32,
    pub rule_priority: u32,
    pub mark: u32,
    pub mask: u32,
    pub local_route: String,
    pub interface: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlan {
    manifest: OwnedManifest,
    nft_batch: String,
    routing: RoutingPlan,
    source_ipv4: Ipv4Addr,
    dns: dns::DnsPlan,
    failure_policy: FailurePolicy,
}
impl NetworkPlan {
    pub fn manifest(&self) -> &OwnedManifest {
        &self.manifest
    }
    pub fn nft_batch(&self) -> &str {
        &self.nft_batch
    }
    pub fn routing(&self) -> &RoutingPlan {
        &self.routing
    }
    pub fn source_ipv4(&self) -> Ipv4Addr {
        self.source_ipv4
    }
    pub fn dns(&self) -> &dns::DnsPlan {
        &self.dns
    }
    pub fn failure_policy(&self) -> FailurePolicy {
        self.failure_policy
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    Unsupported,
    Conflict,
    InvalidPolicy,
}
pub struct Network;
fn valid_owner(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
            }
        })
}
fn cidr4(s: &str) -> bool {
    s.split_once('/')
        .is_some_and(|(a, p)| a.parse::<Ipv4Addr>().is_ok() && p.parse::<u8>().is_ok_and(|n| n > 0 && n <= 32))
}
fn cidr4_contains(s: &str, address: Ipv4Addr) -> bool {
    let Some((network, prefix)) = s.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    (u32::from(network) & mask) == (u32::from(address) & mask)
}
fn usable_lan_pair(cidr: &str, router: Ipv4Addr, client: Ipv4Addr) -> bool {
    let Some((_, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if !(1..=30).contains(&prefix) || !cidr4_contains(cidr, router) || !cidr4_contains(cidr, client) {
        return false;
    }
    let host_mask = u32::MAX >> prefix;
    let host = u32::from(client) & host_mask;
    host != 0 && host != host_mask
}
fn cidr6(s: &str) -> bool {
    s.split_once('/')
        .is_some_and(|(a, p)| a.parse::<Ipv6Addr>().is_ok() && p.parse::<u8>().is_ok_and(|n| n > 0 && n <= 128))
}
impl Network {
    pub fn plan(i: &Inventory, p: &TrafficPolicy) -> Result<NetworkPlan, PlanError> {
        if !i.tproxy_available || !i.socket_available || !i.complete || !i.hook_topology_verified || !i.ethernet_like {
            return Err(PlanError::Unsupported);
        }
        if p.mark == 0 || p.mark != p.mark_mask || p.mark.count_ones() != 1 {
            return Err(PlanError::InvalidPolicy);
        }
        let replacing = match (i.xkeenwrt_table_exists, &i.existing_table, &p.previous_table) {
            (false, None, None) => false,
            (true, Some(existing), Some((generation, digest)))
                if existing.owner_id == p.owner_id
                    && existing.generation == *generation
                    && existing.semantic_sha256 == *digest
                    && *generation < p.generation
                    && digest.len() == 64
                    && digest.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                true
            }
            _ => return Err(PlanError::Conflict),
        };
        if i.occupied_tables.contains(&p.table)
            || i.occupied_priorities.contains(&p.priority)
            || i.occupied_marks.iter().any(|(_, mask)| mask & p.mark_mask != 0)
        {
            return Err(PlanError::Conflict);
        }
        if matches!(p.table, 0 | 253 | 254 | 255)
            || matches!(p.priority, 0 | 32766 | 32767)
            || (p.lan_scope.is_none() && p.client_ipv4 == p.management_ipv4)
            || p.lan_address.is_unspecified()
            || p.lan_address.is_loopback()
            || p.lan_address.is_multicast()
            || !i
                .lan_cidrs
                .iter()
                .any(|cidr| usable_lan_pair(cidr, p.lan_address, p.client_ipv4))
            || p.client_ipv4 == p.lan_address
            || p.client_ipv4.is_unspecified()
            || p.client_ipv4.is_loopback()
            || p.client_ipv4.is_multicast()
            || !p.local_ipv4.iter().any(|cidr| cidr4_contains(cidr, p.client_ipv4))
            || p.management_ipv4.is_unspecified()
            || p.lan_ifname.is_empty()
            || p.lan_ifname.len() > 15
            || !p
                .lan_ifname
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || !valid_owner(&p.owner_id)
            || p.generation == 0
            || p.candidate_id.is_empty()
            || p.candidate_id.len() > 64
            || !p.candidate_id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || p.local_ipv4.is_empty()
            || !p.local_ipv4.iter().all(|s| cidr4(s))
            || p.local_ipv6.is_empty()
            || !p.local_ipv6.iter().all(|s| cidr6(s))
        {
            return Err(PlanError::InvalidPolicy);
        }
        if !p.selected_ipv6.iter().all(|s| cidr6(s) && s.ends_with("/128")) {
            return Err(PlanError::Unsupported);
        }
        if i.lan_ifname.as_deref() != Some(p.lan_ifname.as_str())
            || i.lan_address != Some(p.lan_address)
            || p.local_ipv4 != i.local_ipv4
            || p.local_ipv6 != i.local_ipv6
        {
            return Err(PlanError::Conflict);
        }
        let management_macs = i.management_macs.as_ref().ok_or(PlanError::Unsupported)?;
        if let Some(scope) = &p.lan_scope {
            if i.lan_cidrs.len() != 1
                || xkeenwrt_recovery::lan_network(&i.lan_cidrs[0]).as_ref() != Some(scope)
                || !xkeenwrt_recovery::valid_lan_scope(scope, p.lan_address, p.management_ipv4)
                || p.client_ipv4 != p.management_ipv4
                || i.client_mac.as_deref() != Some("")
                || !p.selected_mac.is_empty()
                || !management_macs.is_empty()
                || !p.selected_ipv6.is_empty()
                || p.management_ipv6.as_ref().is_none_or(|a| !a.is_empty())
            {
                return Err(PlanError::InvalidPolicy);
            }
        } else if i.client_mac.as_deref() != Some(p.selected_mac.as_str())
            || !xkeenwrt_recovery::valid_lan_mac(&p.selected_mac)
            || management_macs.is_empty()
            || !management_macs
                .iter()
                .all(|mac| xkeenwrt_recovery::valid_lan_mac(mac) && mac != &p.selected_mac)
        {
            return Err(PlanError::Unsupported);
        }
        let management_ipv6 = p.management_ipv6.as_ref().ok_or(PlanError::Unsupported)?;
        if p.selected_ipv6.iter().any(|s| {
            let address = s.split_once('/').and_then(|(a, _)| a.parse::<Ipv6Addr>().ok());
            address.is_some_and(|a| a.is_unspecified() || a.is_multicast() || management_ipv6.contains(&a))
        }) {
            return Err(PlanError::Conflict);
        }
        let failure_policy = p.failure_policy.ok_or(PlanError::InvalidPolicy)?;
        let dns = dns::DnsPlan::new(p.dns.as_ref().ok_or(PlanError::Unsupported)?).map_err(|e| match e {
            dns::DnsError::Unsupported => PlanError::Unsupported,
            dns::DnsError::Invalid => PlanError::InvalidPolicy,
        })?;
        let recovery_manifest = xkeenwrt_recovery::Manifest {
            failure_policy: match failure_policy {
                FailurePolicy::DirectOnFailure => xkeenwrt_recovery::FailurePolicy::DirectOnFailure,
                FailurePolicy::BlockSelectedOnFailure => xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure,
            },
            owner_id: p.owner_id.clone(),
            generation: p.generation,
            // Semantic digest is filled by the coordinator from a verified canonical AST before apply.
            nft_semantic_sha256: "0".repeat(64),
            lan_interface: p.lan_ifname.clone(),
            lan_address: p.lan_address,
            lan_scope: p.lan_scope.clone(),
            capture_version: p.capture_version,
            selected_mac: p.selected_mac.clone(),
            management_macs: management_macs.clone(),
            source_ipv4: p.client_ipv4,
            management_ipv4: p.management_ipv4,
            management_ipv6: management_ipv6.clone(),
            local_ipv4: p.local_ipv4.clone(),
            selected_ipv6: p.selected_ipv6.clone(),
            local_ipv6: p.local_ipv6.clone(),
            route_table: p.table,
            mark: p.mark,
            mask: p.mark_mask,
            priority: p.priority,
        };
        let nft = recovery_manifest
            .nft_json_batch(replacing)
            .map_err(|_| PlanError::InvalidPolicy)?;
        Ok(NetworkPlan {
            manifest: OwnedManifest {
                owner_id: p.owner_id.clone(),
                generation: p.generation,
                candidate_id: p.candidate_id.clone(),
                lan_interface: p.lan_ifname.clone(),
                lan_address: p.lan_address,
                lan_scope: p.lan_scope.clone(),
                capture_version: p.capture_version,
                selected_mac: p.selected_mac.clone(),
                management_macs: management_macs.clone(),
                source_ipv4: p.client_ipv4,
                management_ipv4: p.management_ipv4,
                management_ipv6: management_ipv6.clone(),
                local_ipv4: p.local_ipv4.clone(),
                selected_ipv6: p.selected_ipv6.clone(),
                local_ipv6: p.local_ipv6.clone(),
                failure_policy,
                table_name: "xkeenwrt".into(),
                route_table: p.table,
                mark: p.mark,
                mask: p.mark_mask,
                priority: p.priority,
            },
            nft_batch: nft,
            routing: RoutingPlan {
                table: p.table,
                rule_priority: p.priority,
                mark: p.mark,
                mask: p.mark_mask,
                local_route: "0.0.0.0/0".into(),
                interface: "lo".into(),
            },
            source_ipv4: p.client_ipv4,
            dns,
            failure_policy,
        })
    }
}
