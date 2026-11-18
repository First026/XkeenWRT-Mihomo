//! Preparation of an immutable network candidate from trusted inventory.
use super::collector::Observed;
use crate::{
    configuration::{Activation, ActivationError, Validator},
    network::{self, dns::DnsInventory},
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// All fields here are internal runtime values. In particular management is the
/// authenticated TCP peer, owner/generation are loaded under the mutation lock,
/// and Observed is gathered locally; none is an HTTP-supplied inventory.
#[derive(Clone)]
pub(crate) struct PlanInput {
    pub profile_id: String,
    pub revision: String,
    pub manual_candidate_id: String,
    pub selected_ipv4: Ipv4Addr,
    pub management_ipv4: Ipv4Addr,
    pub management_channel: Option<xkeenwrt_recovery::ManagementChannel>,
    pub selected_ipv6: Vec<String>,
    pub management_ipv6: Vec<Ipv6Addr>,
    pub failure_policy: network::FailurePolicy,
    pub owner_id: String,
    pub generation: u64,
    pub previous: Option<xkeenwrt_recovery::Manifest>,
    pub explicit: Option<profile_policy::ExplicitOverlay>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedPlan {
    pub plan_id: String,
    pub expires_unix: u64,
    pub profile_id: String,
    pub revision: String,
    pub candidate_id: String,
    pub overlay: profile_policy::NetworkOverlay,
    #[serde(default)]
    pub explicit: Option<profile_policy::ExplicitOverlay>,
    #[serde(default)]
    pub manual_candidate_id: String,
    pub dns_facts: super::inventory::DnsFacts,
    pub foreign_nft_sha256: String,
    pub network: network::NetworkPlan,
    #[serde(default)]
    pub previous: Option<xkeenwrt_recovery::Manifest>,
}

/// Validate exact candidate bytes and assets only after deriving overlay values
/// from trusted inventory. Caller owns generation and stores the plan privately.
pub(crate) fn prepare<V: Validator>(
    activation: &mut Activation<V>, observed: Observed, input: PlanInput,
) -> Result<PreparedPlan, ActivationError> {
    let i = &observed.network;
    let allocation = i.allocate().map_err(|_| ActivationError::Unavailable)?;
    let lan_ifname = i.lan_ifname.clone().ok_or(ActivationError::Unavailable)?;
    let lan_address = i.lan_address.ok_or(ActivationError::Unavailable)?;
    let selected_mac = i.client_mac.clone().ok_or(ActivationError::Unavailable)?;
    if observed.dns.upstreams.len() > 8 {
        return Err(ActivationError::Unavailable);
    }
    let dns_inventory = DnsInventory {
        dnsmasq_instances: 1,
        incompatible_manager: false,
        local_names: observed.dns.local_zones.clone(),
        upstreams: observed
            .dns
            .upstreams
            .iter()
            .map(|v| format!("{}#{}", v.address, v.port))
            .collect(),
        split_upstreams: observed
            .dns
            .split_upstreams
            .iter()
            .map(|(zone, endpoint)| {
                (
                    zone.clone(),
                    endpoint.as_ref().map(|v| format!("{}#{}", v.address, v.port)),
                )
            })
            .collect(),
        verified_loopback_chain_sha256: observed.dns.verified_loopback_chain_sha256.clone(),
        bootstrap: vec![Ipv4Addr::LOCALHOST.into()],
    };
    let dns_plan = network::dns::DnsPlan::new(&dns_inventory).map_err(|_| ActivationError::Unavailable)?;
    let overlay = super::dns::overlay_from_dns_plan(&lan_ifname, lan_address, input.selected_ipv4, &dns_plan)
        .map_err(|_| ActivationError::Unavailable)?;
    if input.selected_ipv6.iter().any(|cidr| {
        cidr.strip_suffix("/128")
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
            .is_none_or(|a| !observed.selected_ipv6.contains(&a))
    }) || input
        .management_ipv6
        .iter()
        .any(|a| !observed.management_ipv6.contains(a))
    {
        return Err(ActivationError::Conflict);
    }
    let mut policy = network::TrafficPolicy {
        table: allocation.table,
        mark: allocation.mark,
        mark_mask: allocation.mark_mask,
        priority: allocation.priority,
        lan_ifname,
        lan_address,
        capture_version: Some(1),
        lan_scope: if input.selected_ipv4 == input.management_ipv4 {
            match i.lan_cidrs.as_slice() {
                [scope] => Some(xkeenwrt_recovery::lan_network(scope).ok_or(ActivationError::Unavailable)?),
                _ => return Err(ActivationError::Unavailable),
            }
        } else {
            None
        },
        selected_mac,
        client_ipv4: input.selected_ipv4,
        management_ipv4: input.management_ipv4,
        local_ipv4: i.local_ipv4.clone(),
        selected_ipv6: input.selected_ipv6,
        management_ipv6: Some(observed.management_ipv6.clone()),
        management_channel: input.management_channel,
        local_ipv6: i.local_ipv6.clone(),
        candidate_id: input.manual_candidate_id.clone(),
        previous_table: input
            .previous
            .as_ref()
            .map(|m| (m.generation, m.nft_semantic_sha256.clone())),
        owner_id: input.owner_id,
        generation: input.generation,
        failure_policy: Some(input.failure_policy),
        dns: Some(dns_inventory),
    };
    // Avoid replacing the manual candidate if policy prerequisites already fail.
    network::Network::plan(i, &policy).map_err(|_| ActivationError::Unavailable)?;
    let candidate = activation.validate_network_inputs(
        &input.profile_id,
        &input.revision,
        &input.manual_candidate_id,
        overlay.clone(),
        input.explicit.clone(),
    )?;
    policy.candidate_id = candidate.candidate_id.clone();
    let plan = network::Network::plan(i, &policy).map_err(|_| ActivationError::Unavailable)?;
    Ok(PreparedPlan {
        foreign_nft_sha256: observed.foreign_nft_sha256,
        plan_id: uuid::Uuid::new_v4().to_string(),
        expires_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ActivationError::Unavailable)?
            .as_secs()
            .checked_add(300)
            .ok_or(ActivationError::Unavailable)?,
        profile_id: input.profile_id,
        revision: input.revision,
        candidate_id: candidate.candidate_id,
        overlay,
        explicit: input.explicit,
        manual_candidate_id: input.manual_candidate_id,
        dns_facts: observed.dns,
        network: plan,
        previous: input.previous,
    })
}
