//! DNS overlay derived from the observed dnsmasq instance. This never edits UCI.
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsInventory {
    pub dnsmasq_instances: usize,
    pub incompatible_manager: bool,
    pub local_names: Vec<String>,
    pub upstreams: Vec<String>,
    pub split_upstreams: Vec<(String, Option<String>)>,
    pub verified_loopback_chain_sha256: Option<String>,
    pub bootstrap: Vec<IpAddr>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPlan {
    pub local_policy: BTreeMap<String, String>,
    pub nameservers: Vec<String>,
    /// Original dnsmasq forwarding endpoints, retained for exact preflight and
    /// evidence. Mihomo still queries the existing dnsmasq listener at :53.
    pub upstreams: Vec<String>,
    pub split_upstreams: Vec<(String, Option<String>)>,
    pub verified_loopback_chain_sha256: Option<String>,
    pub bootstrap: Vec<IpAddr>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum DnsError {
    Unsupported,
    Invalid,
}
impl DnsPlan {
    pub fn new(inventory: &DnsInventory) -> Result<Self, DnsError> {
        if inventory.dnsmasq_instances != 1 || inventory.incompatible_manager {
            return Err(DnsError::Unsupported);
        }
        if inventory.local_names.is_empty() || inventory.bootstrap.is_empty() || inventory.upstreams.is_empty() {
            return Err(DnsError::Invalid);
        }
        if !inventory
            .local_names
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"+.-_".contains(&c)))
        {
            return Err(DnsError::Invalid);
        }
        fn endpoint(value: &str) -> Option<std::net::SocketAddr> {
            if let Ok(address) = value.parse::<std::net::SocketAddr>() {
                return (address.port() != 0).then_some(address);
            }
            let (host, port) = match value.rsplit_once('#') {
                Some((host, port)) => (host, port.parse::<u16>().ok()?),
                None => (value, 53),
            };
            let address = host.parse::<IpAddr>().ok()?;
            (port != 0).then_some(std::net::SocketAddr::new(address, port))
        }
        let mut upstreams = inventory.upstreams.clone();
        upstreams.sort();
        upstreams.dedup();
        let has_loopback = upstreams
            .iter()
            .filter_map(|value| endpoint(value))
            .any(|value| value.ip().is_loopback())
            || inventory
                .split_upstreams
                .iter()
                .filter_map(|(_, target)| target.as_deref())
                .filter_map(endpoint)
                .any(|value| value.ip().is_loopback());
        if upstreams.len() > 8
            || (has_loopback
                && !inventory
                    .verified_loopback_chain_sha256
                    .as_deref()
                    .is_some_and(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())))
            || upstreams.iter().any(|value| {
                endpoint(value).is_none_or(|endpoint| {
                    endpoint.ip().is_unspecified()
                        || endpoint.ip().is_multicast()
                        || (endpoint.ip().is_loopback() && [53, 1053].contains(&endpoint.port()))
                })
            })
            || inventory.split_upstreams.len() > 256
            || inventory.split_upstreams.iter().any(|(zone, target)| {
                zone.is_empty()
                    || zone.len() > 253
                    || !zone.bytes().all(|c| c.is_ascii_alphanumeric() || b"+.-_".contains(&c))
                    || target.as_deref().is_some_and(|value| {
                        endpoint(value).is_none_or(|endpoint| {
                            endpoint.ip().is_unspecified()
                                || endpoint.ip().is_multicast()
                                || (endpoint.ip().is_loopback() && [53, 1053].contains(&endpoint.port()))
                        })
                    })
            })
        {
            return Err(DnsError::Invalid);
        }
        let mut split_upstreams = inventory.split_upstreams.clone();
        split_upstreams.sort();
        split_upstreams.dedup();
        Ok(Self {
            local_policy: inventory
                .local_names
                .iter()
                .map(|name| (name.clone(), "127.0.0.1:53".into()))
                .collect(),
            nameservers: vec!["127.0.0.1:53".into()],
            upstreams,
            split_upstreams,
            verified_loopback_chain_sha256: inventory.verified_loopback_chain_sha256.clone(),
            bootstrap: inventory.bootstrap.clone(),
        })
    }
}
