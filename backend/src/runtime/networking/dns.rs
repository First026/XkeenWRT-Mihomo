//! Translate the single validated DNS plan into the exact managed overlay.
use crate::network::dns::DnsPlan;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsOverlayError;
impl std::fmt::Display for DnsOverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unsupported DNS plan")
    }
}
impl std::error::Error for DnsOverlayError {}

pub fn overlay_from_dns_plan(
    lan: &str, lan_ip: Ipv4Addr, selected: Ipv4Addr, dns: &DnsPlan,
) -> Result<profile_policy::NetworkOverlay, DnsOverlayError> {
    overlay_from_dns_plan_inner(lan, lan_ip, selected, dns).map_err(|_| DnsOverlayError)
}

fn overlay_from_dns_plan_inner(
    lan: &str, lan_ip: Ipv4Addr, selected: Ipv4Addr, dns: &DnsPlan,
) -> Result<profile_policy::NetworkOverlay, ()> {
    // The overlay deliberately keeps Mihomo behind the existing dnsmasq
    // listener. The dnsmasq forwarding chain (including custom #ports and
    // split zones) is carried by DnsPlan and is never rewritten here.
    let nameservers = dns
        .nameservers
        .iter()
        .map(|s| {
            let addr: SocketAddr = s.parse().map_err(|_| ())?;
            if addr != "127.0.0.1:53".parse().map_err(|_| ())? {
                return Err(());
            }
            Ok(addr.ip())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if dns.upstreams.is_empty()
        || (dns.upstreams.iter().any(|value| {
            value
                .rsplit_once('#')
                .and_then(|(host, _)| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|address| address.is_loopback())
        }) && dns.verified_loopback_chain_sha256.is_none())
        || dns.upstreams.iter().any(|value| {
            let endpoint = value
                .rsplit_once('#')
                .and_then(|(host, port)| Some(SocketAddr::new(host.parse().ok()?, port.parse().ok()?)))
                .or_else(|| value.parse::<SocketAddr>().ok());
            endpoint.is_none_or(|v| v.port() == 0 || (v.ip().is_loopback() && [53, 1053].contains(&v.port())))
        })
    {
        return Err(());
    }
    if dns.local_policy.values().any(|target| target != "127.0.0.1:53") {
        return Err(());
    }
    let overlay = profile_policy::NetworkOverlay {
        lan_ifname: lan.to_owned(),
        lan_ipv4: lan_ip,
        selected_ipv4: selected,
        tproxy_port: 7893,
        dns_port: 1053,
        nameservers,
        bootstrap: dns.bootstrap.clone(),
        local_zones: dns.local_policy.keys().cloned().collect(),
    };
    overlay.dns().map_err(|_| ())?;
    Ok(overlay)
}
