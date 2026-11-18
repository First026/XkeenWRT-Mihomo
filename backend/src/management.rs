//! Discover a narrowly scoped OpenWrt management listener. Ambiguous topology fails to loopback.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::{fd::AsRawFd, raw::c_void},
    ptr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}
impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Option<Self> {
        let max = if network.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { network, prefix })
    }
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let n = u32::from_be_bytes(network.octets());
                let a = u32::from_be_bytes(address.octets());
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                n & mask == a & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let n = u128::from_be_bytes(network.octets());
                let a = u128::from_be_bytes(address.octets());
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                n & mask == a & mask
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedAccess {
    interface: Option<String>,
    sources: Vec<Cidr>,
    overlay_address: Option<Ipv4Addr>,
}
impl TrustedAccess {
    pub fn loopback() -> Self {
        Self {
            interface: None,
            sources: vec![Cidr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8).expect("valid loopback range")],
            overlay_address: None,
        }
    }
    pub fn allows(&self, address: IpAddr) -> bool {
        self.sources.iter().any(|cidr| cidr.contains(address)) && self.boundary_current()
    }
    pub fn boundary_current(&self) -> bool {
        self.overlay_address
            .is_none_or(|expected| discover_tailscale().is_some_and(|b| b.address.ip() == IpAddr::V4(expected)))
    }
    pub fn is_overlay(&self) -> bool {
        self.overlay_address.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementBoundary {
    pub address: SocketAddr,
    pub access: TrustedAccess,
}
impl ManagementBoundary {
    pub fn loopback() -> Self {
        Self {
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 1000)),
            access: TrustedAccess::loopback(),
        }
    }
    /// Bind the listener to the discovered LAN device as well as its assigned address.
    pub fn bind_listener(&self) -> io::Result<tokio::net::TcpListener> {
        let socket = if self.address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        if let Some(interface) = &self.access.interface {
            bind_to_device(socket.as_raw_fd(), interface)?;
        }
        socket.set_reuseaddr(true)?;
        socket.bind(self.address)?;
        socket.listen(128)
    }
}

fn bind_to_device(fd: std::os::fd::RawFd, interface: &str) -> io::Result<()> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid management interface",
        ));
    }
    let name = CString::new(interface).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    let status = unsafe {
        nix::libc::setsockopt(
            fd,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_BINDTODEVICE,
            name.as_ptr().cast::<c_void>(),
            name.as_bytes_with_nul().len() as nix::libc::socklen_t,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Default, Debug)]
struct UciSection {
    kind: String,
    name: String,
    values: BTreeMap<String, Vec<String>>,
}
// UCI permits anonymous sections and quoted or bare tokens. Parse data only;
// never evaluate it as shell code. Malformed or ambiguous input fails closed.
fn uci_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for ch in line.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_some() {
            word.push(ch);
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            started = true;
        } else if ch == '#' {
            break;
        } else if ch.is_ascii_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else if ch.is_control() {
            return None;
        } else {
            word.push(ch);
            started = true;
        }
        if word.len() > 4096 || words.len() > 3 {
            return None;
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}
fn parse_uci(text: &str) -> Option<Vec<UciSection>> {
    if text.len() > 64 * 1024 {
        return None;
    }
    let mut sections: Vec<UciSection> = Vec::new();
    for raw in text.lines() {
        let words = uci_words(raw)?;
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        match words.as_slice() {
            [] => (),
            ["config", kind] | ["config", kind, _] if !kind.is_empty() => {
                sections.push(UciSection {
                    kind: (*kind).into(),
                    name: words.get(2).copied().unwrap_or("").into(),
                    values: BTreeMap::new(),
                });
            }
            ["option" | "list", key, value] if !key.is_empty() => {
                sections
                    .last_mut()?
                    .values
                    .entry((*key).into())
                    .or_default()
                    .push((*value).into());
            }
            _ => return None,
        }
    }
    Some(sections)
}
fn one_value<'a>(section: &'a UciSection, key: &str) -> Option<&'a str> {
    let values = section.values.get(key)?;
    (values.len() == 1).then(|| values[0].as_str())
}
fn network_to_device(network: &str, contents: &str) -> Option<String> {
    let sections = parse_uci(contents)?;
    let interface = sections
        .iter()
        .find(|section| section.kind == "interface" && section.name == network)?;
    let device = one_value(interface, "device").or_else(|| one_value(interface, "ifname"))?;
    if device.contains(' ') || device.contains(',') || device.len() > 15 {
        return None;
    }
    Some(device.to_owned())
}
fn lan_zone_is_isolated(network: &str, contents: &str) -> Option<()> {
    let sections = parse_uci(contents)?;
    let mut lan_zone_found = false;
    for section in sections.iter().filter(|section| section.kind == "zone") {
        let name = one_value(section, "name")?;
        let networks: BTreeSet<&str> = section
            .values
            .get("network")
            .map(|values| values.iter().flat_map(|value| value.split_ascii_whitespace()).collect())
            .unwrap_or_default();
        if name == "lan" {
            if lan_zone_found
                || !networks.contains(network)
                || networks.iter().any(|n| *n == "wan" || n.contains("guest"))
                || one_value(section, "input")? != "ACCEPT"
            {
                return None;
            }
            lan_zone_found = true;
        }
        if name != "lan" && networks.contains(network) {
            return None;
        }
    }
    lan_zone_found.then_some(())
}

fn local_addresses(interface: &str, overlay: bool) -> io::Result<Vec<(IpAddr, u8)>> {
    let interface =
        CString::new(interface).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad interface"))?;
    let mut head = ptr::null_mut();
    if unsafe { nix::libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut result = Vec::new();
    let mut entry = head;
    while !entry.is_null() {
        let item = unsafe { &*entry };
        let same_name =
            !item.ifa_name.is_null() && unsafe { CStr::from_ptr(item.ifa_name) }.to_bytes() == interface.as_bytes();
        if same_name && !item.ifa_addr.is_null() && !item.ifa_netmask.is_null() {
            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            if family == nix::libc::AF_INET {
                let address = unsafe { &*(item.ifa_addr.cast::<nix::libc::sockaddr_in>()) };
                let mask = unsafe { &*(item.ifa_netmask.cast::<nix::libc::sockaddr_in>()) };
                let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
                let mask = u32::from_be_bytes(mask.sin_addr.s_addr.to_ne_bytes());
                let prefix = mask.leading_ones() as u8;
                let contiguous = if prefix == 0 {
                    mask == 0
                } else {
                    mask == u32::MAX << (32 - prefix)
                };
                let permitted = if overlay {
                    tailscale_ipv4(ip) && prefix >= 10
                } else {
                    ip.is_private() && !ip.is_loopback() && prefix >= 8
                };
                if contiguous && permitted {
                    result.push((IpAddr::V4(ip), prefix));
                }
            } else if family == nix::libc::AF_INET6 {
                let address = unsafe { &*(item.ifa_addr.cast::<nix::libc::sockaddr_in6>()) };
                let mask = unsafe { &*(item.ifa_netmask.cast::<nix::libc::sockaddr_in6>()) };
                let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
                let mask = u128::from_be_bytes(mask.sin6_addr.s6_addr);
                let prefix = mask.leading_ones() as u8;
                let contiguous = if prefix == 0 {
                    mask == 0
                } else {
                    mask == u128::MAX << (128 - prefix)
                };
                let ula = ip.segments()[0] & 0xfe00 == 0xfc00;
                if contiguous && ula && prefix >= 32 {
                    result.push((IpAddr::V6(ip), prefix));
                }
            }
        }
        entry = item.ifa_next;
    }
    unsafe { nix::libc::freeifaddrs(head) };
    result.sort_by_key(|(ip, _)| if ip.is_ipv4() { 0 } else { 1 });
    result.dedup();
    Ok(result)
}

/// Discover the default LAN zone. Missing, guest-shared, or ambiguous configuration returns `None`.
pub fn discover() -> Option<ManagementBoundary> {
    let network = std::fs::read_to_string("/etc/config/network").ok()?;
    let firewall = std::fs::read_to_string("/etc/config/firewall").ok()?;
    let device = network_to_device("lan", &network)?;
    lan_zone_is_isolated("lan", &firewall)?;
    let mut addresses = local_addresses(&device, false).ok()?;
    let (address, prefix) = addresses.drain(..).next()?;
    Some(ManagementBoundary {
        address: SocketAddr::new(address, 1000),
        access: TrustedAccess {
            interface: Some(device),
            sources: vec![Cidr::new(address, prefix)?],
            overlay_address: None,
        },
    })
}

fn tailscale_ipv4(address: Ipv4Addr) -> bool {
    address.octets()[0] == 100 && address.octets()[1] & 0xc0 == 0x40
}
fn overlay_admin_config(network: &str, firewall: &str) -> Option<()> {
    if network_to_device("tailscale", network)?.as_str() != "tailscale0" {
        return None;
    }
    lan_zone_is_isolated("lan", firewall)?;
    lan_zone_is_isolated("tailscale", firewall)?;
    // An alias assigned to a different zone is ambiguous even when the named
    // tailscale network itself belongs to LAN.
    let interfaces = parse_uci(network)?;
    let aliases = interfaces
        .iter()
        .filter(|s| {
            s.kind == "interface" && one_value(s, "device").or_else(|| one_value(s, "ifname")) == Some("tailscale0")
        })
        .count();
    if aliases != 1 {
        return None;
    }
    for zone in parse_uci(firewall)?.iter().filter(|s| s.kind == "zone") {
        if one_value(zone, "name")? == "lan" {
            continue;
        }
        for device in zone
            .values
            .get("device")
            .into_iter()
            .flatten()
            .flat_map(|s| s.split_ascii_whitespace())
        {
            let matches = if let Some(prefix) = device.strip_suffix('+').or_else(|| device.strip_suffix('*')) {
                "tailscale0".starts_with(prefix)
            } else {
                device == "tailscale0" || device == "@tailscale" || device.contains(['*', '+'])
            };
            if matches {
                return None;
            }
        }
    }
    Some(())
}
/// Optional second management socket. A real kernel address and an explicit
/// unambiguous admin-zone assignment are both required; no wildcard is bound.
pub fn discover_tailscale() -> Option<ManagementBoundary> {
    let network = std::fs::read_to_string("/etc/config/network").ok()?;
    let firewall = std::fs::read_to_string("/etc/config/firewall").ok()?;
    overlay_admin_config(&network, &firewall)?;
    let addresses = local_addresses("tailscale0", true).ok()?;
    let ips: Vec<_> = addresses
        .into_iter()
        .filter_map(|(a, _)| match a {
            IpAddr::V4(ip) if tailscale_ipv4(ip) => Some(ip),
            _ => None,
        })
        .collect();
    let [address] = ips.as_slice() else {
        return None;
    };
    Some(ManagementBoundary {
        address: SocketAddr::from((*address, 1000)),
        access: TrustedAccess {
            interface: Some("tailscale0".into()),
            sources: vec![Cidr::new("100.64.0.0".parse().ok()?, 10)?],
            overlay_address: Some(*address),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_policy_matches_only_same_family_prefix() {
        let cidr = Cidr::new("192.168.10.1".parse().unwrap(), 24).unwrap();
        assert!(cidr.contains("192.168.10.220".parse().unwrap()));
        assert!(!cidr.contains("192.168.11.2".parse().unwrap()));
        assert!(!cidr.contains("fd00::1".parse().unwrap()));
    }

    #[test]
    fn discovery_requires_one_admin_lan_zone_without_guest_networks() {
        let network = "config interface 'lan'\n option device 'br-lan'\n";
        let firewall = "config zone 'lan'\n option name 'lan'\n option input 'ACCEPT'\n list network 'lan'\nconfig zone 'wan'\n option name 'wan'\n list network 'wan'\nconfig zone 'guest'\n option name 'guest'\n list network 'guest'\n";
        assert_eq!(network_to_device("lan", network).as_deref(), Some("br-lan"));
        assert!(lan_zone_is_isolated("lan", firewall).is_some());
        let shared = firewall.replace("list network 'guest'", "list network 'lan'");
        assert!(lan_zone_is_isolated("lan", &shared).is_none());
    }

    #[test]
    fn stock_uci_and_r2_admin_zone_are_supported() {
        let network = "config device\n\toption name 'br-lan'\n\toption type 'bridge'\n\tlist ports 'eth1'\nconfig interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n";
        let firewall = "config defaults\n\toption input 'REJECT'\nconfig zone\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'tailscale'\n\toption input 'ACCEPT'\nconfig zone\n\toption name 'wan'\n\tlist network 'wan'\n";
        assert_eq!(network_to_device("lan", network).as_deref(), Some("br-lan"));
        assert!(lan_zone_is_isolated("lan", firewall).is_some());
        assert!(lan_zone_is_isolated("lan", &firewall.replace("'tailscale'", "'guest'")).is_none());
        assert!(lan_zone_is_isolated("lan", &firewall.replace("'wan'\n", "'lan'\n")).is_none());
    }

    #[test]
    fn overlay_panel_requires_explicit_admin_network_and_rejects_device_aliases() {
        let network = "config interface 'lan'\n option device 'br-lan'\nconfig interface 'tailscale'\n option device 'tailscale0'\n";
        let firewall = "config zone\n option name 'lan'\n option input 'ACCEPT'\n list network 'lan'\n list network 'tailscale'\nconfig zone\n option name 'wan'\n list network 'wan'\n";
        assert!(overlay_admin_config(network, firewall).is_some());
        assert!(overlay_admin_config(network, &firewall.replace(" list network 'tailscale'\n", "")).is_none());
        assert!(overlay_admin_config(network, &format!("{firewall} list network 'tailscale'\n")).is_none());
        assert!(overlay_admin_config(network, &format!("{firewall} list device 'tailscale+'\n")).is_none());
        assert!(
            overlay_admin_config(
                &format!("{network}config interface 'guest'\n option device 'tailscale0'\n"),
                firewall
            )
            .is_none()
        );
        assert!(tailscale_ipv4("100.64.0.1".parse().unwrap()));
        assert!(tailscale_ipv4("100.127.255.254".parse().unwrap()));
        assert!(!tailscale_ipv4("100.128.0.1".parse().unwrap()));
        assert!(!tailscale_ipv4("10.77.0.2".parse().unwrap()));
    }
}
