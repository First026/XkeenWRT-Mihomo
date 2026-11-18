//! Native bounded nfnetlink. Exact conntrack deletion never accepts a partial
//! selector or CTA_FILTER. Hardware teardown has no supported completion gate.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
fn fail() -> io::Error {
    io::Error::other("flow offload prerequisite unavailable")
}
fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn attrs(bytes: &[u8]) -> io::Result<BTreeMap<u16, &[u8]>> {
    let mut result = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(fail());
        }
        let n =
            u16::from_ne_bytes(bytes[offset..offset + 2].try_into().map_err(|_| fail())?) as usize;
        let typ = u16::from_ne_bytes(
            bytes[offset + 2..offset + 4]
                .try_into()
                .map_err(|_| fail())?,
        ) & 0x3fff;
        if n < 4
            || offset + align(n) > bytes.len()
            || result.insert(typ, &bytes[offset + 4..offset + n]).is_some()
        {
            return Err(fail());
        }
        offset += align(n);
    }
    Ok(result)
}
fn attr(typ: u16, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len: u16 = (payload.len() + 4).try_into().map_err(|_| fail())?;
    out.extend(len.to_ne_bytes());
    out.extend(typ.to_ne_bytes());
    out.extend(payload);
    out.resize(align(out.len()), 0);
    Ok(())
}
fn be32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| fail())?))
}
fn name(bytes: &[u8]) -> io::Result<String> {
    let (last, value) = bytes.split_last().ok_or_else(fail)?;
    let s = std::str::from_utf8(value).map_err(|_| fail())?;
    if *last != 0
        || s.is_empty()
        || s.len() > 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(fail());
    }
    Ok(s.into())
}
struct Netlink {
    fd: OwnedFd,
    seq: u32,
    port: u32,
    deadline: Instant,
}
impl Netlink {
    fn new(deadline: Instant) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        if unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut len = std::mem::size_of_val(&address) as u32;
        if unsafe {
            libc::getsockname(
                raw,
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            seq: 0,
            port: address.nl_pid,
            deadline,
        })
    }
    fn request(
        &mut self,
        typ: u16,
        flags: u16,
        family: u8,
        payload: &[u8],
    ) -> io::Result<Vec<Vec<u8>>> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "flow transition deadline",
            ));
        }
        self.seq = self.seq.checked_add(1).ok_or_else(fail)?;
        let mut bytes = Vec::new();
        bytes.extend(((20 + payload.len()) as u32).to_ne_bytes());
        bytes.extend(typ.to_ne_bytes());
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(self.seq.to_ne_bytes());
        bytes.extend(self.port.to_ne_bytes());
        bytes.extend([family, 0, 0, 0]);
        bytes.extend(payload);
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        };
        if sent != bytes.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let dump = flags & 0x300 != 0;
        let mut rows = Vec::new();
        let mut total = 0usize;
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "flow transition deadline",
                ));
            }
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(3000) as i32) };
            if ready <= 0 || poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(fail());
            }
            let mut buffer = vec![0u8; 65536];
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut sender_len = std::mem::size_of_val(&sender) as u32;
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_TRUNC,
                    (&mut sender as *mut libc::sockaddr_nl).cast(),
                    &mut sender_len,
                )
            };
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            if received as usize > buffer.len() || sender.nl_pid != 0 || sender.nl_groups != 0 {
                return Err(fail());
            }
            buffer.truncate(received as usize);
            total = total.saturating_add(buffer.len());
            if total > 8 * 1024 * 1024 || rows.len() > 16384 {
                return Err(fail());
            }
            let mut offset = 0;
            while offset < buffer.len() {
                if buffer.len() - offset < 16 {
                    return Err(fail());
                }
                let h = &buffer[offset..];
                let n = u32::from_ne_bytes(h[0..4].try_into().map_err(|_| fail())?) as usize;
                let kind = u16::from_ne_bytes(h[4..6].try_into().map_err(|_| fail())?);
                let fl = u16::from_ne_bytes(h[6..8].try_into().map_err(|_| fail())?);
                let seq = u32::from_ne_bytes(h[8..12].try_into().map_err(|_| fail())?);
                let port = u32::from_ne_bytes(h[12..16].try_into().map_err(|_| fail())?);
                if n < 16
                    || offset + align(n) > buffer.len()
                    || seq != self.seq
                    || port != self.port
                    || fl & 0x10 != 0
                {
                    return Err(fail());
                }
                let body = &h[16..n];
                if kind == 2 || kind == 3 {
                    if body.len() < 4 {
                        return Err(fail());
                    }
                    let code = i32::from_ne_bytes(body[..4].try_into().map_err(|_| fail())?);
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    if kind == 3 || !dump {
                        return Ok(rows);
                    }
                } else if kind == 4 {
                    return Err(fail());
                } else {
                    if body.len() < 4 {
                        return Err(fail());
                    }
                    rows.push(body.to_vec());
                }
                offset += align(n);
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTable {
    pub family: u8,
    pub table: String,
    pub name: String,
    pub flags: u32,
    pub hook: u32,
    pub priority: i32,
    pub devices: Vec<String>,
    pub handle: u64,
}
fn flow_row(row: &[u8]) -> io::Result<FlowTable> {
    let a = attrs(&row[4..])?;
    let hook = attrs(a.get(&3).ok_or_else(fail)?)?;
    // NLA device entries may repeat their type. Parse this nested array separately.
    let raw = *hook.get(&3).ok_or_else(fail)?;
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        if raw.len() - pos < 4 {
            return Err(fail());
        }
        let n = u16::from_ne_bytes(raw[pos..pos + 2].try_into().map_err(|_| fail())?) as usize;
        if n < 4 || pos + align(n) > raw.len() {
            return Err(fail());
        }
        names.push(name(&raw[pos + 4..pos + n])?);
        pos += align(n);
    }
    names.sort();
    names.dedup();
    Ok(FlowTable {
        family: row[0],
        table: name(a.get(&1).ok_or_else(fail)?)?,
        name: name(a.get(&2).ok_or_else(fail)?)?,
        flags: a.get(&7).map(|x| be32(x)).transpose()?.unwrap_or(0),
        hook: be32(hook.get(&1).ok_or_else(fail)?)?,
        priority: be32(hook.get(&2).ok_or_else(fail)?)? as i32,
        devices: names,
        handle: u64::from_be_bytes(
            (*a.get(&5).ok_or_else(fail)?)
                .try_into()
                .map_err(|_| fail())?,
        ),
    })
}
fn flowtables_until(deadline: Instant) -> io::Result<Vec<FlowTable>> {
    let mut socket = Netlink::new(deadline)?;
    let mut tables = socket
        .request((10 << 8) | 23, 0x301, 0, &[])?
        .iter()
        .map(|row| flow_row(row))
        .collect::<io::Result<Vec<_>>>()?;
    if tables.len() > 64 {
        return Err(fail());
    }
    tables.sort_by(|a, b| (&a.family, &a.table, &a.name).cmp(&(&b.family, &b.table, &b.name)));
    Ok(tables)
}
pub fn flowtables() -> io::Result<Vec<FlowTable>> {
    flowtables_until(Instant::now() + Duration::from_secs(3))
}
fn generation(deadline: Instant) -> io::Result<u32> {
    let mut socket = Netlink::new(deadline)?;
    let rows = socket.request((10 << 8) | 16, 5, 0, &[])?;
    let [row] = rows.as_slice() else {
        return Err(fail());
    };
    let a = attrs(&row[4..])?;
    be32(a.get(&1).ok_or_else(fail)?)
}
fn coherent<T>(
    deadline: Instant,
    mut observe_generation: impl FnMut() -> io::Result<u32>,
    mut read: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    for _ in 0..3 {
        if Instant::now() >= deadline {
            return Err(fail());
        }
        let before = observe_generation()?;
        let snapshot = read()?;
        let after = observe_generation()?;
        if before == after {
            return Ok(snapshot);
        }
    }
    Err(io::Error::other(
        "nft generation changed during bounded inventory",
    ))
}
/// GETGEN brackets both nft JSON and native flow flags; mixed generations are
/// retried with a fixed total budget, never treated as an authoritative view.
pub fn capture_nft(
    mut read_nft: impl FnMut() -> io::Result<Vec<u8>>,
) -> io::Result<(Vec<u8>, Vec<FlowTable>)> {
    let deadline = Instant::now() + Duration::from_secs(9);
    coherent(
        deadline,
        || generation(deadline),
        || {
            let nft = read_nft()?;
            let tables = flowtables_until(deadline)?;
            verify_metadata(&nft, &tables)?;
            Ok((nft, tables))
        },
    )
}
/// Kernel flags are required even when old nft JSON omits them. A HW flag is
/// a prerequisite gate, not a claim that PPE is currently processing packets.
pub fn verify_tables(nft: &[u8], kernel: &[FlowTable]) -> io::Result<()> {
    verify_metadata(nft, kernel)?;
    if kernel.iter().any(|k| k.flags & !2 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hardware flow offload transition is unverified",
        ));
    }
    Ok(())
}
/// Prove disjoint ingress only from kernel bridge membership, never from the
/// absence of the L3 bridge name in a flowtable's physical device array.
pub fn affects_lan(table: &FlowTable, links: &[u8], lan: &str) -> io::Result<bool> {
    let root: Value = serde_json::from_slice(links).map_err(|_| fail())?;
    let links = root.as_array().ok_or_else(fail)?;
    let index = links
        .iter()
        .find(|l| l["ifname"] == lan)
        .and_then(|l| l["ifindex"].as_u64())
        .ok_or_else(fail)?;
    let mut ingress = BTreeSet::from([lan.to_owned()]);
    for l in links {
        if l["master"] == lan || l["master"].as_u64() == Some(index) {
            ingress.insert(l["ifname"].as_str().ok_or_else(fail)?.to_owned());
        }
    }
    for dev in &table.devices {
        if ingress.contains(dev) || !links.iter().any(|l| l["ifname"] == dev.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn transition_required(tables: &[FlowTable], links: &[u8], lan: &str) -> io::Result<bool> {
    for table in tables {
        if affects_lan(table, links, lan)? {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn verify_for_lan(nft: &[u8], kernel: &[FlowTable], links: &[u8], lan: &str) -> io::Result<()> {
    verify_metadata(nft, kernel)?;
    for table in kernel {
        if affects_lan(table, links, lan)? && table.flags & !2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hardware flow offload transition is unverified",
            ));
        }
    }
    Ok(())
}
pub fn verify_metadata(nft: &[u8], kernel: &[FlowTable]) -> io::Result<()> {
    let root: Value = serde_json::from_slice(nft).map_err(|_| fail())?;
    let items = root["nftables"].as_array().ok_or_else(fail)?;
    let flows: Vec<_> = items.iter().filter_map(|i| i.get("flowtable")).collect();
    if flows.len() != kernel.len() {
        return Err(fail());
    }
    for f in flows {
        let family = match f["family"].as_str() {
            Some("inet") => 1,
            Some("ip") => 2,
            Some("ip6") => 10,
            _ => return Err(fail()),
        };
        let matches: Vec<_> = kernel
            .iter()
            .filter(|k| k.family == family && f["table"] == k.table && f["name"] == k.name)
            .collect();
        let [k] = matches.as_slice() else {
            return Err(fail());
        };
        let mut devices: Vec<_> = f["dev"]
            .as_array()
            .or_else(|| f["devices"].as_array())
            .ok_or_else(fail)?
            .iter()
            .map(|d| d.as_str().map(str::to_owned).ok_or_else(fail))
            .collect::<io::Result<_>>()?;
        devices.sort();
        devices.dedup();
        if devices != k.devices
            || f["hook"] != "ingress"
            || k.hook != 0
            || f["prio"].as_i64() != Some(k.priority as i64)
            || f["handle"].as_u64().is_some_and(|h| h != k.handle)
        {
            return Err(fail());
        }
    }
    Ok(())
}
fn ipv6_candidate(row: &[u8]) -> io::Result<bool> {
    if row.len() < 4 {
        return Err(fail());
    }
    if row[0] != libc::AF_INET6 as u8 {
        return Ok(false);
    }
    let a = attrs(&row[4..])?;
    let status = be32(a.get(&3).ok_or_else(fail)?)?;
    Ok(status & ((1 << 14) | (1 << 15)) != 0 && status & (1 << 9) == 0)
}
/// Aggregate only; the generic adapter cannot prove/mutate old IPv6 offload.
pub fn ipv6_offloaded() -> io::Result<usize> {
    let mut socket = Netlink::new(Instant::now() + Duration::from_secs(3))?;
    let rows = socket.request((1 << 8) | 1, 0x301, 0, &[])?;
    rows.iter()
        .try_fold(0usize, |n, row| Ok(n + usize::from(ipv6_candidate(row)?)))
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub family: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub zone: u16,
    pub status: u32,
    tuple: Vec<u8>,
    id: [u8; 4],
}
impl Entry {
    fn parse(row: &[u8]) -> io::Result<Option<Self>> {
        if row[0] != libc::AF_INET as u8 {
            return Ok(None);
        }
        let a = attrs(&row[4..])?;
        let tuple = *a.get(&1).ok_or_else(fail)?;
        let t = attrs(tuple)?;
        let ip = attrs(t.get(&1).ok_or_else(fail)?)?;
        let p = attrs(t.get(&2).ok_or_else(fail)?)?;
        let proto = *p.get(&1).filter(|p| p.len() == 1).ok_or_else(fail)?;
        if ![6, 17].contains(&proto[0]) {
            return Ok(None);
        }
        let zone = a
            .get(&18)
            .or_else(|| t.get(&3))
            .map(|z| u16::from_be_bytes((*z).try_into().unwrap_or([255, 255])))
            .unwrap_or(0);
        if a.get(&18).is_some_and(|z| z.len() != 2) || t.get(&3).is_some_and(|z| z.len() != 2) {
            return Err(fail());
        }
        Ok(Some(Self {
            family: row[0],
            source: Ipv4Addr::from(
                <[u8; 4]>::try_from(*ip.get(&1).ok_or_else(fail)?).map_err(|_| fail())?,
            ),
            destination: Ipv4Addr::from(
                <[u8; 4]>::try_from(*ip.get(&2).ok_or_else(fail)?).map_err(|_| fail())?,
            ),
            protocol: proto[0],
            source_port: u16::from_be_bytes(
                (*p.get(&2).ok_or_else(fail)?)
                    .try_into()
                    .map_err(|_| fail())?,
            ),
            destination_port: u16::from_be_bytes(
                (*p.get(&3).ok_or_else(fail)?)
                    .try_into()
                    .map_err(|_| fail())?,
            ),
            zone,
            status: be32(a.get(&3).ok_or_else(fail)?)?,
            tuple: tuple.to_vec(),
            id: (*a.get(&12).ok_or_else(fail)?)
                .try_into()
                .map_err(|_| fail())?,
        }))
    }
    fn delete_payload(&self) -> io::Result<Vec<u8>> {
        // Reparse the complete original tuple to make partial selectors unrepresentable.
        let a = attrs(&self.tuple)?;
        let ip = attrs(a.get(&1).ok_or_else(fail)?)?;
        let p = attrs(a.get(&2).ok_or_else(fail)?)?;
        if ip.get(&1).is_none_or(|v| v.len() != 4)
            || ip.get(&2).is_none_or(|v| v.len() != 4)
            || p.get(&1).is_none_or(|v| v.len() != 1)
            || p.get(&2).is_none_or(|v| v.len() != 2)
            || p.get(&3).is_none_or(|v| v.len() != 2)
        {
            return Err(fail());
        }
        let mut out = Vec::new();
        attr(0x8001, &self.tuple, &mut out)?;
        attr(18, &self.zone.to_be_bytes(), &mut out)?;
        attr(12, &self.id, &mut out)?;
        Ok(out)
    }
}
fn contains(cidr: &str, ip: Ipv4Addr) -> bool {
    cidr.split_once('/')
        .and_then(|(a, p)| Some((a.parse::<Ipv4Addr>().ok()?, p.parse::<u32>().ok()?)))
        .is_some_and(|(a, p)| {
            p <= 32
                && (u32::from(a) ^ u32::from(ip)) & if p == 0 { 0 } else { u32::MAX << (32 - p) }
                    == 0
        })
}
/// Shared preflight/transition proof, independent of any application mutation.
pub fn scope_admissible(
    lan: &str,
    cidr: &str,
    addresses: &[u8],
    links: &[u8],
    nft: &[u8],
    rules4: &[u8],
    routes6: &[u8],
) -> io::Result<BTreeSet<Ipv4Addr>> {
    let facts = crate::evidence::inventory::address_facts(addresses, lan).map_err(|_| fail())?;
    let all: Value = serde_json::from_slice(addresses).map_err(|_| fail())?;
    let list = all.as_array().ok_or_else(fail)?;
    let mut router_locals = BTreeSet::new();
    for interface in list {
        for a in interface["addr_info"].as_array().ok_or_else(fail)? {
            if a["family"] != "inet" {
                continue;
            }
            let ip = a["local"]
                .as_str()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
                .ok_or_else(fail)?;
            router_locals.insert(ip);
            if interface["ifname"] != lan && contains(cidr, ip) {
                return Err(fail());
            }
        }
    }
    if facts.lan_cidrs.len() != 1
        || crate::lan_network(&facts.lan_cidrs[0]).as_deref() != Some(cidr)
    {
        return Err(fail());
    }
    let links: Value = serde_json::from_slice(links).map_err(|_| fail())?;
    let links = links.as_array().ok_or_else(fail)?;
    if !links.iter().any(|l| l["ifname"] == lan) {
        return Err(fail());
    }
    // Other live L3 ingresses must have disjoint configured IPv4 source networks.
    for interface in list
        .iter()
        .filter(|i| i["ifname"] != lan && i["ifname"] != "lo")
    {
        for a in interface["addr_info"]
            .as_array()
            .ok_or_else(fail)?
            .iter()
            .filter(|a| a["family"] == "inet")
        {
            let ip = a["local"]
                .as_str()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
                .ok_or_else(fail)?;
            let prefix = a["prefixlen"].as_u64().ok_or_else(fail)?;
            if prefix > 32
                || contains(cidr, ip)
                || cidr
                    .split_once('/')
                    .and_then(|(a, _)| a.parse::<Ipv4Addr>().ok())
                    .is_some_and(|lan_base| contains(&format!("{ip}/{prefix}"), lan_base))
            {
                return Err(fail());
            }
        }
    }
    let rules: Value = serde_json::from_slice(rules4).map_err(|_| fail())?;
    if rules.as_array().ok_or_else(fail)?.iter().any(|r| {
        r["src"]
            .as_str()
            .is_some_and(|s| s != "all" && s != "0.0.0.0/0")
            || r.get("iif").is_some()
            || r.get("iifname").is_some()
    }) {
        return Err(fail());
    }
    let nft: Value = serde_json::from_slice(nft).map_err(|_| fail())?;
    fn has_zone(v: &Value) -> bool {
        match v {
            Value::Object(o) => {
                o.get("ct").is_some_and(|c| c["key"] == "zone") || o.values().any(has_zone)
            }
            Value::Array(a) => a.iter().any(has_zone),
            _ => false,
        }
    }
    if has_zone(&nft) {
        return Err(fail());
    }
    let routes: Value = serde_json::from_slice(routes6).map_err(|_| fail())?;
    if routes
        .as_array()
        .ok_or_else(fail)?
        .iter()
        .any(|r| r["dst"] == "default" && r["type"] != "unreachable")
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 offload transition scope is unverified",
        ));
    }
    Ok(router_locals)
}
/// Same immutable manifest as capture. The OS scope proof additionally prevents
/// private prefixes from accidentally selecting another ingress/zone.
pub struct Scope {
    manifest: crate::Manifest,
    router_locals: BTreeSet<Ipv4Addr>,
}
impl Scope {
    pub fn prove(
        m: &crate::Manifest,
        addresses: &[u8],
        links: &[u8],
        nft: &[u8],
        rules4: &[u8],
        routes6: &[u8],
    ) -> io::Result<Self> {
        if !m.valid() || m.capture_version != Some(1) || !m.whole_lan() {
            return Err(fail());
        }
        let router_locals = scope_admissible(
            &m.lan_interface,
            m.lan_scope.as_deref().ok_or_else(fail)?,
            addresses,
            links,
            nft,
            rules4,
            routes6,
        )?;
        Ok(Self {
            manifest: m.clone(),
            router_locals,
        })
    }
    pub fn selected(&self, entry: &Entry) -> bool {
        if entry.status & ((1 << 14) | (1 << 15)) == 0
            || entry.status & (1 << 9) != 0
            || entry.zone != 0
            || entry.status & (1 << 5) != 0
            || ![6, 17].contains(&entry.protocol)
            || [53, 1053].contains(&entry.destination_port)
            || self.router_locals.contains(&entry.source)
            || self.router_locals.contains(&entry.destination)
        {
            return false;
        }
        // Evaluate the source/destination bypasses from the exact capture AST;
        // adding a future capture exclusion must fail closed until supported here.
        let Ok(ast) = self.manifest.expected_nft_ast() else {
            return false;
        };
        let mut source = false;
        for r in ast["nftables"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|i| i.get("rule"))
            .filter(|r| r["chain"] == "capture")
        {
            let Some(xs) = r["expr"].as_array() else {
                return false;
            };
            if xs.iter().any(|x| x.get("tproxy").is_some()) {
                return source;
            }
            for x in xs {
                let Some(m) = x.get("match") else {
                    continue;
                };
                let left = &m["left"];
                let right = &m["right"];
                let ip_match = |ip: Ipv4Addr| {
                    right
                        .as_str()
                        .is_some_and(|s| s.parse::<Ipv4Addr>().ok() == Some(ip))
                        || right.get("prefix").is_some_and(|p| {
                            p["addr"]
                                .as_str()
                                .zip(p["len"].as_u64())
                                .is_some_and(|(a, n)| contains(&format!("{a}/{n}"), ip))
                        })
                };
                if left == &serde_json::json!({"payload":{"protocol":"ip","field":"saddr"}})
                    && m["op"] == "!="
                {
                    if !ip_match(entry.source) {
                        return false;
                    }
                    source = true;
                }
                if left == &serde_json::json!({"payload":{"protocol":"ip","field":"daddr"}})
                    && m["op"] == "=="
                    && ip_match(entry.destination)
                {
                    return false;
                }
            }
        }
        false
    }
}
#[derive(Debug, Serialize)]
pub struct Transition {
    pub inspected: usize,
    pub selected: usize,
    pub deleted: usize,
    pub replaced_or_gone: usize,
}
/// Publish capture before this call; caller fresh-rechecks scope and deadline
/// afterwards. No hardware success is implied by these counters or ACKs.
pub fn invalidate(scope: &Scope, deadline: Instant) -> io::Result<Transition> {
    let mut socket = Netlink::new(deadline.min(Instant::now() + Duration::from_secs(5)))?;
    let mut result = Transition {
        inspected: 0,
        selected: 0,
        deleted: 0,
        replaced_or_gone: 0,
    };
    let mut empty = 0;
    let mut replaced = BTreeSet::new();
    for _ in 0..4 {
        let rows = socket.request((1 << 8) | 1, 0x301, 0, &[])?;
        result.inspected += rows.len();
        if rows.iter().try_fold(false, |found, row| {
            Ok::<_, io::Error>(found || ipv6_candidate(row)?)
        })? {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 offload transition is unverified; no IPv6 entries are deleted",
            ));
        }
        let mut entries = Vec::new();
        for row in &rows {
            if let Some(entry) = Entry::parse(row)?
                && scope.selected(&entry)
            {
                if entry.status & (1 << 15) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "hardware conntrack candidate observed",
                    ));
                }
                let mut tuple = entry.tuple.clone();
                tuple.extend(entry.zone.to_be_bytes());
                if replaced.contains(&tuple) {
                    return Err(io::Error::other(
                        "offloaded conntrack replacement remains; refusing to retarget its identity",
                    ));
                }
                entries.push(entry);
            }
        }
        if entries.len() > 4096 || result.selected + entries.len() > 4096 {
            return Err(fail());
        }
        if entries.is_empty() {
            empty += 1;
            if empty >= 2 {
                return Ok(result);
            }
            continue;
        }
        empty = 0;
        result.selected += entries.len();
        for entry in entries {
            match socket.request((1 << 8) | 2, 5, entry.family, &entry.delete_payload()?) {
                Ok(_) => result.deleted += 1,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    let mut tuple = entry.tuple.clone();
                    tuple.extend(entry.zone.to_be_bytes());
                    replaced.insert(tuple);
                    result.replaced_or_gone += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Err(io::Error::other(
        "offloaded LAN candidates remain after bounded transition",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn manifest() -> crate::Manifest {
        crate::Manifest {
            failure_policy: crate::FailurePolicy::DirectOnFailure,
            owner_id: "00000000-0000-4000-8000-000000000001".into(),
            generation: 1,
            nft_semantic_sha256: "0".repeat(64),
            lan_interface: "br-lan".into(),
            lan_address: "192.0.2.1".parse().unwrap(),
            lan_scope: Some("192.0.2.0/24".into()),
            capture_version: Some(1),
            selected_mac: String::new(),
            management_macs: Vec::new(),
            source_ipv4: "192.0.2.101".parse().unwrap(),
            management_ipv4: "192.0.2.101".parse().unwrap(),
            management_ipv6: Vec::new(),
            management_channel: None,
            local_ipv4: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            selected_ipv6: Vec::new(),
            local_ipv6: vec!["fe80::/10".into()],
            route_table: 100,
            mark: 0x100,
            mask: 0x100,
            priority: 10000,
        }
    }
    fn entry() -> Entry {
        let mut ip = Vec::new();
        attr(1, &[192, 0, 2, 102], &mut ip).unwrap();
        attr(2, &[203, 0, 113, 10], &mut ip).unwrap();
        let mut p = Vec::new();
        attr(1, &[6], &mut p).unwrap();
        attr(2, &12345u16.to_be_bytes(), &mut p).unwrap();
        attr(3, &443u16.to_be_bytes(), &mut p).unwrap();
        let mut tuple = Vec::new();
        attr(0x8001, &ip, &mut tuple).unwrap();
        attr(0x8002, &p, &mut tuple).unwrap();
        let mut row = vec![2, 0, 0, 0];
        attr(0x8001, &tuple, &mut row).unwrap();
        attr(3, &(1u32 << 14).to_be_bytes(), &mut row).unwrap();
        attr(12, &[0xde, 0xad, 0xbe, 0xef], &mut row).unwrap();
        Entry::parse(&row).unwrap().unwrap()
    }
    type RawInputs = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    fn inputs() -> RawInputs {
        (serde_json::to_vec(&json!([
            {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8},{"family":"inet6","local":"::1","prefixlen":128}]},
            {"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24}]},
            {"ifname":"wan","addr_info":[{"family":"inet","local":"198.51.100.2","prefixlen":24}]}
        ])).unwrap(),serde_json::to_vec(&json!([{"ifname":"br-lan","ifindex":1},{"ifname":"lan1","ifindex":2,"master":"br-lan"},{"ifname":"wan","ifindex":3}])).unwrap(),br#"{"nftables":[]}"#.to_vec(),br#"[{"src":"all"}]"#.to_vec(),b"[]".to_vec())
    }
    #[test]
    fn nft_generation_must_bracket_the_same_rules_and_flags() {
        let values = std::cell::RefCell::new(vec![3, 3, 2, 1]);
        let reads = std::cell::Cell::new(0);
        let result = coherent(
            Instant::now() + Duration::from_secs(1),
            || Ok(values.borrow_mut().pop().unwrap()),
            || {
                reads.set(reads.get() + 1);
                Ok(reads.get())
            },
        )
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(reads.get(), 2);
        let n = std::cell::Cell::new(0);
        let result = coherent(
            Instant::now() + Duration::from_secs(1),
            || {
                n.set(n.get() + 1);
                Ok(n.get())
            },
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(n.get(), 6);
    }
    #[test]
    fn any_observed_ipv6_offload_requires_a_separate_scope_prerequisite() {
        let mut row = vec![libc::AF_INET6 as u8, 0, 0, 0];
        attr(3, &(1u32 << 14).to_be_bytes(), &mut row).unwrap();
        assert!(ipv6_candidate(&row).unwrap());
        let mut fresh = vec![libc::AF_INET6 as u8, 0, 0, 0];
        attr(3, &0u32.to_be_bytes(), &mut fresh).unwrap();
        assert!(!ipv6_candidate(&fresh).unwrap());
        let mut dying = vec![libc::AF_INET6 as u8, 0, 0, 0];
        attr(3, &((1u32 << 14) | (1 << 9)).to_be_bytes(), &mut dying).unwrap();
        assert!(!ipv6_candidate(&dying).unwrap());
    }
    #[test]
    fn exact_delete_is_bound_to_tuple_zone_and_raw_id_without_filter_or_flush_selector() {
        let e = entry();
        let bytes = e.delete_payload().unwrap();
        let a = attrs(&bytes).unwrap();
        assert_eq!(a.len(), 3);
        assert_eq!(*a.get(&12).unwrap(), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(*a.get(&18).unwrap(), [0, 0]);
        assert!(!a.contains_key(&28));
        let mut broken = e.clone();
        broken.tuple.clear();
        assert!(broken.delete_payload().is_err());
    }
    #[test]
    fn capture_scope_preserves_wrong_zone_all_router_locals_management_dnat_and_bypass_flows() {
        let (addresses, links, nft, rules, routes) = inputs();
        let scope = Scope::prove(&manifest(), &addresses, &links, &nft, &rules, &routes).unwrap();
        let original = entry();
        assert!(scope.selected(&original));
        let mut fresh = original.clone();
        fresh.status = 0;
        assert!(!scope.selected(&fresh));
        let mut remote = original.clone();
        remote.destination_port = 222;
        assert!(scope.selected(&remote));
        remote.destination_port = 1000;
        assert!(scope.selected(&remote));
        for (source, destination, port, zone, status) in [
            ("192.0.2.102", "203.0.113.10", 443, 7, 1 << 14),
            ("192.0.2.1", "203.0.113.10", 443, 0, 1 << 14),
            ("192.0.2.102", "198.51.100.2", 443, 0, 1 << 14),
            ("192.0.2.102", "192.0.2.101", 1000, 0, 1 << 14),
            ("192.0.2.102", "203.0.113.10", 443, 0, (1 << 5) | (1 << 14)),
            ("198.51.100.3", "203.0.113.10", 443, 0, 1 << 14),
            ("192.0.2.102", "224.0.0.1", 443, 0, 1 << 14),
        ] {
            let mut e = original.clone();
            e.source = source.parse().unwrap();
            e.destination = destination.parse().unwrap();
            e.destination_port = port;
            e.zone = zone;
            e.status = status;
            assert!(
                !scope.selected(&e),
                "preserve {source}/{destination}/{port}/{zone}/{status}"
            );
        }
    }
    #[test]
    fn ambiguous_sources_zone_assignment_and_ipv6_wan_refuse_scoped_transition() {
        let (mut addresses, links, nft, rules, routes) = inputs();
        let mut a: Value = serde_json::from_slice(&addresses).unwrap();
        a[2]["addr_info"][0]["local"] = json!("192.0.2.254");
        addresses = serde_json::to_vec(&a).unwrap();
        assert!(Scope::prove(&manifest(), &addresses, &links, &nft, &rules, &routes).is_err());
        let (addresses, _, _, _, _) = inputs();
        assert!(Scope::prove(&manifest(),&addresses,&links,br#"{"nftables":[{"rule":{"expr":[{"mangle":{"key":{"ct":{"key":"zone"}},"value":4}}]}}]}"#,&rules,&routes).is_err());
        assert!(
            Scope::prove(
                &manifest(),
                &addresses,
                &links,
                &nft,
                &rules,
                br#"[{"dst":"default","dev":"wan6"}]"#
            )
            .is_err()
        );
    }
    #[test]
    fn physical_bridge_members_overlap_and_proven_foreign_devices_remain_disjoint() {
        let (_, links, _, _, _) = inputs();
        let mut table = FlowTable {
            family: 1,
            table: "foreign".into(),
            name: "ft".into(),
            flags: 1,
            hook: 0,
            priority: 0,
            devices: vec!["lan1".into()],
            handle: 1,
        };
        assert!(affects_lan(&table, &links, "br-lan").unwrap());
        table.devices = vec!["wan".into()];
        assert!(!affects_lan(&table, &links, "br-lan").unwrap());
        table.devices = vec!["unknown-phy".into()];
        assert!(affects_lan(&table, &links, "br-lan").unwrap());
    }
    #[test]
    fn truncated_or_duplicate_attributes_are_never_accepted_as_complete_dump_data() {
        assert!(attrs(&[3, 0, 1, 0]).is_err());
        let mut b = Vec::new();
        attr(1, &[2], &mut b).unwrap();
        attr(1, &[3], &mut b).unwrap();
        assert!(attrs(&b).is_err());
    }
}
