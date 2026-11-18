//! Canonical, bounded foreign-topology evidence for a network generation.
//! Callers gather all inputs through fixed trusted OS readers, never HTTP.
use crate::{Manifest, nft_semantic_digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub lan_ifname: String,
    pub lan_ipv4: Ipv4Addr,
    pub lan_cidrs: Vec<String>,
    pub selected_ipv4: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_version: Option<u8>,
    pub selected_mac: String,
    pub management_ipv4: Ipv4Addr,
    pub management_macs: Vec<String>,
    pub management_ipv6: Vec<Ipv6Addr>,
    pub local_ipv4: Vec<String>,
    pub local_ipv6: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitUpstream {
    pub zone: String,
    pub target: Option<Endpoint>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsEvidence {
    pub configuration_sha256: String,
    pub default_upstreams: Vec<Endpoint>,
    pub split_upstreams: Vec<SplitUpstream>,
    pub local_zones: Vec<String>,
    /// Required if a loopback forwarder is present; caller must verify its full
    /// transitive config and executables do not point back at port 1053.
    pub verified_loopback_chain_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flowtables: Option<Vec<crate::flow_offload::FlowTable>>,
    pub version: u32,
    pub scope: Scope,
    pub dns: DnsEvidence,
    pub links_sha256: String,
    pub addresses_sha256: String,
    pub foreign_nft_sha256: String,
    pub foreign_rules4_sha256: String,
    pub foreign_rules6_sha256: String,
    pub foreign_routes4_sha256: String,
    pub foreign_routes6_sha256: String,
}
/// Internal phase-specific expectations derived solely from the durable journal.
pub enum NftExpectation<'a> {
    Absent,
    Digest(&'a str),
}
pub enum RoutingExpectation {
    Absent,
    RouteOnly,
    RuleOnly,
    Exact,
}
pub struct OwnedExpectation<'a> {
    pub manifest: &'a Manifest,
    /// The active policy for this evidence. During replacement, `manifest`
    /// identifies the old owned objects while this binds the new client scope.
    pub scope_manifest: Option<&'a Manifest>,
    pub nft: NftExpectation<'a>,
    pub routing: RoutingExpectation,
}
fn fail() -> std::io::Error {
    std::io::Error::other("unverifiable network evidence")
}
fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn valid_mac(s: &str) -> bool {
    let p: Vec<_> = s.split(':').collect();
    if p.len() != 6
        || p.iter().any(|v| {
            v.len() != 2
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return false;
    }
    let Ok(first) = u8::from_str_radix(p[0], 16) else {
        return false;
    };
    first & 1 == 0 && s != "00:00:00:00:00:00"
}
fn cidr(s: &str, v6: bool) -> bool {
    let Some((a, p)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = p.parse::<u8>() else {
        return false;
    };
    if v6 {
        (1..=128).contains(&prefix) && a.parse::<Ipv6Addr>().is_ok()
    } else {
        (1..=32).contains(&prefix) && a.parse::<Ipv4Addr>().is_ok()
    }
}
fn valid_zone(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+.-_".contains(&b))
}
fn ordered<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|x| x[0] < x[1])
}
fn number(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => u32::try_from(n.as_u64()?).ok(),
        Value::String(s) => {
            if let Some(h) = s.strip_prefix("0x") {
                u32::from_str_radix(h, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        _ => None,
    }
}
fn table(v: Option<&Value>) -> Option<u32> {
    match v {
        None => Some(254),
        Some(Value::String(s)) if s == "main" => Some(254),
        Some(Value::String(s)) if s == "local" => Some(255),
        Some(Value::String(s)) if s == "default" => Some(253),
        Some(v) => number(v),
    }
}
fn mark(v: &serde_json::Map<String, Value>) -> std::io::Result<Option<(u32, u32)>> {
    let Some(m) = v.get("fwmark") else {
        return if v.contains_key("fwmask") {
            Err(fail())
        } else {
            Ok(None)
        };
    };
    let (n, mask) = if let Some(s) = m.as_str() {
        if let Some((a, b)) = s.split_once('/') {
            (
                number(&Value::String(a.into())).ok_or_else(fail)?,
                number(&Value::String(b.into())).ok_or_else(fail)?,
            )
        } else {
            (number(m).ok_or_else(fail)?, u32::MAX)
        }
    } else {
        (number(m).ok_or_else(fail)?, u32::MAX)
    };
    let mask = match v.get("fwmask") {
        Some(x) if mask == u32::MAX => number(x).ok_or_else(fail)?,
        Some(_) => return Err(fail()),
        None => mask,
    };
    if mask == 0 || n & !mask != 0 {
        return Err(fail());
    }
    Ok(Some((n, mask)))
}
fn parse(input: &[u8]) -> std::io::Result<Value> {
    if input.len() > 1_048_576 {
        return Err(fail());
    }
    serde_json::from_slice(input).map_err(|_| fail())
}
// Sort object keys while preserving every field and array order. Dynamic nft
// fields are normalized explicitly in `normalize_foreign_nft` below.
fn canonical(v: &Value, _in_counter: bool) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|x| canonical(x, false)).collect()),
        Value::Object(o) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in o {
                sorted.insert(k.clone(), canonical(v, k == "counter"));
            }
            Value::Object(sorted.into_iter().collect())
        }
        _ => v.clone(),
    }
}
fn digest(v: &Value) -> std::io::Result<String> {
    let b = serde_json::to_vec(&canonical(v, false)).map_err(|_| fail())?;
    Ok(Sha256::digest(&b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn normalize_counter(counter: &mut Value) -> std::io::Result<()> {
    let fail = || std::io::Error::other("unrecognized nft counter");
    if let Some(name) = counter.as_str() {
        return if !name.is_empty()
            && name.len() <= 255
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            Ok(())
        } else {
            Err(fail())
        };
    }
    let values = counter.as_object_mut().ok_or_else(fail)?;
    const ALLOWED: &[&str] = &["family", "table", "name", "packets", "bytes"];
    let identities = ["family", "table", "name"];
    let identity_count = identities
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    if values.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || (identity_count != 0 && identity_count != identities.len())
        || identities.iter().any(|key| {
            values
                .get(*key)
                .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        })
        || values
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| {
                name.len() > 255
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        || values.get("packets").and_then(Value::as_u64).is_none()
        || values.get("bytes").and_then(Value::as_u64).is_none()
    {
        return Err(fail());
    }
    values.insert("packets".into(), Value::from(0));
    values.insert("bytes".into(), Value::from(0));
    Ok(())
}
fn normalize_foreign_nft(mut item: Value) -> std::io::Result<Value> {
    let fail = || std::io::Error::other("unrecognized foreign nft object");
    let object = item.as_object_mut().ok_or_else(fail)?;
    if object.len() != 1 {
        return Err(fail());
    }
    let (kind, body) = object.iter_mut().next().ok_or_else(fail)?;
    let fields = body.as_object_mut().ok_or_else(fail)?;
    const HANDLE_KINDS: &[&str] = &[
        "table",
        "chain",
        "rule",
        "set",
        "map",
        "flowtable",
        "counter",
        "quota",
        "limit",
        "ct_helper",
        "ct_timeout",
        "ct_expect",
        "secmark",
        "synproxy",
        "objref",
        "meter",
    ];
    if HANDLE_KINDS.contains(&kind.as_str())
        && let Some(handle) = fields.get("handle")
    {
        if handle.as_u64().is_none() {
            return Err(fail());
        }
        fields.remove("handle");
    }
    if kind == "counter" && (fields.contains_key("packets") || fields.contains_key("bytes")) {
        let mut counter = Value::Object(fields.clone());
        normalize_counter(&mut counter)?;
        *fields = counter.as_object().cloned().ok_or_else(fail)?;
    }
    if kind == "rule"
        && let Some(exprs) = fields.get_mut("expr")
    {
        let exprs = exprs.as_array_mut().ok_or_else(fail)?;
        for expr in exprs {
            let expr = expr.as_object_mut().ok_or_else(fail)?;
            if expr.len() == 1
                && let Some(counter) = expr.get_mut("counter")
            {
                normalize_counter(counter)?;
            }
        }
    }
    Ok(item)
}
/// Hash an already ownership-filtered ruleset for Plan -> Apply drift detection.
/// Handles and counters are normalized; rule order, set elements and semantics are not.
pub fn foreign_nft_digest(input: &[u8]) -> std::io::Result<String> {
    let root = parse(input)?;
    let entries = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(fail)?;
    let normalized: std::io::Result<Vec<_>> = entries
        .iter()
        .filter(|i| i.get("metainfo").is_none())
        .cloned()
        .map(normalize_foreign_nft)
        .collect();
    digest(&serde_json::json!({"nftables":normalized?}))
}

fn strip_nft(input: &[u8], expected: &OwnedExpectation<'_>) -> std::io::Result<Value> {
    let mut root = parse(input)?;
    let list = root
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or_else(fail)?;
    let mut own = Vec::new();
    let mut foreign = Vec::new();
    for item in std::mem::take(list) {
        let obj = item.as_object().ok_or_else(fail)?;
        if obj.len() != 1 {
            return Err(fail());
        }
        let (kind, body) = obj.iter().next().ok_or_else(fail)?;
        let b = body.as_object().ok_or_else(fail)?;
        if kind == "table" {
            if b.get("family").and_then(Value::as_str).is_none()
                || b.get("name").and_then(Value::as_str).is_none()
            {
                return Err(fail());
            }
        } else if kind != "metainfo"
            && (b.get("family").and_then(Value::as_str).is_none()
                || b.get("table").and_then(Value::as_str).is_none())
        {
            return Err(fail());
        }
        let is_own = if kind == "table" {
            b.get("family").and_then(Value::as_str) == Some("inet")
                && b.get("name").and_then(Value::as_str) == Some("xkeenwrt")
        } else {
            b.get("family").and_then(Value::as_str) == Some("inet")
                && b.get("table").and_then(Value::as_str) == Some("xkeenwrt")
        };
        if is_own {
            own.push(item)
        } else {
            foreign.push(normalize_foreign_nft(item)?)
        }
    }
    match expected.nft {
        NftExpectation::Absent if !own.is_empty() => return Err(fail()),
        NftExpectation::Absent => (),
        NftExpectation::Digest(want) => {
            if !valid_hex(want) || own.is_empty() {
                return Err(fail());
            }
            let value = serde_json::json!({"nftables":own});
            if nft_semantic_digest(&serde_json::to_vec(&value).map_err(|_| fail())?)? != want {
                return Err(fail());
            }
        }
    }
    *list = foreign;
    Ok(root)
}
fn strip_rules(
    input: &[u8],
    m: &Manifest,
    expect_exact: bool,
    ipv6: bool,
) -> std::io::Result<Value> {
    let mut root = parse(input)?;
    let list = root.as_array_mut().ok_or_else(fail)?;
    let mut kept = Vec::new();
    let mut found = 0;
    for item in std::mem::take(list) {
        let r = item.as_object().ok_or_else(fail)?;
        let priority = number(r.get("priority").ok_or_else(fail)?).ok_or_else(fail)?;
        let fm = mark(r)?;
        let own = priority == m.priority;
        if own {
            if ipv6
                || !expect_exact
                || table(r.get("table")) != Some(m.route_table)
                || fm != Some((m.mark, m.mask))
                || r.get("src").is_some_and(|v| v.as_str() != Some("all"))
                || r.keys().any(|k| {
                    !["priority", "table", "fwmark", "fwmask", "src"].contains(&k.as_str())
                })
            {
                return Err(fail());
            }
            found += 1;
        } else {
            if fm.is_some_and(|(_, mask)| mask & m.mask != 0) {
                return Err(fail());
            }
            kept.push(item);
        }
    }
    if found != usize::from(expect_exact && !ipv6) {
        return Err(fail());
    }
    *list = kept;
    Ok(root)
}
fn strip_routes(
    input: &[u8],
    m: &Manifest,
    expect_exact: bool,
    ipv6: bool,
) -> std::io::Result<Value> {
    let mut root = parse(input)?;
    let list = root.as_array_mut().ok_or_else(fail)?;
    let mut kept = Vec::new();
    let mut found = 0;
    for item in std::mem::take(list) {
        let r = item.as_object().ok_or_else(fail)?;
        let t = table(r.get("table")).ok_or_else(fail)?;
        if t == m.route_table {
            if ipv6
                || !expect_exact
                || !matches!(
                    r.get("dst").and_then(Value::as_str),
                    Some("default") | Some("0.0.0.0/0")
                )
                || r.get("type").and_then(Value::as_str) != Some("local")
                || r.get("dev").and_then(Value::as_str) != Some("lo")
                || r.get("gateway").is_some()
                || r.get("scope").is_some_and(|v| v.as_str() != Some("host"))
                || r.get("flags")
                    .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
                || r.keys().any(|k| {
                    !["dst", "type", "dev", "table", "protocol", "scope", "flags"]
                        .contains(&k.as_str())
                })
            {
                return Err(fail());
            }
            found += 1;
        } else {
            kept.push(item);
        }
    }
    if found != usize::from(expect_exact && !ipv6) {
        return Err(fail());
    }
    *list = kept;
    Ok(root)
}
fn contains_v4(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(prefix)) = (address.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return false;
    };
    if !(1..=32).contains(&prefix) {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(address) & mask == u32::from(ip) & mask
}
fn valid_scope_dns(scope: &Scope, dns: &DnsEvidence) -> bool {
    if let Some(lan_scope) = &scope.lan_scope
        && (!crate::valid_lan_scope(lan_scope, scope.lan_ipv4, scope.management_ipv4)
            || scope.lan_cidrs.len() != 1
            || crate::lan_network(&scope.lan_cidrs[0]).as_ref() != Some(lan_scope)
            || scope.selected_ipv4 != scope.management_ipv4
            || !scope.selected_mac.is_empty()
            || !scope.management_macs.is_empty()
            || !scope.management_ipv6.is_empty()
            || !scope.local_ipv4.contains(lan_scope))
    {
        return false;
    }
    if !valid_name(&scope.lan_ifname)
        || (scope.lan_scope.is_none() && !valid_mac(&scope.selected_mac))
        || scope.lan_ipv4.is_unspecified()
        || scope.lan_ipv4.is_loopback()
        || scope.lan_ipv4.is_multicast()
        || scope.selected_ipv4.is_unspecified()
        || scope.selected_ipv4.is_loopback()
        || scope.selected_ipv4.is_multicast()
        || scope.management_ipv4.is_unspecified()
        || scope.management_ipv4.is_loopback()
        || scope.management_ipv4.is_multicast()
        || (scope.lan_scope.is_none() && scope.selected_ipv4 == scope.management_ipv4)
        || scope.selected_ipv4 == scope.lan_ipv4
        || (scope.lan_scope.is_none() && scope.management_macs.is_empty())
        || scope.management_macs.len() > 256
        || scope.management_ipv6.len() > 256
        || scope
            .management_macs
            .iter()
            .any(|v| !valid_mac(v) || v == &scope.selected_mac)
        || scope
            .management_ipv6
            .iter()
            .any(|v| v.is_unspecified() || v.is_multicast())
        || scope.lan_cidrs.is_empty()
        || scope.lan_cidrs.len() > 256
        || !ordered(&scope.lan_cidrs)
        || scope.lan_cidrs.iter().any(|v| !cidr(v, false))
        || !scope
            .lan_cidrs
            .iter()
            .any(|v| contains_v4(v, scope.lan_ipv4))
        || !scope
            .lan_cidrs
            .iter()
            .any(|v| contains_v4(v, scope.selected_ipv4))
        || !scope
            .lan_cidrs
            .iter()
            .any(|v| contains_v4(v, scope.management_ipv4))
        || scope.local_ipv4.is_empty()
        || scope.local_ipv4.len() > 256
        || scope.local_ipv6.is_empty()
        || scope.local_ipv6.len() > 256
        || !ordered(&scope.management_macs)
        || !ordered(&scope.management_ipv6)
        || !ordered(&scope.local_ipv4)
        || !ordered(&scope.local_ipv6)
        || scope.local_ipv4.iter().any(|v| !cidr(v, false))
        || scope.local_ipv6.iter().any(|v| !cidr(v, true))
        || !valid_hex(&dns.configuration_sha256)
        || dns.default_upstreams.is_empty()
        || dns.default_upstreams.len() > 256
        || dns.split_upstreams.len() > 256
        || dns.local_zones.len() > 256
        || !ordered(&dns.default_upstreams)
        || !ordered(&dns.split_upstreams)
        || !ordered(&dns.local_zones)
        || dns.local_zones.iter().any(|v| !valid_zone(v))
        || dns
            .split_upstreams
            .iter()
            .any(|v| !valid_zone(&v.zone) || !dns.local_zones.contains(&v.zone))
    {
        return false;
    }
    let endpoints = dns
        .default_upstreams
        .iter()
        .chain(dns.split_upstreams.iter().filter_map(|s| s.target.as_ref()));
    let mut loopback = false;
    for ep in endpoints {
        let is_local = ep.address.is_loopback()
            || scope
                .local_ipv4
                .iter()
                .chain(scope.local_ipv6.iter())
                .any(|c| {
                    c.split_once('/')
                        .and_then(|(a, _)| a.parse::<IpAddr>().ok())
                        == Some(ep.address)
                });
        if ep.port == 0
            || ep.address.is_unspecified()
            || ep.address.is_multicast()
            || (is_local && [53, 1053].contains(&ep.port))
        {
            return false;
        }
        loopback |= ep.address.is_loopback();
    }
    if loopback
        && !dns
            .verified_loopback_chain_sha256
            .as_deref()
            .is_some_and(valid_hex)
    {
        return false;
    }
    !dns.verified_loopback_chain_sha256
        .as_deref()
        .is_some_and(|v| !valid_hex(v))
}
/// Physical carrier and the RFC 2863 operational state derived from it follow
/// cables and radio association, not configuration: an `eth1` cable must not
/// look like a different `br-lan`. Interface identity, bridge membership,
/// MAC, MTU, administrative `UP` and every other kernel field stay digested.
/// Loss of carrier on the LAN device itself remains visible through the
/// `linkdown` flag of its routes.
fn without_carrier_state(link: &mut Value) -> std::io::Result<()> {
    let item = link.as_object_mut().ok_or_else(fail)?;
    item.remove("operstate");
    if let Some(flags) = item.get_mut("flags") {
        let flags = flags.as_array_mut().ok_or_else(fail)?;
        if flags.iter().any(|f| !f.is_string()) {
            return Err(fail());
        }
        flags.retain(|f| !matches!(f.as_str(), Some("NO-CARRIER" | "LOWER_UP" | "DORMANT")));
    }
    Ok(())
}
fn link_semantics(input: &[u8]) -> std::io::Result<Value> {
    let mut value = parse(input)?;
    for link in value.as_array_mut().ok_or_else(fail)? {
        without_carrier_state(link)?;
    }
    Ok(value)
}
fn address_semantics(input: &[u8]) -> std::io::Result<Value> {
    let mut value = parse(input)?;
    let links = value.as_array_mut().ok_or_else(fail)?;
    for link in links {
        without_carrier_state(link)?;
        let infos = link
            .get_mut("addr_info")
            .and_then(Value::as_array_mut)
            .ok_or_else(fail)?;
        for info in infos {
            let item = info.as_object_mut().ok_or_else(fail)?;
            // These kernel lifetime/timestamp counters change without a semantic
            // change; flags and all other fields remain part of the fingerprint.
            for key in ["valid_life_time", "preferred_life_time", "cstamp", "tstamp"] {
                item.remove(key);
            }
        }
    }
    Ok(value)
}
/// Fixed read-only outputs, collected by the privileged caller through bounded
/// commands. These bytes are never supplied by an HTTP client.
pub struct FixedInputs<'a> {
    pub flowtables: Option<&'a [crate::flow_offload::FlowTable]>,
    pub links: &'a [u8],
    pub addresses: &'a [u8],
    pub neighbours: &'a [u8],
    pub leases: &'a [u8],
    pub netifd: &'a [u8],
    pub dnsconfig: &'a [u8],
    pub proxyconfig: &'a [u8],
    pub proxyservice: &'a [u8],
    pub tcp4: &'a [u8],
    pub udp4: &'a [u8],
    pub tcp6: &'a [u8],
    pub udp6: &'a [u8],
    pub nft: &'a [u8],
    pub rules4: &'a [u8],
    pub rules6: &'a [u8],
    pub routes4: &'a [u8],
    pub routes6: &'a [u8],
    pub now_unix: u64,
}

impl NetworkEvidence {
    /// Derive identity, DNS and local routes from fresh fixed outputs. Callers
    /// must take two identical captures and separately prove core health.
    pub fn capture_fixed(
        input: &FixedInputs<'_>,
        owned: OwnedExpectation<'_>,
    ) -> std::io::Result<Self> {
        use std::collections::BTreeSet;
        let m = owned.manifest;
        let scope_m = owned.scope_manifest.unwrap_or(m);
        if scope_m.lan_interface != m.lan_interface || scope_m.lan_address != m.lan_address {
            return Err(fail());
        }
        let lan = &scope_m.lan_interface;
        let addresses = inventory::address_facts(input.addresses, lan).map_err(|_| fail())?;
        if !inventory::ethernet_like(input.links, lan).map_err(|_| fail())? {
            return Err(fail());
        }
        let net = parse(input.netifd)?;
        let interfaces = net
            .get("interface")
            .and_then(Value::as_array)
            .ok_or_else(fail)?;
        let matches: Vec<_> = interfaces
            .iter()
            .filter(|v| v.get("interface").and_then(Value::as_str) == Some("lan"))
            .collect();
        if matches.len() != 1
            || matches[0].get("up").and_then(Value::as_bool) != Some(true)
            || matches[0].get("l3_device").and_then(Value::as_str) != Some(lan)
            || !matches[0]
                .get("ipv4-address")
                .and_then(Value::as_array)
                .ok_or_else(fail)?
                .iter()
                .any(|v| {
                    v.get("address")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse::<Ipv4Addr>().ok())
                        == Some(addresses.lan_address)
                })
        {
            return Err(fail());
        }
        let (selected_mac, management_macs, management_ipv6) = if let Some(scope) =
            &scope_m.lan_scope
        {
            if addresses.lan_cidrs.len() != 1
                || crate::lan_network(&addresses.lan_cidrs[0]).as_ref() != Some(scope)
                || !crate::valid_lan_scope(scope, addresses.lan_address, scope_m.management_ipv4)
            {
                return Err(fail());
            }
            (String::new(), Vec::new(), Vec::new())
        } else {
            let (selected, management) = inventory::resolve_client_and_management_mac(
                input.neighbours,
                input.leases,
                lan,
                scope_m.source_ipv4,
                scope_m.management_ipv4,
                input.now_unix,
            )
            .map_err(|_| fail())?;
            let management_ipv6 =
                inventory::ipv6_for_mac(input.neighbours, lan, &management).map_err(|_| fail())?;
            (selected, vec![management], management_ipv6)
        };
        let dns = inventory::dnsmasq_facts(input.dnsconfig).map_err(|_| fail())?;
        let has_loopback = dns.has_loopback_upstream();
        let proxy_inodes = if has_loopback {
            inventory::https_dns_proxy_socket_inodes(input.proxyservice).map_err(|_| fail())?
        } else {
            Vec::new()
        };
        let loopback_chain = inventory::verified_loopback_chain(
            &dns,
            input.dnsconfig,
            input.proxyconfig,
            input.proxyservice,
            [input.tcp4, input.udp4, input.tcp6, input.udp6],
            &proxy_inodes,
        )
        .map_err(|_| fail())?;
        inventory::validate_dns_targets(
            &dns,
            &addresses.local_ipv4,
            &addresses.local_ipv6,
            loopback_chain.as_deref(),
        )
        .map_err(|_| fail())?;
        let config = parse(input.dnsconfig)?;
        let sections = config
            .get("values")
            .and_then(Value::as_object)
            .ok_or_else(fail)?;
        let instance = sections
            .values()
            .find(|v| v.get(".type").and_then(Value::as_str) == Some("dnsmasq"))
            .ok_or_else(fail)?;
        if instance
            .get("leasefile")
            .is_some_and(|v| v.as_str() != Some("/tmp/dhcp.leases"))
        {
            return Err(fail());
        }
        let mut local4: BTreeSet<_> = addresses.local_ipv4.into_iter().collect();
        let mut local6: BTreeSet<_> = addresses.local_ipv6.into_iter().collect();
        let mut tables = BTreeSet::new();
        let exact = matches!(
            owned.routing,
            RoutingExpectation::Exact | RoutingExpectation::RouteOnly
        );
        let routes4 = serde_json::to_vec(&strip_routes(input.routes4, m, exact, false)?)
            .map_err(|_| fail())?;
        let routes6 = serde_json::to_vec(&strip_routes(input.routes6, m, false, true)?)
            .map_err(|_| fail())?;
        inventory::route_facts(&routes4, false, &mut tables, &mut local4).map_err(|_| fail())?;
        inventory::route_facts(&routes6, true, &mut tables, &mut local6).map_err(|_| fail())?;
        let scope = Scope {
            lan_ifname: lan.clone(),
            lan_ipv4: addresses.lan_address,
            lan_cidrs: addresses.lan_cidrs,
            selected_ipv4: scope_m.source_ipv4,
            lan_scope: scope_m.lan_scope.clone(),
            capture_version: scope_m.capture_version,
            selected_mac,
            management_ipv4: scope_m.management_ipv4,
            management_macs,
            management_ipv6,
            local_ipv4: local4.into_iter().collect(),
            local_ipv6: local6.into_iter().collect(),
        };
        let dns = DnsEvidence {
            configuration_sha256: digest(&config)?,
            default_upstreams: dns.upstreams.into_iter().collect(),
            split_upstreams: dns
                .split_upstreams
                .into_iter()
                .map(|(zone, target)| SplitUpstream { zone, target })
                .collect(),
            local_zones: dns.local_zones,
            verified_loopback_chain_sha256: loopback_chain,
        };
        Self::capture(
            input.flowtables,
            scope,
            dns,
            input.links,
            input.addresses,
            input.nft,
            input.rules4,
            input.rules6,
            input.routes4,
            input.routes6,
            owned,
        )
    }
    /// The caller must recapture twice and compare; this function alone does not
    /// prove a multi-command snapshot was concurrent or that listeners are healthy.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        flowtables: Option<&[crate::flow_offload::FlowTable]>,
        mut scope: Scope,
        mut dns: DnsEvidence,
        links: &[u8],
        addresses: &[u8],
        nft: &[u8],
        rules4: &[u8],
        rules6: &[u8],
        routes4: &[u8],
        routes6: &[u8],
        owned: OwnedExpectation<'_>,
    ) -> std::io::Result<Self> {
        let m = owned.manifest;
        let scope_m = owned.scope_manifest.unwrap_or(m);
        // Reuse the shared strict manifest validation without performing I/O.
        m.nft_json_batch(false)?;
        if scope.lan_ifname != scope_m.lan_interface
            || scope.lan_ipv4 != scope_m.lan_address
            || scope.lan_scope != scope_m.lan_scope
            || scope.capture_version != scope_m.capture_version
            || scope.selected_ipv4 != scope_m.source_ipv4
            || scope.selected_mac != scope_m.selected_mac
            || scope.management_ipv4 != scope_m.management_ipv4
        {
            return Err(fail());
        }
        scope.lan_cidrs.sort();
        scope.management_macs.sort();
        scope.management_ipv6.sort();
        scope.local_ipv4.sort();
        scope.local_ipv6.sort();
        dns.default_upstreams.sort();
        dns.split_upstreams.sort();
        dns.local_zones.sort();
        if !valid_scope_dns(&scope, &dns)
            || scope.management_macs != scope_m.management_macs
            || scope.management_ipv6 != scope_m.management_ipv6
            || scope.local_ipv4 != scope_m.local_ipv4
            || scope.local_ipv6 != scope_m.local_ipv6
        {
            return Err(fail());
        }
        let route_exact = matches!(
            owned.routing,
            RoutingExpectation::Exact | RoutingExpectation::RouteOnly
        );
        let rule_exact = matches!(
            owned.routing,
            RoutingExpectation::Exact | RoutingExpectation::RuleOnly
        );
        let foreign = strip_nft(nft, &owned)?;
        let has_flow = foreign["nftables"]
            .as_array()
            .is_some_and(|a| a.iter().any(|i| i.get("flowtable").is_some()));
        let flowtables = match flowtables {
            Some(tables) => {
                crate::flow_offload::verify_for_lan(nft, tables, links, &scope.lan_ifname)?;
                if tables.is_empty() {
                    None
                } else {
                    Some(tables.to_vec())
                }
            }
            None if !has_flow => None,
            None => return Err(fail()),
        };

        let version = if scope.capture_version == Some(1) {
            let bytes = serde_json::to_vec(&foreign).map_err(|_| fail())?;
            if crate::topology::topology_conflict_with_inventory(
                &bytes,
                &[&scope.lan_ifname],
                addresses,
            )
            .map_err(|_| fail())?
            .is_some()
            {
                return Err(fail());
            }
            // Neighbour reloads cannot acquire the mark allocated to this
            // generation, including via a previously unused compare/write.
            if inventory::occupied_nft(&bytes)
                .map_err(|_| fail())?
                .used_mark_mask
                & m.mask
                != 0
            {
                return Err(fail());
            }
            2
        } else {
            1
        };
        Ok(Self {
            flowtables,
            version,
            scope,
            dns,
            links_sha256: digest(&link_semantics(links)?)?,
            addresses_sha256: digest(&address_semantics(addresses)?)?,
            foreign_nft_sha256: digest(&foreign)?,
            foreign_rules4_sha256: digest(&strip_rules(rules4, m, rule_exact, false)?)?,
            foreign_rules6_sha256: digest(&strip_rules(rules6, m, false, true)?)?,
            foreign_routes4_sha256: digest(&strip_routes(routes4, m, route_exact, false)?)?,
            foreign_routes6_sha256: digest(&strip_routes(routes6, m, false, true)?)?,
        })
    }
    /// Version 2 is issued only after fresh semantic admission. Compatible
    /// address-set/rule reloads may change the diagnostic fingerprint; every
    /// non-firewall fact and all allocated resources must still agree.
    pub fn compatible_with(&self, expected: &Self) -> bool {
        if self.version != 2 || expected.version != 2 {
            return self == expected;
        }
        let mut normalized = self.clone();
        normalized.foreign_nft_sha256 = expected.foreign_nft_sha256.clone();
        // GETGEN and identity are checked on every fresh read. A semantically
        // identical recreation changes only this diagnostic kernel handle.
        if let (Some(actual), Some(prior)) = (&mut normalized.flowtables, &expected.flowtables)
            && actual.len() == prior.len()
        {
            for (actual, prior) in actual.iter_mut().zip(prior) {
                actual.handle = prior.handle;
            }
        }
        normalized == *expected
    }
    pub fn valid(&self) -> bool {
        matches!(self.version, 1 | 2)
            && valid_scope_dns(&self.scope, &self.dns)
            && [
                &self.links_sha256,
                &self.addresses_sha256,
                &self.foreign_nft_sha256,
                &self.foreign_rules4_sha256,
                &self.foreign_rules6_sha256,
                &self.foreign_routes4_sha256,
                &self.foreign_routes6_sha256,
            ]
            .iter()
            .all(|v| valid_hex(v))
    }
    pub fn matches_manifest(&self, m: &Manifest) -> bool {
        self.valid()
            && m.nft_json_batch(false).is_ok()
            && self.scope.lan_ifname == m.lan_interface
            && self.scope.lan_ipv4 == m.lan_address
            && self.scope.lan_scope == m.lan_scope
            && self.scope.capture_version == m.capture_version
            && self.scope.selected_ipv4 == m.source_ipv4
            && self.scope.selected_mac == m.selected_mac
            && self.scope.management_ipv4 == m.management_ipv4
            && self.scope.management_macs == m.management_macs
            && self.scope.management_ipv6 == m.management_ipv6
            && self.scope.local_ipv4 == m.local_ipv4
            && self.scope.local_ipv6 == m.local_ipv6
    }
    pub fn fingerprint(&self) -> std::io::Result<String> {
        if !self.valid() {
            return Err(fail());
        }
        digest(&serde_json::to_value(self).map_err(|_| fail())?)
    }
}

pub mod inventory {
    //! Shared pure parsers used by runtime and independent rescue.
    //! Conservative parsing for read-only operating-system inventory.
    //! Unknown names or malformed fields fail closed, never become free allocations.
    use serde_json::Value;
    use std::collections::BTreeSet;

    const MAX_INPUT: usize = 1_048_576;
    const MAX_RULES: usize = 4096;

    #[derive(Debug, PartialEq, Eq)]
    pub enum InventoryError {
        Unsupported,
        ResourceConflict {
            port: u16,
            transport: SocketTransport,
        },
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SocketTransport {
        Tcp,
        Udp,
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct OccupiedRules {
        pub priorities: Vec<u32>,
        pub tables: Vec<u32>,
        pub marks: Vec<(u32, u32)>,
    }

    fn number(value: &Value) -> Option<u32> {
        match value {
            Value::Number(n) => u32::try_from(n.as_u64()?).ok(),
            Value::String(s) => parse_number(s),
            _ => None,
        }
    }
    fn parse_number(s: &str) -> Option<u32> {
        if let Some(hex) = s.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()
        } else {
            s.parse().ok()
        }
    }
    fn table(value: &Value) -> Option<u32> {
        match value.as_str() {
            Some("local") => Some(255),
            Some("main") => Some(254),
            Some("default") => Some(253),
            Some("unspec") => Some(0),
            _ => number(value),
        }
    }
    /// Parse `ip -j -4 rule show` or `ip -j -6 rule show` output.
    /// A symbolic table that cannot be resolved numerically makes allocation unsafe.
    pub fn occupied_rules(input: &[u8]) -> Result<OccupiedRules, InventoryError> {
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT {
            return Err(fail());
        }
        let json: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let rules = json.as_array().ok_or_else(fail)?;
        if rules.len() > MAX_RULES {
            return Err(fail());
        }
        let mut result = OccupiedRules::default();
        for rule in rules {
            let r = rule.as_object().ok_or_else(fail)?;
            let priority = r.get("priority").and_then(number).ok_or_else(fail)?;
            result.priorities.push(priority);
            if let Some(value) = r.get("table") {
                result.tables.push(table(value).ok_or_else(fail)?);
            }
            if let Some(mark) = r.get("fwmark") {
                let (mark, mask) = match mark {
                    Value::String(s) => match s.split_once('/') {
                        Some((m, mask)) => (
                            parse_number(m).ok_or_else(fail)?,
                            parse_number(mask).ok_or_else(fail)?,
                        ),
                        None => (parse_number(s).ok_or_else(fail)?, u32::MAX),
                    },
                    _ => (number(mark).ok_or_else(fail)?, u32::MAX),
                };
                let mask = match r.get("fwmask") {
                    Some(value) => number(value).ok_or_else(fail)?,
                    None => mask,
                };
                if mask == 0 || mark & !mask != 0 {
                    return Err(fail());
                }
                result.marks.push((mark, mask));
            } else if r.contains_key("fwmask") {
                return Err(fail());
            }
        }
        Ok(result)
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct OccupiedNft {
        pub xkeenwrt_table_exists: bool,
        pub used_mark_mask: u32,
    }

    /// Only operations preserving every untouched bit are supported. A copy
    /// from another register, a constant assignment or unknown syntax owns all bits.
    pub fn mark_update_mask(value: &Value) -> Option<u32> {
        let m = value.as_object()?.get("mangle")?.as_object()?;
        if value.as_object()?.len() != 1 || m.len() != 2 {
            return None;
        }
        let key = m.get("key")?;
        if ![
            serde_json::json!({"meta":{"key":"mark"}}),
            serde_json::json!({"ct":{"key":"mark"}}),
        ]
        .contains(key)
        {
            return None;
        }
        fn bits(v: &Value, key: &Value, depth: usize) -> Option<u32> {
            if depth > 4 {
                return None;
            }
            if v == key {
                return Some(0);
            }
            let o = v.as_object()?;
            if o.len() != 1 {
                return None;
            }
            let (op, args) = o.iter().next()?;
            let a = args.as_array()?;
            if a.len() != 2 {
                return None;
            }
            let touched = bits(&a[0], key, depth + 1)?;
            let n = number(&a[1])?;
            match op.as_str() {
                "|" | "^" => Some(touched | n),
                "&" => Some(touched | !n),
                _ => None,
            }
        }
        bits(m.get("value")?, key, 0)
    }

    // Unknown mark expressions reserve all bits. Recognize only a plain masked
    // comparison and same-register bit operations. Other writes/dynamic
    // expressions remain conservative.
    fn mark_mask(value: &Value) -> u32 {
        match value {
            Value::String(_) => 0,
            Value::Array(values) => values.iter().fold(0, |mask, v| mask | mark_mask(v)),
            Value::Object(values) => {
                if let Some(mask) = mark_update_mask(value) {
                    return mask;
                }
                if let Some(m) = values.get("mangle")
                    && [
                        serde_json::json!({"meta":{"key":"mark"}}),
                        serde_json::json!({"ct":{"key":"mark"}}),
                    ]
                    .contains(&m["key"])
                {
                    return number(&m["value"]).unwrap_or(0);
                }

                if values.len() == 1
                    && let Some(m) = values.get("match").and_then(Value::as_object)
                {
                    let left = m.get("left");
                    let right = m.get("right");
                    let extra = m
                        .iter()
                        .filter(|(k, _)| *k != "left" && *k != "right")
                        .fold(0, |mask, (_, v)| mask | mark_mask(v));
                    if extra == 0
                        && left
                            .and_then(Value::as_object)
                            .is_some_and(|o| o.len() == 1)
                        && right.is_some_and(|r| mark_mask(r) == 0)
                        && let Some(and) = left.and_then(|l| l.get("&")).and_then(Value::as_array)
                        && and.len() == 2
                        && [
                            serde_json::json!({"meta": {"key": "mark"}}),
                            serde_json::json!({"ct": {"key": "mark"}}),
                        ]
                        .contains(&and[0])
                        && let Some(mask) = number(&and[1])
                    {
                        return mask;
                    }
                }
                values.iter().fold(0, |mask, (key, v)| {
                    let _ = key;
                    mask | mark_mask(v)
                })
            }
            _ => 0,
        }
    }
    /// Parse `nft -j list ruleset`. Never infer free mark bits from unknown expressions.
    pub fn occupied_nft(input: &[u8]) -> Result<OccupiedNft, InventoryError> {
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT {
            return Err(fail());
        }
        let json: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let items = json
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or_else(fail)?;
        if items.len() > 65_536 {
            return Err(fail());
        }
        let mut result = OccupiedNft::default();
        for item in items {
            let item = item.as_object().ok_or_else(fail)?;
            if item.len() != 1 {
                return Err(fail());
            }
            let (kind, body) = item.iter().next().ok_or_else(fail)?;
            let body = body.as_object().ok_or_else(fail)?;
            if kind == "table" {
                let family = body
                    .get("family")
                    .and_then(Value::as_str)
                    .ok_or_else(fail)?;
                let name = body.get("name").and_then(Value::as_str).ok_or_else(fail)?;
                result.xkeenwrt_table_exists |= family == "inet" && name == "xkeenwrt";
            }
            result.used_mark_mask |= mark_mask(&Value::Object(body.clone()));
        }
        Ok(result)
    }

    /// Resolve both addresses independently from live neighbour and unexpired
    /// dnsmasq lease evidence. Contradictions and missing evidence fail closed.
    pub fn resolve_client_and_management_mac(
        neighbours: &[u8],
        leases: &[u8],
        lan: &str,
        selected: std::net::Ipv4Addr,
        management: std::net::Ipv4Addr,
        now_unix: u64,
    ) -> Result<(String, String), InventoryError> {
        use std::collections::BTreeSet;
        let fail = || InventoryError::Unsupported;
        if neighbours.len() > MAX_INPUT
            || leases.len() > MAX_INPUT
            || selected == management
            || lan.is_empty()
        {
            return Err(fail());
        }
        let value: Value = serde_json::from_slice(neighbours).map_err(|_| fail())?;
        let entries = value.as_array().ok_or_else(fail)?;
        if entries.len() > MAX_RULES {
            return Err(fail());
        }
        let leases = std::str::from_utf8(leases).map_err(|_| fail())?;
        fn mac(value: &str) -> Option<String> {
            let parts: Vec<_> = value.split(':').collect();
            if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
                return None;
            }
            let bytes: Vec<u8> = parts
                .iter()
                .map(|p| u8::from_str_radix(p, 16))
                .collect::<Result<_, _>>()
                .ok()?;
            if bytes[0] & 1 != 0 || bytes.iter().all(|b| *b == 0) {
                return None;
            }
            Some(
                bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            )
        }
        let mut resolved = Vec::new();
        for address in [selected, management] {
            let mut observed = BTreeSet::new();
            for entry in entries {
                let e = entry.as_object().ok_or_else(fail)?;
                if e.get("dev").and_then(Value::as_str) != Some(lan)
                    || e.get("dst")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                        != Some(address)
                {
                    continue;
                }
                let state = e.get("state").ok_or_else(fail)?;
                let valid_state =
                    |s: &str| ["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"].contains(&s);
                let valid = state.as_str().is_some_and(valid_state)
                    || state.as_array().is_some_and(|a| {
                        !a.is_empty() && a.iter().all(|v| v.as_str().is_some_and(valid_state))
                    });
                if !valid {
                    return Err(fail());
                }
                observed.insert(
                    mac(e.get("lladdr").and_then(Value::as_str).ok_or_else(fail)?)
                        .ok_or_else(fail)?,
                );
            }
            let mut leased = BTreeSet::new();
            for line in leases.lines() {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                if fields.len() < 3 {
                    return Err(fail());
                }
                if fields[2].parse::<std::net::Ipv4Addr>().ok() != Some(address) {
                    continue;
                }
                let expiry: u64 = fields[0].parse().map_err(|_| fail())?;
                if expiry != 0 && expiry <= now_unix {
                    continue;
                }
                leased.insert(mac(fields[1]).ok_or_else(fail)?);
            }
            if observed.len() != 1 || observed != leased {
                return Err(fail());
            }
            resolved.push(observed.into_iter().next().ok_or_else(fail)?);
        }
        if resolved[0] == resolved[1] {
            return Err(fail());
        }
        Ok((resolved.remove(0), resolved.remove(0)))
    }

    /// Compatibility helper returning just the selected client MAC.
    pub fn resolve_client_mac(
        neighbours: &[u8],
        leases: &[u8],
        lan: &str,
        selected: std::net::Ipv4Addr,
        management: std::net::Ipv4Addr,
        now_unix: u64,
    ) -> Result<String, InventoryError> {
        resolve_client_and_management_mac(neighbours, leases, lan, selected, management, now_unix)
            .map(|pair| pair.0)
    }

    /// Only Ethernet-framed links with known kinds can support a MAC-wide IPv6 policy.
    pub fn ethernet_like(input: &[u8], ifname: &str) -> Result<bool, InventoryError> {
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT || ifname.is_empty() {
            return Err(fail());
        }
        let value: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let links = value.as_array().ok_or_else(fail)?;
        if links.len() > MAX_RULES {
            return Err(fail());
        }
        let mut found = None;
        for link in links {
            let link = link.as_object().ok_or_else(fail)?;
            if link.get("ifname").and_then(Value::as_str) != Some(ifname) {
                continue;
            }
            if found.is_some() {
                return Err(fail());
            }
            let is_ether = link.get("link_type").and_then(Value::as_str) == Some("ether");
            let kind_ok = match link.get("linkinfo") {
                None => true,
                Some(info) => info
                    .get("info_kind")
                    .and_then(Value::as_str)
                    .is_some_and(|s| ["bridge", "vlan", "veth"].contains(&s)),
            };
            found = Some(is_ether && kind_ok);
        }
        Ok(found.unwrap_or(false))
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DnsFacts {
        pub upstreams: Vec<super::Endpoint>,
        pub split_upstreams: Vec<(String, Option<super::Endpoint>)>,
        pub local_zones: Vec<String>,
        pub verified_loopback_chain_sha256: Option<String>,
    }

    impl DnsFacts {
        pub fn has_loopback_upstream(&self) -> bool {
            self.upstreams
                .iter()
                .chain(
                    self.split_upstreams
                        .iter()
                        .filter_map(|(_, target)| target.as_ref()),
                )
                .any(|endpoint| endpoint.address.is_loopback())
        }
    }

    /// A deliberately narrow dnsmasq configuration: one instance, explicit
    /// numeric upstreams, no implicit resolver file, and split domains routed back
    /// to the original dnsmasq. Unknown additional config sources are rejected.
    pub fn dnsmasq_facts(input: &[u8]) -> Result<DnsFacts, InventoryError> {
        use std::collections::BTreeSet;
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT {
            return Err(fail());
        }
        let value: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let values = value
            .get("values")
            .and_then(Value::as_object)
            .ok_or_else(fail)?;
        let instances: Vec<_> = values
            .values()
            .filter(|v| v.get(".type").and_then(Value::as_str) == Some("dnsmasq"))
            .collect();
        if instances.len() != 1 {
            return Err(fail());
        }
        let dns = instances[0].as_object().ok_or_else(fail)?;
        let resolver_servers = value
            .get("xkeenwrt_resolv_servers")
            .and_then(Value::as_array);
        let explicit = dns.get("noresolv").and_then(Value::as_str) == Some("1");
        if (!explicit
            && (dns.get("resolvfile").and_then(Value::as_str)
                != Some(crate::dns_snapshot::RESOLVER)
                || resolver_servers.is_none_or(|v| v.is_empty() || v.len() > 8)))
            || (explicit && resolver_servers.is_some())
            || [
                "serversfile",
                "confdir",
                "conf_file",
                "address",
                "addnhosts",
                "hostsdir",
                "dhcphostsfile",
            ]
            .iter()
            .any(|k| dns.contains_key(*k))
        {
            return Err(fail());
        }
        fn zone(s: &str) -> Option<String> {
            let s = s.trim_matches('/').trim_end_matches('.');
            if s.is_empty() || s.len() > 253 {
                return None;
            }
            let ascii = if s.is_ascii() {
                if !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                {
                    return None;
                }
                s.to_ascii_lowercase()
            } else {
                idna::domain_to_ascii(s).ok()?.to_ascii_lowercase()
            };
            Some(format!("+.{ascii}"))
        }
        let mut zones = BTreeSet::from(["+.in-addr.arpa".to_owned(), "+.ip6.arpa".to_owned()]);
        for field in ["local", "domain"] {
            if let Some(value) = dns.get(field) {
                zones.insert(zone(value.as_str().ok_or_else(fail)?).ok_or_else(fail)?);
            }
        }
        let mut servers: Vec<&str> = match dns.get("server") {
            None => Vec::new(),
            Some(Value::String(s)) => vec![s],
            Some(Value::Array(v)) => v
                .iter()
                .map(|v| v.as_str().ok_or_else(fail))
                .collect::<Result<_, _>>()?,
            _ => return Err(fail()),
        };
        if let Some(resolvers) = resolver_servers {
            for value in resolvers {
                let address = value.as_str().ok_or_else(fail)?;
                address.parse::<std::net::IpAddr>().map_err(|_| fail())?;
                servers.push(address);
            }
        }
        if servers.len() > 256 {
            return Err(fail());
        }
        fn endpoint(value: &str) -> Option<super::Endpoint> {
            let (host, port) = match value.rsplit_once('#') {
                Some((host, port)) => (host, port.parse::<u16>().ok()?),
                None => (value, 53),
            };
            let host = host
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .unwrap_or(host);
            let address = host.parse::<std::net::IpAddr>().ok()?;
            (port != 0 && !address.is_unspecified() && !address.is_multicast())
                .then_some(super::Endpoint { address, port })
        }
        let mut upstreams = BTreeSet::new();
        let mut split_upstreams = BTreeSet::new();
        for server in servers {
            if let Some(split) = server.strip_prefix('/') {
                let (domain, target) = split.split_once('/').ok_or_else(fail)?;
                let domain = zone(domain).ok_or_else(fail)?;
                zones.insert(domain.clone());
                let target = (!target.is_empty())
                    .then(|| endpoint(target).ok_or_else(fail))
                    .transpose()?;
                if target.as_ref().is_some_and(|v| v.address.is_loopback()) {
                    return Err(fail());
                }
                split_upstreams.insert((domain, target));
            } else {
                upstreams.insert(endpoint(server).ok_or_else(fail)?);
            }
        }
        if upstreams.is_empty() || zones.len() <= 2 {
            return Err(fail());
        }
        let endpoints = upstreams.iter().chain(
            split_upstreams
                .iter()
                .filter_map(|(_, target)| target.as_ref()),
        );
        if endpoints
            .clone()
            .any(|e| e.address.is_loopback() && [53, 1053].contains(&e.port))
        {
            return Err(fail());
        }
        let _has_loopback = endpoints.clone().any(|e| e.address.is_loopback());
        Ok(DnsFacts {
            upstreams: upstreams.into_iter().collect(),
            split_upstreams: split_upstreams.into_iter().collect(),
            local_zones: zones.into_iter().collect(),
            // Only the live chain verifier may set this field. Hashing dnsmasq
            // alone does not prove which process, if any, owns a loopback port.
            verified_loopback_chain_sha256: None,
        })
    }

    /// Reject an upstream that points back to a router-owned address. The
    /// only accepted local hop is a loopback endpoint whose proxy chain was
    /// independently bound to its config, process and socket owners.
    pub fn validate_dns_targets(
        dns: &DnsFacts,
        local_ipv4: &[String],
        local_ipv6: &[String],
        verified_loopback_chain: Option<&str>,
    ) -> Result<(), InventoryError> {
        let fail = || InventoryError::Unsupported;
        for endpoint in dns.upstreams.iter().chain(
            dns.split_upstreams
                .iter()
                .filter_map(|(_, target)| target.as_ref()),
        ) {
            if endpoint.address.is_loopback() {
                if [53, 1053].contains(&endpoint.port) || verified_loopback_chain.is_none() {
                    return Err(fail());
                }
                continue;
            }
            if local_ipv4.iter().chain(local_ipv6).any(|cidr| {
                cidr.split_once('/').and_then(|(ip, _)| ip.parse().ok()) == Some(endpoint.address)
            }) {
                return Err(fail());
            }
        }
        Ok(())
    }

    /// Resolve the sole running fixed https-dns-proxy instance from ubus.
    pub fn https_dns_proxy_pid(service_input: &[u8]) -> Result<Option<u32>, InventoryError> {
        let fail = || InventoryError::Unsupported;
        if service_input.len() > MAX_INPUT {
            return Err(fail());
        }
        let service: Value = serde_json::from_slice(service_input).map_err(|_| fail())?;
        let Some(instances) = service
            .get("https-dns-proxy")
            .and_then(|v| v.get("instances"))
            .and_then(Value::as_object)
        else {
            return Ok(None);
        };
        let mut running = None;
        for instance in instances.values() {
            match instance.get("running").and_then(Value::as_bool) {
                Some(false) => continue,
                Some(true) => (),
                None => return Err(fail()),
            }
            let pid = instance
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 1)
                .ok_or_else(fail)?;
            let command = instance
                .get("command")
                .and_then(Value::as_array)
                .and_then(|args| args.first())
                .and_then(Value::as_str)
                .ok_or_else(fail)?;
            if !command.ends_with("/https-dns-proxy") || running.replace(pid).is_some() {
                return Err(fail());
            }
        }
        Ok(running)
    }

    /// Resolve the socket inodes owned by the exact running binary advertised
    /// by procd. The PID alone is not sufficient: it can exit and be reused
    /// between the service query and `/proc` inspection.
    pub fn https_dns_proxy_socket_inodes(service_input: &[u8]) -> Result<Vec<u64>, InventoryError> {
        use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::Path};
        let fail = || InventoryError::Unsupported;
        let Some(pid) = https_dns_proxy_pid(service_input)? else {
            return Ok(Vec::new());
        };
        let service: Value = serde_json::from_slice(service_input).map_err(|_| fail())?;
        let instances = service
            .get("https-dns-proxy")
            .and_then(|v| v.get("instances"))
            .and_then(Value::as_object)
            .ok_or_else(fail)?;
        let instance = instances
            .values()
            .find(|instance| {
                instance.get("running").and_then(Value::as_bool) == Some(true)
                    && instance.get("pid").and_then(Value::as_u64) == Some(u64::from(pid))
            })
            .ok_or_else(fail)?;
        let command = instance
            .get("command")
            .and_then(Value::as_array)
            .and_then(|args| args.first())
            .and_then(Value::as_str)
            .filter(|command| {
                Path::new(command).file_name().and_then(|s| s.to_str()) == Some("https-dns-proxy")
            })
            .ok_or_else(fail)?;
        let proc = format!("/proc/{pid}");
        let stat_path = format!("{proc}/stat");
        let start_time = || -> Result<String, InventoryError> {
            let stat = std::fs::read(&stat_path).map_err(|_| fail())?;
            if stat.len() > 16_384 {
                return Err(fail());
            }
            let stat = std::str::from_utf8(&stat).map_err(|_| fail())?;
            let fields = stat
                .rsplit_once(')')
                .ok_or_else(fail)?
                .1
                .split_ascii_whitespace()
                .collect::<Vec<_>>();
            fields
                .get(19)
                .map(|value| (*value).to_owned())
                .ok_or_else(fail)
        };
        let before = start_time()?;
        let exe_path = format!("{proc}/exe");
        let executable = std::fs::canonicalize(&exe_path).map_err(|_| fail())?;
        let command = std::fs::canonicalize(command).map_err(|_| fail())?;
        if executable != command || std::fs::metadata(&executable).map_err(|_| fail())?.uid() != 0 {
            return Err(fail());
        }
        let mut inodes = BTreeSet::new();
        let descriptors = std::fs::read_dir(format!("{proc}/fd")).map_err(|_| fail())?;
        for (index, descriptor) in descriptors.enumerate() {
            if index >= 8192 {
                return Err(fail());
            }
            let descriptor = descriptor.map_err(|_| fail())?;
            let target = std::fs::read_link(descriptor.path()).map_err(|_| fail())?;
            let Some(raw) = target
                .to_str()
                .and_then(|target| target.strip_prefix("socket:["))
                .and_then(|target| target.strip_suffix(']'))
            else {
                continue;
            };
            inodes.insert(raw.parse::<u64>().map_err(|_| fail())?);
        }
        if start_time()? != before {
            return Err(fail());
        }
        Ok(inodes.into_iter().collect())
    }

    /// Verify every live loopback dnsmasq hop against the UCI https-dns-proxy
    /// configuration, procd identity and exact TCP/UDP socket inode ownership.
    /// A configured endpoint with no listener is retained as a dead end; an
    /// unknown listener or partial proxy listener is rejected.
    pub fn verified_loopback_chain(
        dns: &DnsFacts,
        dnsconfig: &[u8],
        proxyconfig: &[u8],
        proxyservice: &[u8],
        sockets: [&[u8]; 4],
        owned_inodes: &[u64],
    ) -> Result<Option<String>, InventoryError> {
        use std::collections::BTreeSet;
        let fail = || InventoryError::Unsupported;
        let loopbacks: Vec<_> = dns
            .upstreams
            .iter()
            .chain(
                dns.split_upstreams
                    .iter()
                    .filter_map(|(_, target)| target.as_ref()),
            )
            .filter(|endpoint| endpoint.address.is_loopback())
            .collect();
        if loopbacks.is_empty() {
            return Ok(None);
        }
        if [dnsconfig, proxyconfig, proxyservice]
            .into_iter()
            .chain(sockets)
            .any(|bytes| bytes.len() > MAX_INPUT)
        {
            return Err(fail());
        }
        let proxy: Value = serde_json::from_slice(proxyconfig).map_err(|_| fail())?;
        let sections = proxy
            .get("values")
            .and_then(Value::as_object)
            .ok_or_else(fail)?;
        let proxy_sections: Vec<_> = sections
            .values()
            .filter(|section| {
                section.get(".type").and_then(Value::as_str) == Some("https-dns-proxy")
            })
            .collect();
        let owned = https_dns_proxy_pid(proxyservice)?;
        let owned_inodes: BTreeSet<u64> = owned_inodes.iter().copied().collect();
        fn socket_rows(
            bytes: &[u8],
            port: u16,
            protocol: usize,
        ) -> Result<Vec<(String, u64)>, InventoryError> {
            let fail = || InventoryError::Unsupported;
            let text = std::str::from_utf8(bytes).map_err(|_| fail())?;
            let mut lines = text.lines();
            if !lines.next().is_some_and(|line| {
                line.split_ascii_whitespace()
                    .any(|part| part == "local_address")
            }) {
                return Err(fail());
            }
            let mut rows = Vec::new();
            for line in lines {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                let local = *fields.get(1).ok_or_else(fail)?;
                let (address, raw_port) = local.split_once(':').ok_or_else(fail)?;
                if raw_port.len() != 4 || !raw_port.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(fail());
                }
                if u16::from_str_radix(raw_port, 16).map_err(|_| fail())? != port {
                    continue;
                }
                let state = *fields.get(3).ok_or_else(fail)?;
                if (protocol == 0 && state != "0A") || (protocol == 1 && state != "07") {
                    continue;
                }
                let inode = fields
                    .get(9)
                    .ok_or_else(fail)?
                    .parse()
                    .map_err(|_| fail())?;
                rows.push((address.to_ascii_uppercase(), inode));
            }
            Ok(rows)
        }
        fn expected_address(address: std::net::IpAddr) -> String {
            match address {
                std::net::IpAddr::V4(v4) => v4
                    .octets()
                    .iter()
                    .rev()
                    .map(|b| format!("{b:02X}"))
                    .collect(),
                std::net::IpAddr::V6(v6) => v6
                    .octets()
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .flat_map(|chunk| chunk.iter().rev().copied())
                    .map(|b| format!("{b:02X}"))
                    .collect(),
            }
        }
        fn safe_https(section: &Value) -> Result<(), InventoryError> {
            let fail = || InventoryError::Unsupported;
            if section
                .get("enabled")
                .is_some_and(|value| value.as_str() != Some("1"))
            {
                return Err(fail());
            }
            let resolver = section
                .get("resolver_url")
                .and_then(Value::as_str)
                .ok_or_else(fail)?;
            let authority = resolver
                .strip_prefix("https://")
                .and_then(|value| value.split('/').next())
                .filter(|value| !value.is_empty() && !value.contains('@'))
                .ok_or_else(fail)?;
            let host = authority.split(':').next().ok_or_else(fail)?;
            if host.is_empty()
                || host.ends_with(".local")
                || host.ends_with(".lan")
                || host.parse::<std::net::IpAddr>().is_ok_and(|address| {
                    address.is_loopback()
                        || address.is_unspecified()
                        || address.is_multicast()
                        || match address {
                            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                            std::net::IpAddr::V6(v6) => {
                                v6.is_unique_local() || v6.is_unicast_link_local()
                            }
                        }
                })
            {
                return Err(fail());
            }
            let bootstrap = section
                .get("bootstrap_dns")
                .and_then(Value::as_str)
                .ok_or_else(fail)?;
            let values: Vec<_> = bootstrap.split(',').map(str::trim).collect();
            if values.is_empty()
                || values.iter().any(|value| {
                    value.parse::<std::net::IpAddr>().is_err_and(|_| true)
                        || value.parse::<std::net::IpAddr>().is_ok_and(|address| {
                            address.is_loopback()
                                || address.is_unspecified()
                                || address.is_multicast()
                                || match address {
                                    std::net::IpAddr::V4(v4) => {
                                        v4.is_private() || v4.is_link_local()
                                    }
                                    std::net::IpAddr::V6(v6) => {
                                        v6.is_unique_local() || v6.is_unicast_link_local()
                                    }
                                }
                        })
                })
            {
                return Err(fail());
            }
            Ok(())
        }
        let mut topology = Vec::new();
        for endpoint in loopbacks {
            let port = endpoint.port;
            let rows = [
                socket_rows(sockets[0], port, 0)?,
                socket_rows(sockets[1], port, 1)?,
                socket_rows(sockets[2], port, 0)?,
                socket_rows(sockets[3], port, 1)?,
            ];
            let any = rows.iter().any(|rows| !rows.is_empty());
            if !any {
                topology.push(format!("{}#{port}:unbound", endpoint.address));
                continue;
            }
            let exact = expected_address(endpoint.address);
            let ipv6 = endpoint.address.is_ipv6();
            let base = if ipv6 { 2 } else { 0 };
            if rows.iter().enumerate().any(|(index, entries)| {
                if (index >= 2) != ipv6 {
                    !entries.is_empty()
                } else {
                    entries
                        .iter()
                        .any(|(address, inode)| address != &exact || !owned_inodes.contains(inode))
                }
            }) || rows[base].len() > 1
                || rows[base + 1].len() != 1
            {
                return Err(fail());
            }
            let matching: Vec<_> = proxy_sections
                .iter()
                .filter(|section| {
                    section.get("listen_port").and_then(Value::as_str)
                        == Some(port.to_string().as_str())
                        && section.get("listen_addr").and_then(Value::as_str)
                            == Some(endpoint.address.to_string().as_str())
                })
                .collect();
            if matching.len() != 1 || owned.is_none() {
                return Err(fail());
            }
            safe_https(matching[0])?;
            topology.push(format!("{}#{port}:owned-https-dns-proxy", endpoint.address));
        }
        let dns: Value = serde_json::from_slice(dnsconfig).map_err(|_| fail())?;
        let canonical_proxy = super::canonical(&proxy, false);
        let canonical_dns = super::canonical(&dns, false);
        let chain = serde_json::json!({
            "dnsmasq": canonical_dns,
            "https_dns_proxy": canonical_proxy,
            "service_executable": owned.map(|_| "/https-dns-proxy"),
            "topology": topology,
        });
        Ok(Some(super::digest(&chain).map_err(|_| fail())?))
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AddressFacts {
        pub lan_address: std::net::Ipv4Addr,
        pub lan_cidrs: Vec<String>,
        pub local_ipv4: Vec<String>,
        pub local_ipv6: Vec<String>,
    }

    /// Parse all addresses from the kernel, retaining every non-default connected
    /// prefix. The LAN name must additionally be verified against netifd by caller.
    pub fn address_facts(input: &[u8], lan: &str) -> Result<AddressFacts, InventoryError> {
        use std::collections::BTreeSet;
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT || lan.is_empty() {
            return Err(fail());
        }
        let root: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let links = root.as_array().ok_or_else(fail)?;
        if links.len() > MAX_RULES {
            return Err(fail());
        }
        let mut local4 = BTreeSet::new();
        let mut local6 = BTreeSet::new();
        let mut lan4 = BTreeSet::new();
        let mut lan_addresses = BTreeSet::new();
        let mut found_lan = false;
        for link in links {
            let name = link
                .get("ifname")
                .and_then(Value::as_str)
                .ok_or_else(fail)?;
            if name == lan {
                if found_lan {
                    return Err(fail());
                }
                found_lan = true;
            }
            let addresses = link
                .get("addr_info")
                .and_then(Value::as_array)
                .ok_or_else(fail)?;
            if addresses.len() > 256 {
                return Err(fail());
            }
            for address in addresses {
                let family = address
                    .get("family")
                    .and_then(Value::as_str)
                    .ok_or_else(fail)?;
                let local = address
                    .get("local")
                    .and_then(Value::as_str)
                    .ok_or_else(fail)?;
                let prefix = address
                    .get("prefixlen")
                    .and_then(Value::as_u64)
                    .ok_or_else(fail)?;
                match family {
                    "inet" => {
                        let ip: std::net::Ipv4Addr = local.parse().map_err(|_| fail())?;
                        if !(1..=32).contains(&prefix) || ip.is_unspecified() || ip.is_multicast() {
                            return Err(fail());
                        }
                        let cidr = format!("{ip}/{prefix}");
                        local4.insert(cidr.clone());
                        if name == lan {
                            lan4.insert(cidr);
                            lan_addresses.insert(ip);
                        }
                    }
                    "inet6" => {
                        let ip: std::net::Ipv6Addr = local.parse().map_err(|_| fail())?;
                        if !(1..=128).contains(&prefix) || ip.is_unspecified() || ip.is_multicast()
                        {
                            return Err(fail());
                        }
                        local6.insert(format!("{ip}/{prefix}"));
                    }
                    _ => return Err(fail()),
                }
            }
        }
        if !found_lan || lan_addresses.len() != 1 || local4.is_empty() || local6.is_empty() {
            return Err(fail());
        }
        Ok(AddressFacts {
            lan_address: *lan_addresses.iter().next().ok_or_else(fail)?,
            lan_cidrs: lan4.into_iter().collect(),
            local_ipv4: local4.into_iter().collect(),
            local_ipv6: local6.into_iter().collect(),
        })
    }

    /// IPv6 neighbour entries are diagnostics and management exclusions only; the
    /// enforcement boundary is the independently corroborated Ethernet MAC.
    pub fn ipv6_for_mac(
        input: &[u8],
        lan: &str,
        expected_mac: &str,
    ) -> Result<Vec<std::net::Ipv6Addr>, InventoryError> {
        use std::collections::BTreeSet;
        let fail = || InventoryError::Unsupported;
        if input.len() > MAX_INPUT || lan.is_empty() || expected_mac.is_empty() {
            return Err(fail());
        }
        let root: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        let entries = root.as_array().ok_or_else(fail)?;
        if entries.len() > MAX_RULES {
            return Err(fail());
        }
        let mut addresses = BTreeSet::new();
        for entry in entries {
            if entry.get("dev").and_then(Value::as_str) != Some(lan)
                || !entry
                    .get("lladdr")
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.eq_ignore_ascii_case(expected_mac))
            {
                continue;
            }
            let Some(dst) = entry.get("dst").and_then(Value::as_str) else {
                return Err(fail());
            };
            let Ok(ip) = dst.parse::<std::net::Ipv6Addr>() else {
                continue;
            };
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(fail());
            }
            let state = entry.get("state").ok_or_else(fail)?;
            let valid =
                |s: &str| ["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"].contains(&s);
            if !(state.as_str().is_some_and(valid)
                || state.as_array().is_some_and(|a| {
                    !a.is_empty() && a.iter().all(|v| v.as_str().is_some_and(valid))
                }))
            {
                return Err(fail());
            }
            addresses.insert(ip);
        }
        Ok(addresses.into_iter().collect())
    }
    pub fn route_facts(
        input: &[u8],
        ipv6: bool,
        tables: &mut BTreeSet<u32>,
        local: &mut BTreeSet<String>,
    ) -> Result<(), InventoryError> {
        let fail = || InventoryError::Unsupported;
        let root: Value = serde_json::from_slice(input).map_err(|_| fail())?;
        for route in root.as_array().ok_or_else(fail)? {
            if let Some(table) = route.get("table") {
                let n = table
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .or_else(|| match table.as_str()? {
                        "main" => Some(254),
                        "local" => Some(255),
                        "default" => Some(253),
                        s => s.parse().ok(),
                    })
                    .ok_or_else(fail)?;
                tables.insert(n);
            }
            if route.get("gateway").is_some() {
                continue;
            }
            let Some(dst) = route.get("dst").and_then(Value::as_str) else {
                continue;
            };
            if dst == "default" {
                continue;
            }
            let cidr = if dst.contains('/') {
                dst.to_owned()
            } else {
                format!("{dst}/{}", if ipv6 { 128 } else { 32 })
            };
            let (host, prefix) = cidr.split_once('/').ok_or_else(fail)?;
            let prefix: u8 = prefix.parse().map_err(|_| fail())?;
            if prefix == 0
                || (ipv6 && (prefix > 128 || host.parse::<std::net::Ipv6Addr>().is_err()))
                || (!ipv6 && (prefix > 32 || host.parse::<std::net::Ipv4Addr>().is_err()))
            {
                return Err(fail());
            }
            local.insert(cidr);
        }
        Ok(())
    }
}

/// Prove that no object at this manifest's reserved nft/routing identities
/// remains. Foreign ambiguity is an error. Inputs must be fresh fixed queries.
pub fn resources_absent(
    manifest: &Manifest,
    nft: &[u8],
    rules4: &[u8],
    rules6: &[u8],
    routes4: &[u8],
    routes6: &[u8],
) -> std::io::Result<()> {
    let expected = OwnedExpectation {
        manifest,
        scope_manifest: None,
        nft: NftExpectation::Absent,
        routing: RoutingExpectation::Absent,
    };
    strip_nft(nft, &expected)?;
    strip_rules(rules4, manifest, false, false)?;
    strip_rules(rules6, manifest, false, true)?;
    strip_routes(routes4, manifest, false, false)?;
    strip_routes(routes6, manifest, false, true)?;
    Ok(())
}

#[cfg(test)]
mod foreign_counter_tests {
    use super::*;

    fn expectation<'a>(manifest: &'a Manifest) -> OwnedExpectation<'a> {
        OwnedExpectation {
            manifest,
            scope_manifest: None,
            nft: NftExpectation::Absent,
            routing: RoutingExpectation::Absent,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            failure_policy: crate::FailurePolicy::DirectOnFailure,
            owner_id: "00000000-0000-4000-8000-000000000001".into(),
            generation: 1,
            nft_semantic_sha256: "0".repeat(64),
            lan_interface: "br-test".into(),
            lan_address: "192.0.2.1".parse().unwrap(),
            lan_scope: None,
            capture_version: None,
            selected_mac: "02:00:00:00:00:02".into(),
            management_macs: vec!["02:00:00:00:00:03".into()],
            source_ipv4: "192.0.2.2".parse().unwrap(),
            management_ipv4: "192.0.2.3".parse().unwrap(),
            management_ipv6: vec![],
            local_ipv4: vec!["192.0.2.0/24".into()],
            selected_ipv6: vec![],
            local_ipv6: vec!["2001:db8::/64".into()],
            route_table: 100,
            mark: 0x100,
            mask: 0x100,
            priority: 10_000,
        }
    }

    #[test]
    fn named_counter_identity_and_rule_reference_survive_runtime_delta_normalization() {
        let manifest = manifest();
        let expected = expectation(&manifest);
        let initial = br#"{"nftables":[{"counter":{"family":"inet","table":"filter","name":"named_counter","handle":12,"packets":5,"bytes":200}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":14,"expr":[{"counter":"named_counter"},{"accept":null}]}}]}"#;
        let runtime_delta = br#"{"nftables":[{"counter":{"family":"inet","table":"filter","name":"named_counter","handle":99,"packets":900,"bytes":48000}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":77,"expr":[{"counter":"named_counter"},{"accept":null}]}}]}"#;
        let changed_reference = br#"{"nftables":[{"counter":{"family":"inet","table":"filter","name":"named_counter","handle":99,"packets":900,"bytes":48000}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":77,"expr":[{"counter":"other_counter"},{"accept":null}]}}]}"#;

        let initial_value = strip_nft(initial, &expected).unwrap();
        let initial_digest = digest(&initial_value).unwrap();
        assert_eq!(
            initial_digest,
            digest(&strip_nft(runtime_delta, &expected).unwrap()).unwrap()
        );
        assert_ne!(
            initial_digest,
            digest(&strip_nft(changed_reference, &expected).unwrap()).unwrap()
        );
        let objects = initial_value["nftables"].as_array().unwrap();
        assert_eq!(objects[0]["counter"]["name"], "named_counter");
        assert_eq!(objects[0]["counter"]["packets"], 0);
        assert_eq!(objects[0]["counter"]["bytes"], 0);
        assert_eq!(objects[1]["rule"]["expr"][0]["counter"], "named_counter");
    }
}
