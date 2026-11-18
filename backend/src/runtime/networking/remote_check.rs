//! Router-local evidence for a gateway started over Tailscale (decision 024).
//! The administrator is not in the LAN, so confirmation needs proof that LAN
//! clients can use the gateway: its DNS answers and a proxy reaches out.
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Name resolved through the gateway DNS listener.
pub const PROBE_NAME: &str = "www.gstatic.com";
/// URL Mihomo fetches through a proxy node.
pub const PROBE_URL: &str = "https://www.gstatic.com/generate_204";
/// Gateway DNS port of decision 021.
pub const GATEWAY_DNS_PORT: u16 = 1053;
/// Per-node delay timeout passed to Mihomo, in milliseconds.
pub const NODE_TIMEOUT_MS: u32 = 4000;
const MAX_CANDIDATES: usize = 8;
const PARALLEL: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteCheck {
    pub dns: bool,
    pub egress: Egress,
    /// LAN addresses already served through TProxy; shown, never required.
    pub lan_clients: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Egress {
    Ok {
        node: String,
        delay_ms: u32,
    },
    Failed {
        tested: u32,
    },
    /// The profile has no proxy node: nothing beyond DIRECT to test.
    Skipped,
}
impl RemoteCheck {
    pub fn verdict(&self) -> Result<(), super::transaction::Error> {
        if !self.dns {
            return Err(super::transaction::Error::RemoteDns);
        }
        match self.egress {
            Egress::Failed { .. } => Err(super::transaction::Error::RemoteEgress),
            Egress::Ok { .. } | Egress::Skipped => Ok(()),
        }
    }
}

/// A proxy node and the provider that owns it (`None`: the profile's `proxies:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub provider: Option<String>,
    pub name: String,
}

/// I/O used by the probes. Implemented by the live runtime and by tests.
pub trait Probe: Sync {
    /// One UDP DNS round trip; the raw response, if any arrived in time.
    fn dns(&self, server: SocketAddrV4, query: &[u8]) -> Option<Vec<u8>>;
    /// GET on the local Mihomo controller: JSON body of a 2xx response.
    fn controller(&self, segments: &[&str], query: &[(&str, &str)]) -> Option<serde_json::Value>;
}

/// Recursive A query for `name` with the given id.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    q
}
fn be16(r: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*r.get(i)?, *r.get(i + 1)?]))
}
/// Offset after a possibly compressed name; every step advances, so a
/// hostile response cannot loop.
fn skip_name(r: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *r.get(i)?;
        if len & 0xc0 == 0xc0 {
            r.get(i + 1)?;
            return Some(i + 2);
        }
        if len == 0 {
            return Some(i + 1);
        }
        i += 1 + usize::from(len);
    }
}
/// A response to query `id` with NOERROR and at least one IPv4 address.
pub fn dns_answer_ok(id: u16, r: &[u8]) -> bool {
    (|| {
        if be16(r, 0)? != id || r.get(2)? & 0x80 == 0 || r.get(3)? & 0x0f != 0 {
            return None;
        }
        let mut i = 12;
        for _ in 0..be16(r, 4)? {
            i = skip_name(r, i)? + 4;
        }
        for _ in 0..be16(r, 6)? {
            i = skip_name(r, i)?;
            let (kind, len) = (be16(r, i)?, usize::from(be16(r, i + 8)?));
            i += 10;
            r.get(i..i + len)?;
            if kind == 1 && len == 4 {
                return Some(true);
            }
            i += len;
        }
        Some(false)
    })()
    .unwrap_or(false)
}
/// Built-in outbounds and groups: nothing behind them is a proxy node.
const NOT_A_NODE: [&str; 12] = [
    "Direct",
    "Reject",
    "RejectDrop",
    "Pass",
    "PassRule",
    "Compatible",
    "Dns",
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
    "Relay",
];
/// Proxy nodes from `/providers/proxies`: the profile's own `proxies:` (the
/// `default` provider) first, then subscription providers, at most eight.
pub fn egress_candidates(providers: &serde_json::Value) -> Vec<Candidate> {
    let Some(map) = providers["providers"].as_object() else {
        return Vec::new();
    };
    let nodes = |p: &serde_json::Value| -> Vec<String> {
        p["proxies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|n| n["type"].as_str().is_some_and(|t| !NOT_A_NODE.contains(&t)))
            .filter_map(|n| n["name"].as_str().map(str::to_owned))
            .collect()
    };
    let mut out: Vec<Candidate> = map
        .get("default")
        .map(nodes)
        .unwrap_or_default()
        .into_iter()
        .map(|name| Candidate { provider: None, name })
        .collect();
    for (provider, p) in map {
        if provider != "default" && matches!(p["vehicleType"].as_str(), Some("HTTP" | "File")) {
            out.extend(nodes(p).into_iter().map(|name| Candidate {
                provider: Some(provider.clone()),
                name,
            }));
        }
    }
    out.truncate(MAX_CANDIDATES);
    out
}
/// Distinct LAN sources whose TProxy connections already received data.
pub fn lan_clients(connections: &serde_json::Value, lan_scope: &str) -> u32 {
    let Some((network, prefix)) = lan_scope.split_once('/') else {
        return 0;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return 0;
    };
    let mask = u32::MAX.checked_shl(32 - prefix.min(32)).unwrap_or(0);
    let sources: std::collections::BTreeSet<Ipv4Addr> = connections["connections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["metadata"]["type"] == "TProxy" && c["download"].as_u64().is_some_and(|d| d > 0))
        .filter_map(|c| c["metadata"]["sourceIP"].as_str()?.parse::<Ipv4Addr>().ok())
        .filter(|ip| u32::from(*ip) & mask == u32::from(network) & mask)
        .collect();
    sources.len() as u32
}
fn node_delay(probe: &impl Probe, c: &Candidate) -> Option<u32> {
    let timeout = NODE_TIMEOUT_MS.to_string();
    let query = [("url", PROBE_URL), ("timeout", timeout.as_str())];
    let body = match &c.provider {
        None => probe.controller(&["proxies", &c.name, "delay"], &query),
        Some(p) => probe.controller(&["providers", "proxies", p, &c.name, "healthcheck"], &query),
    }?;
    u32::try_from(body["delay"].as_u64()?).ok().filter(|d| *d > 0)
}
/// Run every probe. Bounded: two DNS tries and at most two batches of four
/// node checks, each limited by the controller and Mihomo timeouts.
pub fn run(probe: &impl Probe, lan_address: Ipv4Addr, lan_scope: &str) -> RemoteCheck {
    let server = SocketAddrV4::new(lan_address, GATEWAY_DNS_PORT);
    let dns = [0x5852u16, 0x5853].iter().any(|id| {
        probe
            .dns(server, &dns_query(*id, PROBE_NAME))
            .is_some_and(|r| dns_answer_ok(*id, &r))
    });
    let egress = match probe.controller(&["providers", "proxies"], &[]) {
        None => Egress::Failed { tested: 0 },
        Some(providers) => {
            let candidates = egress_candidates(&providers);
            if candidates.is_empty() {
                Egress::Skipped
            } else {
                let mut tested = 0;
                let mut found = None;
                for batch in candidates.chunks(PARALLEL) {
                    let delays: Vec<Option<u32>> = std::thread::scope(|s| {
                        let handles: Vec<_> = batch.iter().map(|c| s.spawn(|| node_delay(probe, c))).collect();
                        handles.into_iter().map(|h| h.join().ok().flatten()).collect()
                    });
                    tested += batch.len() as u32;
                    found = batch
                        .iter()
                        .zip(delays)
                        .find_map(|(c, d)| d.map(|d| (c.name.clone(), d)));
                    if found.is_some() {
                        break;
                    }
                }
                match found {
                    Some((node, delay_ms)) => Egress::Ok { node, delay_ms },
                    None => Egress::Failed { tested },
                }
            }
        }
    };
    let lan_clients = probe
        .controller(&["connections"], &[])
        .map(|c| lan_clients(&c, lan_scope));
    RemoteCheck {
        dns,
        egress,
        lan_clients,
    }
}

/// Probes from the runtime process: UDP to the gateway DNS listener (local
/// delivery over `lo`, which `inputguard` admits) and GETs on the local
/// Mihomo controller with its secret. Responses are size-bounded.
pub(crate) struct LiveProbe {
    secret: String,
    client: reqwest::blocking::Client,
}
impl LiveProbe {
    const MAX_BODY: u64 = 4 * 1024 * 1024;
    pub(crate) fn new(secret: &str) -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(u64::from(NODE_TIMEOUT_MS) + 2000))
            .build()
            .ok()?;
        Some(Self {
            secret: secret.to_owned(),
            client,
        })
    }
}
impl Probe for LiveProbe {
    fn dns(&self, server: SocketAddrV4, query: &[u8]) -> Option<Vec<u8>> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok()?;
        socket.connect(server).ok()?;
        socket.send(query).ok()?;
        let mut buffer = [0u8; 1500];
        let length = socket.recv(&mut buffer).ok()?;
        Some(buffer[..length].to_vec())
    }
    fn controller(&self, segments: &[&str], query: &[(&str, &str)]) -> Option<serde_json::Value> {
        use std::io::Read;
        let mut url = reqwest::Url::parse("http://127.0.0.1:9090/").ok()?;
        url.path_segments_mut().ok()?.clear().extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let response = self.client.get(url).bearer_auth(&self.secret).send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut body = Vec::new();
        response.take(Self::MAX_BODY + 1).read_to_end(&mut body).ok()?;
        if body.len() as u64 > Self::MAX_BODY {
            return None;
        }
        serde_json::from_slice(&body).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `/providers/proxies` shape observed on Mihomo 1.19.34 (17.11.2026).
    fn providers() -> serde_json::Value {
        json!({"providers":{
            "G":{"vehicleType":"Compatible","proxies":[{"name":"dead","type":"Socks5"}]},
            "default":{"vehicleType":"Compatible","proxies":[
                {"name":"DIRECT","type":"Direct"},{"name":"REJECT","type":"Reject"},
                {"name":"🇩🇪 reality-Тест","type":"Vless"},{"name":"G","type":"Selector"},
                {"name":"PASS","type":"Pass"}]},
            "subscription_1":{"vehicleType":"HTTP","proxies":[
                {"name":"nl-1","type":"Vless"},{"name":"direct-node","type":"Direct"},
                {"name":"auto","type":"URLTest"},{"name":"de-2","type":"Trojan"}]}
        }})
    }

    #[test]
    fn candidates_are_real_nodes_of_the_profile_and_its_subscriptions() {
        let c = egress_candidates(&providers());
        let names: Vec<_> = c.iter().map(|c| (c.provider.as_deref(), c.name.as_str())).collect();
        assert_eq!(
            names,
            vec![
                (None, "🇩🇪 reality-Тест"),
                (Some("subscription_1"), "nl-1"),
                (Some("subscription_1"), "de-2"),
            ]
        );
        let many = json!({"providers":{"sub":{"vehicleType":"File","proxies":
            (0..20).map(|i| json!({"name":format!("n{i}"),"type":"Socks5"})).collect::<Vec<_>>()}}});
        assert_eq!(egress_candidates(&many).len(), 8);
        assert!(egress_candidates(&json!({})).is_empty());
    }

    #[test]
    fn dns_probe_needs_a_matching_noerror_answer_with_an_a_record() {
        let q = dns_query(0x1234, "www.gstatic.com");
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..17], &[3, b'w', b'w', b'w', 7]);
        assert_eq!(&q[q.len() - 5..], &[0, 0, 1, 0, 1]);
        let answer = |id: u16, rcode: u8, rtype: u16| {
            let mut r = q.clone();
            r[..2].copy_from_slice(&id.to_be_bytes());
            r[2] = 0x81;
            r[3] = 0x80 | rcode;
            r[7] = 1;
            r.extend([0xc0, 12]);
            r.extend(rtype.to_be_bytes());
            r.extend([0, 1, 0, 0, 0, 60, 0, 4, 142, 250, 74, 99]);
            r
        };
        assert!(dns_answer_ok(0x1234, &answer(0x1234, 0, 1)));
        assert!(!dns_answer_ok(0x1234, &answer(0x4321, 0, 1)), "other id");
        assert!(!dns_answer_ok(0x1234, &answer(0x1234, 3, 1)), "NXDOMAIN");
        assert!(!dns_answer_ok(0x1234, &answer(0x1234, 0, 5)), "CNAME only");
        assert!(!dns_answer_ok(0x1234, &q), "a query is not an answer");
        assert!(!dns_answer_ok(0x1234, &answer(0x1234, 0, 1)[..20]), "truncated");
    }

    #[test]
    fn lan_clients_counts_distinct_tproxy_sources_with_traffic() {
        let c = json!({"connections":[
            {"download":10,"metadata":{"type":"TProxy","sourceIP":"192.168.5.20"}},
            {"download":99,"metadata":{"type":"TProxy","sourceIP":"192.168.5.20"}},
            {"download":5,"metadata":{"type":"TProxy","sourceIP":"192.168.5.30"}},
            {"download":0,"metadata":{"type":"TProxy","sourceIP":"192.168.5.40"}},
            {"download":7,"metadata":{"type":"HTTPS","sourceIP":"192.168.5.50"}},
            {"download":7,"metadata":{"type":"TProxy","sourceIP":"10.0.0.2"}}]});
        assert_eq!(lan_clients(&c, "192.168.5.0/24"), 2);
        assert_eq!(lan_clients(&json!({"connections":null}), "192.168.5.0/24"), 0);
    }

    struct Fake {
        dns: bool,
        providers: Option<serde_json::Value>,
        alive: &'static [&'static str],
    }
    impl Probe for Fake {
        fn dns(&self, server: SocketAddrV4, query: &[u8]) -> Option<Vec<u8>> {
            assert_eq!(server, "192.168.5.1:1053".parse().unwrap());
            if !self.dns {
                return None;
            }
            let mut r = query.to_vec();
            r[2] = 0x81;
            r[3] = 0x80;
            r[7] = 1;
            r.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 142, 250, 74, 99]);
            Some(r)
        }
        fn controller(&self, segments: &[&str], query: &[(&str, &str)]) -> Option<serde_json::Value> {
            match segments {
                ["providers", "proxies"] => self.providers.clone(),
                ["connections"] => Some(json!({"connections":[
                    {"download":3,"metadata":{"type":"TProxy","sourceIP":"192.168.5.20"}}]})),
                ["proxies", name, "delay"] | ["providers", "proxies", _, name, "healthcheck"] => {
                    assert!(query.contains(&("url", PROBE_URL)));
                    self.alive.contains(name).then(|| json!({"delay":49}))
                }
                other => panic!("unexpected controller call {other:?}"),
            }
        }
    }

    #[test]
    fn verdict_requires_dns_and_one_live_proxy_unless_the_profile_has_none() {
        use super::super::transaction::Error;
        let scope = "192.168.5.0/24";
        let lan = "192.168.5.1".parse().unwrap();
        let ok = run(
            &Fake {
                dns: true,
                providers: Some(providers()),
                alive: &["de-2"],
            },
            lan,
            scope,
        );
        assert_eq!(
            ok.egress,
            Egress::Ok {
                node: "de-2".into(),
                delay_ms: 49
            }
        );
        assert_eq!(ok.lan_clients, Some(1));
        assert_eq!(ok.verdict(), Ok(()));
        let no_dns = run(
            &Fake {
                dns: false,
                providers: Some(providers()),
                alive: &["nl-1"],
            },
            lan,
            scope,
        );
        assert_eq!(no_dns.verdict(), Err(Error::RemoteDns));
        let dead = run(
            &Fake {
                dns: true,
                providers: Some(providers()),
                alive: &[],
            },
            lan,
            scope,
        );
        assert_eq!(dead.egress, Egress::Failed { tested: 3 });
        assert_eq!(dead.verdict(), Err(Error::RemoteEgress));
        let direct_only = json!({"providers":{"default":{"vehicleType":"Compatible","proxies":[
            {"name":"DIRECT","type":"Direct"}]}}});
        let skipped = run(
            &Fake {
                dns: true,
                providers: Some(direct_only),
                alive: &[],
            },
            lan,
            scope,
        );
        assert_eq!(skipped.egress, Egress::Skipped);
        assert_eq!(skipped.verdict(), Ok(()));
        // An unreachable controller is a failure, never "no proxies".
        let blind = run(
            &Fake {
                dns: true,
                providers: None,
                alive: &[],
            },
            lan,
            scope,
        );
        assert_eq!(blind.egress, Egress::Failed { tested: 0 });
        assert_eq!(blind.verdict(), Err(Error::RemoteEgress));
    }
}
