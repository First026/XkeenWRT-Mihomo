//! Conservative completeness check shared with the isolated validator.
//! `true` means that the reviewed profile requires no external assets; it is
//! not a substitute for core syntax validation or proof of network safety.
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
pub mod mrs;
/// The upstream template contains 41 providers; retain the 8 MiB byte budget.
pub const MAX_PROVIDER_FILES: usize = 64;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(n.into()))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(Unique(out.into()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(A::Error::custom("duplicate key"));
                    }
                    let Unique(value) = map.next_value()?;
                    out.insert(key, value);
                }
                Ok(Unique(out.into()))
            }
        }
        d.deserialize_any(V)
    }
}

fn keys(v: &Value, allowed: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().all(|k| allowed.contains(&k.as_str())))
}

fn safe_sniffer(v: &Value, rule_names: &HashSet<String>) -> bool {
    if !keys(
        v,
        &[
            "enable",
            "force-dns-mapping",
            "parse-pure-ip",
            "override-destination",
            "sniff",
            "skip-domain",
            "force-domain",
            "skip-src-address",
            "skip-dst-address",
        ],
    ) {
        return false;
    }
    for name in [
        "enable",
        "force-dns-mapping",
        "parse-pure-ip",
        "override-destination",
    ] {
        if v.get(name).is_some_and(|x| !x.is_boolean()) {
            return false;
        }
    }
    for name in [
        "skip-domain",
        "force-domain",
        "skip-src-address",
        "skip-dst-address",
    ] {
        if v.get(name).is_some_and(|x| {
            !x.as_array().is_some_and(|items| {
                items.iter().all(|x| {
                    let Some(s) = x.as_str() else {
                        return false;
                    };
                    if s.is_empty() || s.len() > 512 || s.chars().any(char::is_control) {
                        return false;
                    }
                    if name.ends_with("domain") {
                        !s.contains(':') && !s.chars().any(char::is_whitespace)
                    } else if let Some(provider) = s.strip_prefix("rule-set:") {
                        rule_names.contains(provider)
                    } else {
                        let (address, prefix) =
                            s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
                        address.parse::<std::net::IpAddr>().is_ok_and(|ip| {
                            prefix.is_none_or(|p| {
                                p.parse::<u8>()
                                    .is_ok_and(|n| n <= if ip.is_ipv4() { 32 } else { 128 })
                            })
                        })
                    }
                })
            })
        }) {
            return false;
        }
    }
    v.get("sniff").is_none_or(|sniff| sniff.as_object().is_some_and(|protocols| protocols.iter().all(|(name, settings)| {
        ["HTTP", "TLS", "QUIC"].contains(&name.as_str())
            && keys(settings, &["ports", "override-destination"])
            && settings.get("override-destination").is_none_or(Value::is_boolean)
            && settings.get("ports").is_none_or(|ports| ports.as_array().is_some_and(|ports| ports.iter().all(|port| {
                port.as_u64().is_some_and(|n| (1..=65535).contains(&n))
                    || port.as_str().is_some_and(|s| s.split_once('-').is_some_and(|(a, b)| {
                        matches!((a.parse::<u16>(), b.parse::<u16>()), (Ok(a), Ok(b)) if a != 0 && a <= b)
                    }))
            })))
    })))
}

fn safe_classical_rule(rule: &str, depth: usize, references: &HashSet<String>) -> bool {
    if depth > 16 {
        return false;
    }
    let Some((kind, rest)) = rule.split_once(',') else {
        return false;
    };
    if kind == "RULE-SET" {
        let fields: Vec<_> = rest.split(',').collect();
        return depth > 0
            && fields.len() <= 3
            && references.contains(fields[0])
            && fields[1..]
                .iter()
                .all(|p| matches!(*p, "no-resolve" | "src"));
    }
    if !["AND", "OR", "NOT"].contains(&kind) {
        return matches!(
            kind,
            "DOMAIN"
                | "DOMAIN-SUFFIX"
                | "DOMAIN-KEYWORD"
                | "DOMAIN-REGEX"
                | "IP-CIDR"
                | "IP-CIDR6"
                | "SRC-IP-CIDR"
                | "SRC-IP-CIDR6"
                | "SRC-PORT"
                | "DST-PORT"
                | "NETWORK"
                | "PROCESS-NAME"
                | "PROCESS-NAME-REGEX"
                | "PROCESS-PATH-REGEX"
                | "PROCESS-PATH"
        );
    }
    let Some(mut items) = rest.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    let mut count = 0;
    while !items.is_empty() {
        if !items.starts_with('(') {
            return false;
        }
        let mut nesting = 0;
        let mut end = None;
        for (i, c) in items.char_indices() {
            if c == '(' {
                nesting += 1;
            }
            if c == ')' {
                nesting -= 1;
            }
            if nesting == 0 {
                end = Some(i);
                break;
            }
        }
        let Some(end) = end else {
            return false;
        };
        if !safe_classical_rule(&items[1..end], depth + 1, references) {
            return false;
        }
        count += 1;
        items = &items[end + 1..];
        if !items.is_empty() {
            let Some(tail) = items.strip_prefix(',').filter(|s| !s.is_empty()) else {
                return false;
            };
            items = tail;
        }
    }
    if kind == "NOT" {
        count == 1
    } else {
        count >= 2
    }
}
fn safe_proxy(v: &Value) -> bool {
    const KEYS: &[&str] = &[
        "name",
        "type",
        "server",
        "port",
        "udp",
        "ip-version",
        "dialer-proxy",
        "tfo",
        "mptcp",
        "udp-over-tcp",
        "udp-over-tcp-version",
        "cipher",
        "password",
        "uuid",
        "alterId",
        "alter-id",
        "security",
        "tls",
        "servername",
        "sni",
        "skip-cert-verify",
        "client-fingerprint",
        "fingerprint",
        "alpn",
        "network",
        "ws-opts",
        "grpc-opts",
        "h2-opts",
        "http-opts",
        "reality-opts",
        "packet-encoding",
        "packet-addr",
        "xudp",
        "flow",
        "encryption",
        "obfs",
        "obfs-password",
        "up",
        "down",
        "auth",
        "auth-str",
        "fast-open",
        "ip",
        "ipv6",
        "private-key",
        "public-key",
        "pre-shared-key",
        "mtu",
        "reserved",
        "remote-dns-resolve",
        "dns",
        "amnezia-wg-option",
        "peers",
        "keepalive",
        "workers",
        "preshared-key",
        "allowed-ips",
        "endpoint",
        "persistent-keepalive",
        "refresh-server-ip-interval",
        "ip-stack",
        "congestion-controller",
        "jc",
        "jmin",
        "jmax",
        "s1",
        "s2",
        "h1",
        "h2",
        "h3",
        "h4",
        "jc",
        "host",
        "method",
        "service-name",
        "grpc-service-name",
        "authority",
        "public-key",
        "short-id",
        "support-x25519mlkem768",
        "mode",
        "mux",
        "enabled",
        "max-connections",
        "min-streams",
        "max-streams",
        "padding",
        "statistic",
        "only-tcp",
        "smux",
        "protocol",
        "max-padding",
        "min-padding",
    ];
    fn recursive(v: &Value, parent: &str) -> bool {
        match v {
            Value::Object(m) if parent == "amnezia-wg-option" => m.iter().all(|(k, v)| {
                [
                    "version",
                    "j1",
                    "j2",
                    "j3",
                    "itime",
                    "jc",
                    "jmin",
                    "jmax",
                    "s1",
                    "s2",
                    "s3",
                    "s4",
                    "h1",
                    "h2",
                    "h3",
                    "h4",
                    "i1",
                    "i2",
                    "i3",
                    "i4",
                    "i5",
                    "header-protection-key",
                    "content-padding-addition",
                    "rekey-after-time",
                    "rekey-timeout",
                    "reject-after-time",
                    "keepalive-timeout",
                    "max-handshake-attempts",
                    "random-trailers",
                    "disable-cookies",
                ]
                .contains(&k.as_str())
                    && (v.is_string() || v.is_number() || v.is_boolean())
            }),
            Value::Object(m) if parent == "headers" => m.iter().all(|(k, v)| {
                !k.is_empty()
                    && k.len() <= 128
                    && (v.as_str().is_some_and(|s| s.len() <= 2048)
                        || v.as_array().is_some_and(|a| {
                            a.iter()
                                .all(|x| x.as_str().is_some_and(|s| s.len() <= 2048))
                        }))
            }),
            Value::Object(m) => m.iter().all(|(k, v)| {
                if k == "path" {
                    return matches!(parent, "ws-opts" | "http-opts")
                        && (v
                            .as_str()
                            .is_some_and(|s| s.starts_with('/') && s.len() <= 2048)
                            || v.as_array().is_some_and(|a| {
                                a.iter().all(|x| {
                                    x.as_str()
                                        .is_some_and(|s| s.starts_with('/') && s.len() <= 2048)
                                })
                            }));
                }
                if k == "headers" {
                    return matches!(parent, "ws-opts" | "http-opts") && recursive(v, k);
                }
                KEYS.contains(&k.as_str()) && recursive(v, k)
            }),
            Value::Array(a) => a.iter().all(|v| recursive(v, parent)),
            _ => true,
        }
    }
    keys(v, KEYS)
        && matches!(
            v.get("type").and_then(Value::as_str),
            Some("wireguard" | "vless" | "vmess" | "trojan" | "ss" | "hysteria2")
        )
        && recursive(v, "")
}
/// Accept only the canonical effective JSON generated by the backend and
/// profiles whose lazy dependencies are fully known to be absent.
pub fn asset_free_complete(config: &str) -> bool {
    let Ok(Unique(v)) = serde_json::from_str::<Unique>(config) else {
        return false;
    };
    let Some(root) = v.as_object() else {
        return false;
    };
    const ROOT: &[&str] = &[
        "mode",
        "log-level",
        "ipv6",
        "unified-delay",
        "tcp-concurrent",
        "find-process-mode",
        "global-client-fingerprint",
        "global-ua",
        "keep-alive-interval",
        "keep-alive-idle",
        "disable-keep-alive",
        "etag-support",
        "proxies",
        "proxy-groups",
        "rules",
        "hosts",
        "mixed-port",
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "allow-lan",
        "bind-address",
        "external-controller",
        "external-controller-tls",
        "external-controller-unix",
        "external-controller-pipe",
        "external-doh-server",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "secret",
        "ss-config",
        "vmess-config",
        "external-controller-routing-mark",
        "routing-mark",
        "interface-name",
        "listeners",
        "tunnels",
        "tun",
        "iptables",
        "ntp",
        "tuic-server",
        "dns",
        "profile",
        "sniffer",
        "geo-auto-update",
    ];
    if !root.keys().all(|k| ROOT.contains(&k.as_str())) {
        return false;
    }
    if root
        .get("sniffer")
        .is_some_and(|s| !safe_sniffer(s, &HashSet::new()))
    {
        return false;
    }
    if root.get("global-ua").is_some_and(|v| {
        !v.as_str()
            .is_some_and(|s| s.len() <= 512 && !s.chars().any(char::is_control))
    }) {
        return false;
    }
    for (key, expected) in [
        ("mixed-port", serde_json::json!(7890)),
        ("port", serde_json::json!(0)),
        ("socks-port", serde_json::json!(0)),
        ("redir-port", serde_json::json!(0)),
        ("tproxy-port", serde_json::json!(0)),
        ("allow-lan", serde_json::json!(false)),
        ("bind-address", serde_json::json!("127.0.0.1")),
        ("external-controller", serde_json::json!("127.0.0.1:9090")),
        ("external-controller-tls", serde_json::json!("")),
        ("external-controller-unix", serde_json::json!("")),
        ("external-controller-pipe", serde_json::json!("")),
        ("external-doh-server", serde_json::json!("")),
        ("external-ui", serde_json::json!("")),
        ("external-ui-url", serde_json::json!("")),
        ("external-ui-name", serde_json::json!("")),
        ("ss-config", serde_json::json!("")),
        ("vmess-config", serde_json::json!("")),
        ("routing-mark", serde_json::json!(0)),
        ("external-controller-routing-mark", serde_json::json!(0)),
        ("interface-name", serde_json::json!("")),
        ("listeners", serde_json::json!([])),
        ("tunnels", serde_json::json!([])),
        ("geo-auto-update", serde_json::json!(false)),
        (
            "tun",
            serde_json::json!({"enable":false,"auto-route":false,"auto-redirect":false,"auto-detect-interface":false,"dns-hijack":[]}),
        ),
        (
            "iptables",
            serde_json::json!({"enable":false,"dns-redirect":false}),
        ),
        (
            "ntp",
            serde_json::json!({"enable":false,"write-to-system":false}),
        ),
        ("tuic-server", serde_json::json!({"enable":false})),
        (
            "dns",
            serde_json::json!({"enable":false,"enhanced-mode":"normal","listen":"","use-system-hosts":false,"fallback-filter":{"geoip":false}}),
        ),
        (
            "profile",
            serde_json::json!({"store-selected":false,"store-fake-ip":false}),
        ),
    ] {
        if root.get(key) != Some(&expected) {
            return false;
        }
    }
    if !root
        .get("secret")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return false;
    }
    if root
        .get("proxies")
        .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(safe_proxy)))
    {
        return false;
    }
    if root.get("proxy-groups").is_some_and(|v| {
        !v.as_array().is_some_and(|a| {
            a.iter().all(|g| {
                keys(
                    g,
                    &[
                        "name",
                        "type",
                        "proxies",
                        "url",
                        "interval",
                        "timeout",
                        "tolerance",
                        "lazy",
                        "disable-udp",
                        "strategy",
                        "hidden",
                        "icon",
                        "expected-status",
                        "use",
                        "filter",
                        "exclude-filter",
                        "exclude-type",
                        "include-all",
                        "include-all-proxies",
                        "include-all-providers",
                        "max-failed-times",
                    ],
                ) && matches!(
                    g.get("type").and_then(Value::as_str),
                    Some("select" | "url-test" | "fallback" | "load-balance")
                ) && g
                    .get("url")
                    .is_none_or(|u| u.as_str() == Some("https://www.gstatic.com/generate_204"))
            })
        })
    }) {
        return false;
    }
    if root.get("rules").is_some_and(|v| {
        !v.as_array().is_some_and(|a| {
            a.iter().all(|r| {
                r.as_str().is_some_and(|s| {
                    matches!(
                        s.split(',').next(),
                        Some(
                            "DOMAIN"
                                | "DOMAIN-SUFFIX"
                                | "DOMAIN-KEYWORD"
                                | "DOMAIN-REGEX"
                                | "IP-CIDR"
                                | "IP-CIDR6"
                                | "SRC-IP-CIDR"
                                | "SRC-IP-CIDR6"
                                | "SRC-PORT"
                                | "DST-PORT"
                                | "IN-PORT"
                                | "IN-TYPE"
                                | "IN-USER"
                                | "IN-NAME"
                                | "PROCESS-PATH"
                                | "PROCESS-PATH-REGEX"
                                | "PROCESS-NAME"
                                | "PROCESS-NAME-REGEX"
                                | "NETWORK"
                                | "DSCP"
                                | "MATCH"
                        )
                    )
                })
            })
        })
    }) {
        return false;
    }
    if root.get("hosts").is_some_and(|v| {
        !v.as_object().is_some_and(|m| {
            m.values().all(|v| {
                v.is_string() || v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
            })
        })
    }) {
        return false;
    }
    true
}

/// A staged file in the private Mihomo home. Paths are generated by this crate's caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub path: String,
    pub content: Vec<u8>,
}

/// Parse a single, unambiguous YAML document; aliases, tags and duplicate keys are forbidden.
pub fn parse_document(source: &str) -> Result<Value, PolicyError> {
    use yaml_rust2::{
        parser::{Event, Parser},
        scanner::TScalarStyle,
        Yaml, YamlLoader,
    };
    if source.len() > 2 * 1024 * 1024 {
        return Err(PolicyError);
    }
    enum Frame {
        Map(bool, HashSet<String>),
        Seq,
    }
    let mut frames = Vec::new();
    let mut nodes = 0usize;
    let mut documents = 0;
    let mut p = Parser::new(source.chars());
    loop {
        let (event, _) = p.next_token().map_err(|_| PolicyError)?;
        match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(PolicyError);
                }
            }
            Event::Alias(_) => return Err(PolicyError),
            Event::Scalar(value, style, anchor, tag) => {
                nodes += 1;
                if anchor != 0 || tag.is_some() {
                    return Err(PolicyError);
                }
                if style == TScalarStyle::Plain {
                    let low = value.to_ascii_lowercase();
                    if ["yes", "no", "on", "off", "y", "n"].contains(&low.as_str())
                        || (low == "null" && value != "null")
                    {
                        return Err(PolicyError);
                    }
                    let n = value.strip_prefix(['+', '-']).unwrap_or(&value);
                    if n.len() > 1 && n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(PolicyError);
                    }
                    let lower_n = n.to_ascii_lowercase();
                    if lower_n.starts_with("0x")
                        || lower_n.starts_with("0o")
                        || lower_n.starts_with("0b")
                        || value.starts_with('+')
                    {
                        return Err(PolicyError);
                    }
                    if n.contains('_')
                        && n.bytes().all(|b| {
                            b.is_ascii_digit()
                                || matches!(b, b'_' | b'.' | b'+' | b'-' | b'e' | b'E')
                        })
                    {
                        return Err(PolicyError);
                    }
                    if n.len() >= 10
                        && n.as_bytes().get(4) == Some(&b'-')
                        && n.as_bytes().get(7) == Some(&b'-')
                        && n.as_bytes()[..4].iter().all(u8::is_ascii_digit)
                    {
                        return Err(PolicyError);
                    }
                    if matches!(Yaml::from_str(&value), Yaml::Real(_))
                        && value.parse::<serde_json::Number>().is_err()
                    {
                        return Err(PolicyError);
                    }
                    if n.bytes().all(|b| b.is_ascii_digit())
                        && !n.is_empty()
                        && value.parse::<i64>().is_err()
                    {
                        return Err(PolicyError);
                    }
                }
                if let Some(Frame::Map(key, seen)) = frames.last_mut() {
                    if *key
                        && (value == "<<"
                            || (style == TScalarStyle::Plain
                                && !matches!(Yaml::from_str(&value), Yaml::String(_)))
                            || !seen.insert(value))
                    {
                        return Err(PolicyError);
                    }
                    *key = !*key;
                }
            }
            Event::MappingStart(anchor, ref tag) | Event::SequenceStart(anchor, ref tag) => {
                nodes += 1;
                if anchor != 0 || tag.is_some() {
                    return Err(PolicyError);
                }
                if let Some(Frame::Map(key, _)) = frames.last_mut() {
                    if *key {
                        return Err(PolicyError);
                    }
                    *key = true;
                }
                frames.push(if matches!(event, Event::MappingStart(..)) {
                    Frame::Map(true, HashSet::new())
                } else {
                    Frame::Seq
                });
                if frames.len() > 64 {
                    return Err(PolicyError);
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                frames.pop().ok_or(PolicyError)?;
            }
            _ => (),
        }
        if nodes > 50_000 {
            return Err(PolicyError);
        }
    }
    fn convert(y: &Yaml) -> Result<Value, PolicyError> {
        Ok(match y {
            Yaml::String(s) => Value::String(s.clone()),
            Yaml::Integer(n) => (*n).into(),
            Yaml::Real(n) => Value::Number(
                serde_json::Number::from_f64(n.parse().map_err(|_| PolicyError)?)
                    .ok_or(PolicyError)?,
            ),
            Yaml::Boolean(b) => Value::Bool(*b),
            Yaml::Null => Value::Null,
            Yaml::Array(a) => Value::Array(a.iter().map(convert).collect::<Result<_, _>>()?),
            Yaml::Hash(h) => {
                let mut m = serde_json::Map::new();
                for (k, v) in h {
                    let Yaml::String(k) = k else {
                        return Err(PolicyError);
                    };
                    m.insert(k.clone(), convert(v)?);
                }
                Value::Object(m)
            }
            _ => return Err(PolicyError),
        })
    }
    let docs = YamlLoader::load_from_str(source).map_err(|_| PolicyError)?;
    if docs.len() != 1 {
        return Err(PolicyError);
    }
    convert(&docs[0])
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyError;

/// Validate proxy-provider payload before it is staged or consumed by the core.
pub fn proxy_payload_complete(data: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(data) else {
        return false;
    };
    let Ok(v) = parse_document(s) else {
        return false;
    };
    keys(&v, &["proxies"])
        && v.get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty() && a.iter().all(safe_proxy))
}

/// Validate a YAML rule-provider payload without resolving network or filesystem resources.
pub fn rule_payload_complete(data: &[u8], behavior: &str) -> bool {
    rule_payload_complete_with_refs(data, behavior, &HashSet::new())
}
/// Only domain/IP sets can be dependencies: this excludes cycles and recursive classical sets.
fn leaf_names(value: &Value) -> HashSet<String> {
    value
        .get("rule-providers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, p)| {
            matches!(
                p.get("behavior").and_then(Value::as_str),
                Some("domain" | "ipcidr")
            )
        })
        .map(|(name, _)| name.clone())
        .collect()
}
pub fn leaf_rule_provider_names(config: &str) -> Result<HashSet<String>, PolicyError> {
    parse_document(config).map(|v| leaf_names(&v))
}
/// References are accepted only when bound to the complete staged provider set by `complete`.
pub fn rule_payload_complete_with_refs(
    data: &[u8],
    behavior: &str,
    references: &HashSet<String>,
) -> bool {
    let Ok(s) = std::str::from_utf8(data) else {
        return false;
    };
    let Ok(v) = parse_document(s) else {
        return false;
    };
    keys(&v, &["payload"])
        && v.get("payload").and_then(Value::as_array).is_some_and(|a| {
            a.iter().all(|item| {
                item.as_str().is_some_and(|s| {
                    if s.is_empty() || s.len() > 2048 || s.chars().any(char::is_control) {
                        return false;
                    }
                    match behavior {
                        "domain" => s.bytes().all(|b| {
                            b.is_ascii_alphanumeric()
                                || matches!(b, b'.' | b'-' | b'+' | b'*' | b'_')
                        }),
                        "ipcidr" => s
                            .split('/')
                            .next()
                            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok()),
                        "classical" => safe_classical_rule(s, 0, references),
                        _ => false,
                    }
                })
            })
        })
}

/// Completeness check for a prepared configuration and its exact staged assets.
pub fn complete(config: &str, assets: &[Asset]) -> bool {
    if assets.len() > MAX_PROVIDER_FILES
        || assets.iter().map(|a| a.content.len()).sum::<usize>() > 8 * 1024 * 1024
    {
        return false;
    }
    let Ok(mut value) = parse_document(config) else {
        return false;
    };
    let references = leaf_names(&value);
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    let mut expected = HashSet::new();
    if let Some(providers) = root.remove("proxy-providers") {
        let Some(map) = providers.as_object() else {
            return false;
        };
        for (i, (_, provider)) in map.iter().enumerate() {
            let path = format!("providers/proxies/{i}.yaml");
            if !keys(
                provider,
                &[
                    "type",
                    "path",
                    "health-check",
                    "filter",
                    "exclude-filter",
                    "exclude-type",
                    "override",
                    "size-limit",
                ],
            ) || provider.get("type").and_then(Value::as_str) != Some("file")
                || provider.get("path").and_then(Value::as_str) != Some(path.as_str())
            {
                return false;
            }
            if let Some(health) = provider.get("health-check") {
                if !keys(
                    health,
                    &[
                        "enable",
                        "url",
                        "interval",
                        "timeout",
                        "lazy",
                        "expected-status",
                    ],
                ) {
                    return false;
                }
                if health.get("enable").and_then(Value::as_bool) == Some(true)
                    && health.get("url").and_then(Value::as_str)
                        != Some("https://www.gstatic.com/generate_204")
                {
                    return false;
                }
            }
            // Expressions, interface controls and unknown override keys are never admitted.
            if provider.get("override").is_some_and(|v| {
                !keys(
                    v,
                    &[
                        "additional-prefix",
                        "additional-suffix",
                        "udp",
                        "skip-cert-verify",
                        "dialer-proxy",
                        "tfo",
                        "mptcp",
                        "ip-version",
                        "down",
                        "up",
                        "sni",
                        "servername",
                        "client-fingerprint",
                        "alpn",
                    ],
                )
            }) {
                return false;
            }
            let Some(asset) = assets.iter().find(|a| a.path == path) else {
                return false;
            };
            if !proxy_payload_complete(&asset.content) || !expected.insert(path) {
                return false;
            }
        }
    }
    let mut rule_names = HashSet::new();
    if let Some(providers) = root.remove("rule-providers") {
        let Some(map) = providers.as_object() else {
            return false;
        };
        for (i, (name, provider)) in map.iter().enumerate() {
            let path = format!("providers/rules/{i}.yaml");
            if !keys(provider, &["type", "path", "behavior", "format"])
                || provider.get("type").and_then(Value::as_str) != Some("file")
                || provider.get("path").and_then(Value::as_str) != Some(path.as_str())
                || provider
                    .get("format")
                    .is_some_and(|v| !matches!(v.as_str(), Some("yaml" | "mrs")))
            {
                return false;
            }
            let Some(behavior) = provider.get("behavior").and_then(Value::as_str) else {
                return false;
            };
            let Some(asset) = assets.iter().find(|a| a.path == path) else {
                return false;
            };
            let valid = if provider.get("format").and_then(Value::as_str) == Some("mrs") {
                mrs::inspect(&asset.content).is_ok_and(|m| m.behavior == behavior)
            } else {
                rule_payload_complete_with_refs(&asset.content, behavior, &references)
            };
            if !valid || !expected.insert(path) {
                return false;
            }
            rule_names.insert(name.clone());
        }
    }
    if let Some(Value::Array(rules)) = root.get_mut("rules") {
        for rule in rules {
            if let Some(text) = rule.as_str() {
                let parts: Vec<_> = text.split(',').collect();
                if parts.first() == Some(&"RULE-SET") {
                    if parts.len() < 3 || !rule_names.contains(parts[1]) {
                        return false;
                    }
                    *rule = Value::String("MATCH,DIRECT".into());
                } else if parts
                    .first()
                    .is_some_and(|kind| ["AND", "OR", "NOT"].contains(kind))
                {
                    let Some((expression, target)) = text.rsplit_once(',') else {
                        return false;
                    };
                    if text.len() > 2048
                        || text.chars().any(char::is_control)
                        || target.is_empty()
                        || !safe_classical_rule(expression, 0, &rule_names)
                    {
                        return false;
                    }
                    // This is a local inspection copy. The actual rule and its target
                    // remain byte-for-byte in the profile handed to Mihomo.
                    *rule = Value::String("MATCH,DIRECT".into());
                }
            }
        }
    }
    if root
        .remove("sniffer")
        .is_some_and(|s| !safe_sniffer(&s, &rule_names))
    {
        return false;
    }
    if expected.len() != assets.len() || assets.iter().any(|a| !expected.contains(&a.path)) {
        return false;
    }
    let Ok(json) = serde_json::to_string(&value) else {
        return false;
    };
    asset_free_complete(&json)
}

/// Exact listener and DNS values derived by runtime from a trusted network plan.
/// This type does not by itself authorize network activation or prove firewall safety.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkOverlay {
    pub lan_ifname: String,
    pub lan_ipv4: std::net::Ipv4Addr,
    pub selected_ipv4: std::net::Ipv4Addr,
    pub tproxy_port: u16,
    pub dns_port: u16,
    pub nameservers: Vec<std::net::IpAddr>,
    pub bootstrap: Vec<std::net::IpAddr>,
    pub local_zones: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitOverlay {
    pub lan_ifname: String,
    pub lan_ipv4: std::net::Ipv4Addr,
    pub lan_scope: String,
    pub port: u16,
    pub owner_id: String,
    pub generation: u64,
}
impl ExplicitOverlay {
    pub fn valid(&self) -> bool {
        let Some((address, prefix)) = self.lan_scope.split_once('/') else {
            return false;
        };
        let (Ok(network), Ok(prefix)) =
            (address.parse::<std::net::Ipv4Addr>(), prefix.parse::<u8>())
        else {
            return false;
        };
        let ip = self.lan_ipv4;
        let owner = self.owner_id.as_bytes();
        let uuid = owner.len() == 36
            && owner.iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            });
        let mask = if (1..=30).contains(&prefix) {
            u32::MAX << (32 - prefix)
        } else {
            return false;
        };
        !self.lan_ifname.is_empty()
            && self.lan_ifname.len() <= 15
            && self
                .lan_ifname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            && !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && self.port == 7890
            && self.generation > 0
            && uuid
            && u32::from(network) & mask == u32::from(network)
            && u32::from(ip) & mask == u32::from(network)
            && ip != network
            && u32::from(ip) != u32::from(network) | !mask
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputsOverlay {
    pub explicit: Option<ExplicitOverlay>,
    pub gateway: Option<NetworkOverlay>,
}
impl InputsOverlay {
    pub fn valid(&self) -> bool {
        self.explicit.as_ref().is_none_or(ExplicitOverlay::valid)
            && self.gateway.as_ref().is_none_or(|n| n.dns().is_ok())
            && self
                .explicit
                .as_ref()
                .zip(self.gateway.as_ref())
                .is_none_or(|(e, g)| e.lan_ifname == g.lan_ifname && e.lan_ipv4 == g.lan_ipv4)
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", content = "network", rename_all = "snake_case")]
pub enum ManagedOverlay {
    #[default]
    Manual,
    Network(NetworkOverlay),
    Composite(InputsOverlay),
}
impl ManagedOverlay {
    pub fn explicit(&self) -> Option<&ExplicitOverlay> {
        match self {
            Self::Composite(i) => i.explicit.as_ref(),
            _ => None,
        }
    }
    pub fn gateway(&self) -> Option<&NetworkOverlay> {
        match self {
            Self::Network(n) => Some(n),
            Self::Composite(i) => i.gateway.as_ref(),
            _ => None,
        }
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::Manual => true,
            Self::Network(n) => n.dns().is_ok(),
            Self::Composite(i) => i.valid(),
        }
    }
}
impl NetworkOverlay {
    /// Generate the sole permitted DNS structure for this trusted plan.
    pub fn dns(&self) -> Result<Value, PolicyError> {
        let ip = self.lan_ipv4;
        let selected = self.selected_ipv4;
        if self.lan_ifname.is_empty()
            || self.lan_ifname.len() > 15
            || !self
                .lan_ifname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            || self.tproxy_port != 7893
            || self.dns_port != 1053
            || selected.is_unspecified()
            || selected.is_loopback()
            || selected.is_multicast()
            || selected.is_broadcast()
            || selected == ip
        {
            return Err(PolicyError);
        }
        if ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || ip.is_broadcast()
            || self.nameservers.is_empty()
            || self.nameservers.len() > 8
            || self.bootstrap.is_empty()
            || self.bootstrap.len() > 8
            || self.local_zones.len() > 256
        {
            return Err(PolicyError);
        }
        if self
            .nameservers
            .iter()
            .chain(&self.bootstrap)
            .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(PolicyError);
        }
        let mut policies = serde_json::Map::new();
        for zone in &self.local_zones {
            if zone.is_empty()
                || zone.len() > 253
                || !zone
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
                || policies
                    .insert(zone.clone(), serde_json::json!(["127.0.0.1:53"]))
                    .is_some()
            {
                return Err(PolicyError);
            }
        }
        Ok(
            serde_json::json!({"enable":true,"enhanced-mode":"redir-host","listen":format!("{ip}:1053"),"use-system-hosts":false,"fallback-filter":{"geoip":false},"nameserver":self.nameservers.iter().map(|ip| std::net::SocketAddr::new(*ip, 53).to_string()).collect::<Vec<_>>(),"default-nameserver":self.bootstrap.iter().map(ToString::to_string).collect::<Vec<_>>(),"nameserver-policy":policies}),
        )
    }
}
/// Check the exact immutable candidate against the runtime-selected overlay.
pub fn complete_for(config: &str, assets: &[Asset], overlay: &ManagedOverlay) -> bool {
    match overlay {
        ManagedOverlay::Manual => complete(config, assets),
        ManagedOverlay::Composite(inputs) => {
            if !inputs.valid() {
                return false;
            }
            let Ok(mut document) = parse_document(config) else {
                return false;
            };
            let Some(root) = document.as_object_mut() else {
                return false;
            };
            let Ok(fields) = input_fields(inputs) else {
                return false;
            };
            for (key, value) in &fields {
                if root.get(key) != Some(value) {
                    return false;
                }
            }
            for (key, value) in manual_fields() {
                root.insert(key, value);
            }
            serde_json::to_string(&document).is_ok_and(|base| complete(&base, assets))
        }
        ManagedOverlay::Network(network) => {
            let Ok(dns) = network.dns() else { return false };
            let Ok(mut doc) = parse_document(config) else {
                return false;
            };
            let Some(root) = doc.as_object_mut() else {
                return false;
            };
            for (key, expected) in [
                ("mixed-port", serde_json::json!(0)),
                ("tproxy-port", serde_json::json!(7893)),
                ("allow-lan", serde_json::json!(true)),
                (
                    "bind-address",
                    serde_json::json!(network.lan_ipv4.to_string()),
                ),
                ("dns", dns),
            ] {
                if root.get(key) != Some(&expected) {
                    return false;
                }
            }
            // Reuse the strict asset/root admission after replacing only the
            // five already compared network fields with their manual values.
            root.insert("mixed-port".into(), serde_json::json!(7890));
            root.insert("tproxy-port".into(), serde_json::json!(0));
            root.insert("allow-lan".into(), serde_json::json!(false));
            root.insert("bind-address".into(), serde_json::json!("127.0.0.1"));
            root.insert("dns".into(), serde_json::json!({"enable":false,"enhanced-mode":"normal","listen":"","use-system-hosts":false,"fallback-filter":{"geoip":false}}));
            serde_json::to_string(&doc).is_ok_and(|manual| complete(&manual, assets))
        }
    }
}

fn manual_fields() -> Vec<(String, Value)> {
    vec![
        ("mixed-port".into(), serde_json::json!(7890)),
        ("tproxy-port".into(), serde_json::json!(0)),
        ("allow-lan".into(), serde_json::json!(false)),
        ("bind-address".into(), serde_json::json!("127.0.0.1")),
        (
            "dns".into(),
            serde_json::json!({"enable":false,"enhanced-mode":"normal","listen":"","use-system-hosts":false,"fallback-filter":{"geoip":false}}),
        ),
    ]
}
fn input_fields(inputs: &InputsOverlay) -> Result<Vec<(String, Value)>, PolicyError> {
    if !inputs.valid() {
        return Err(PolicyError);
    }
    let mut fields = manual_fields();
    fields[0].1 = serde_json::json!(inputs.explicit.as_ref().map_or(0, |e| e.port));
    if let Some(g) = &inputs.gateway {
        fields[1].1 = serde_json::json!(g.tproxy_port);
        fields[4].1 = g.dns()?;
    }
    fields[2].1 = serde_json::json!(inputs.explicit.is_some() || inputs.gateway.is_some());
    fields[3].1 = serde_json::json!(inputs
        .gateway
        .as_ref()
        .map(|g| g.lan_ipv4.to_string())
        .or_else(|| inputs.explicit.as_ref().map(|e| e.lan_ipv4.to_string()))
        .unwrap_or_else(|| "127.0.0.1".into()));
    Ok(fields)
}
/// Build all managed inputs in one immutable configuration for one Mihomo.
/// The caller supplies trusted bindings; source YAML cannot enable listeners.
pub fn compose_inputs(
    base: &str,
    assets: &[Asset],
    inputs: &InputsOverlay,
) -> Result<String, PolicyError> {
    if !complete(base, assets) {
        return Err(PolicyError);
    }
    let mut document = parse_document(base)?;
    let root = document.as_object_mut().ok_or(PolicyError)?;
    for (key, value) in input_fields(inputs)? {
        root.insert(key, value);
    }
    serde_json::to_string(&document).map_err(|_| PolicyError)
}
/// Recover the canonical accepted profile from a validated combined snapshot.
pub fn base_from_inputs(
    config: &str,
    assets: &[Asset],
    overlay: &ManagedOverlay,
) -> Result<String, PolicyError> {
    if !complete_for(config, assets, overlay) {
        return Err(PolicyError);
    }
    let mut document = parse_document(config)?;
    let root = document.as_object_mut().ok_or(PolicyError)?;
    for (key, value) in manual_fields() {
        root.insert(key, value);
    }
    serde_json::to_string(&document).map_err(|_| PolicyError)
}
