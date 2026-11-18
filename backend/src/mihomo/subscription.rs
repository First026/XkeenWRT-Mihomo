//! URI-list subscription import, using the same Mihomo node contract as the UI importer.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashSet};

pub const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 2048;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    Empty,
    Format,
    Unsupported,
    TooLarge,
    Parameter(ImportDetail),
}

/// Only audited protocol field names may leave the parser. Unknown input keys
/// are represented by an ordinal, never by their text or a reversible hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterName {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "type")]
    Transport,
    #[serde(rename = "security")]
    Security,
    #[serde(rename = "spx")]
    Spx,
    #[serde(rename = "support-x25519mlkem768")]
    SupportX25519Mlkem768,
    #[serde(rename = "headerType")]
    HeaderType,
    #[serde(rename = "flow")]
    Flow,
    #[serde(rename = "encryption")]
    Encryption,
    #[serde(rename = "mode")]
    Mode,
    #[serde(rename = "pqv")]
    Pqv,
    #[serde(rename = "extra")]
    Extra,
    #[serde(rename = "minPacketSize")]
    MinPacketSize,
    #[serde(rename = "maxPacketSize")]
    MaxPacketSize,
}
impl ParameterName {
    fn from_key(key: &str) -> Self {
        match key {
            "type" => Self::Transport,
            "security" => Self::Security,
            "spx" => Self::Spx,
            "support-x25519mlkem768" => Self::SupportX25519Mlkem768,
            "headertype" => Self::HeaderType,
            "flow" => Self::Flow,
            "encryption" => Self::Encryption,
            "mode" => Self::Mode,
            "pqv" => Self::Pqv,
            "extra" => Self::Extra,
            "minpacketsize" | "obfs-min-packet-size" => Self::MinPacketSize,
            "maxpacketsize" | "obfs-max-packet-size" => Self::MaxPacketSize,
            _ => Self::Unknown,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "неизвестный параметр (имя скрыто)",
            Self::Transport => "type",
            Self::Security => "security",
            Self::Spx => "spx",
            Self::SupportX25519Mlkem768 => "support-x25519mlkem768",
            Self::HeaderType => "headerType",
            Self::Flow => "flow",
            Self::Encryption => "encryption",
            Self::Mode => "mode",
            Self::Pqv => "pqv",
            Self::Extra => "extra",
            Self::MinPacketSize => "minPacketSize",
            Self::MaxPacketSize => "maxPacketSize",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterIssue {
    UnsupportedParameter,
    IncompatibleValue,
    DuplicateParameter,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDetail {
    pub node: u16,
    pub parameter: ParameterName,
    pub position: Option<u16>,
    pub issue: ParameterIssue,
}
fn parameter_error(key: &str, index: usize, position: Option<usize>, issue: ParameterIssue) -> ImportError {
    ImportError::Parameter(ImportDetail {
        node: (index + 1) as u16,
        parameter: ParameterName::from_key(key),
        position: position.map(|n| (n + 1) as u16),
        issue,
    })
}

fn base64(s: &str) -> Result<Vec<u8>, ImportError> {
    let text: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if text.len() > MAX_BYTES {
        return Err(ImportError::TooLarge);
    }
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(&text).ok())
        .ok_or(ImportError::Format)
}
fn decoded(s: &str) -> Result<String, ImportError> {
    urlencoding::decode(s)
        .map(|s| s.into_owned())
        .map_err(|_| ImportError::Format)
}
fn number(s: &str) -> Result<u16, ImportError> {
    s.parse::<u16>().ok().filter(|n| *n != 0).ok_or(ImportError::Format)
}
fn put(map: &mut Map<String, Value>, key: &str, value: Option<&String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        map.insert(key.into(), json!(v));
    }
}
fn transport(node: &mut Map<String, Value>, q: &BTreeMap<String, String>, index: usize) -> Result<(), ImportError> {
    let incompatible = |key| parameter_error(key, index, None, ParameterIssue::IncompatibleValue);
    let net = q.get("type").map(String::as_str).unwrap_or("tcp");
    if !matches!(net, "tcp" | "ws" | "grpc") {
        return Err(incompatible("type"));
    }
    if (net != "grpc" && (q.contains_key("servicename") || q.contains_key("mode")))
        || (net == "tcp" && (q.contains_key("path") || q.contains_key("host")))
        || (net == "grpc" && q.contains_key("host"))
    {
        return Err(ImportError::Unsupported);
    }
    node.insert("network".into(), json!(net));
    let security = q.get("security").map(String::as_str).unwrap_or("none");
    // Xray's spider path is fallback metadata, not a Mihomo connection option.
    // Accept only a bounded origin-relative path on VLESS Reality; never emit it.
    if q.get("spx").is_some_and(|s| {
        node.get("type").and_then(Value::as_str) != Some("vless")
            || security != "reality"
            || s.len() > 2048
            || !s.starts_with('/')
            || s.starts_with("//")
            || s.chars().any(char::is_control)
    }) {
        return Err(incompatible("spx"));
    }
    if q.get("headertype").is_some_and(|s| net != "tcp" || s != "none") {
        return Err(incompatible("headertype"));
    }
    if !matches!(security, "none" | "tls" | "reality" | "") {
        return Err(incompatible("security"));
    }
    if security != "reality" && (q.contains_key("pbk") || q.contains_key("sid")) {
        return Err(ImportError::Unsupported);
    }
    if !matches!(security, "tls" | "reality")
        && ["sni", "fp", "alpn", "insecure", "allowinsecure"]
            .iter()
            .any(|k| q.contains_key(*k))
    {
        return Err(ImportError::Unsupported);
    }
    if matches!(security, "tls" | "reality") {
        node.insert("tls".into(), json!(true));
        node.insert(
            "client-fingerprint".into(),
            json!(q.get("fp").map(String::as_str).unwrap_or("chrome")),
        );
        let sni_key = if node.get("type").and_then(Value::as_str) == Some("trojan") {
            "sni"
        } else {
            "servername"
        };
        put(node, sni_key, q.get("sni"));
        if let Some(alpn) = q.get("alpn") {
            node.insert("alpn".into(), json!(alpn.split(',').collect::<Vec<_>>()));
        }
        if q.get("insecure")
            .or(q.get("allowinsecure"))
            .is_some_and(|v| v == "1" || v == "true")
        {
            node.insert("skip-cert-verify".into(), json!(true));
        }
    }
    if security == "reality" {
        if node.get("type").and_then(Value::as_str) != Some("vless") {
            return Err(ImportError::Unsupported);
        }
        let public = q.get("pbk").filter(|s| !s.is_empty()).ok_or(ImportError::Format)?;
        let support_mlkem = q.get("support-x25519mlkem768").is_none_or(|value| value == "true");
        let mut reality = json!({"public-key":public,"support-x25519mlkem768":support_mlkem});
        if let Some(sid) = q.get("sid") {
            if sid.len() > 16 || sid.len() % 2 != 0 || !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ImportError::Format);
            }
            reality["short-id"] = json!(sid);
        }
        node.insert("reality-opts".into(), reality);
    }
    if net == "ws" {
        let mut ws = json!({"path":q.get("path").map(String::as_str).unwrap_or("/")});
        if let Some(host) = q.get("host").filter(|s| !s.is_empty()) {
            ws["headers"] = json!({"Host":host});
        }
        node.insert("ws-opts".into(), ws);
    } else if net == "grpc" {
        if q.get("mode").is_some_and(|s| s != "gun") {
            return Err(ImportError::Unsupported);
        }
        if let Some(service) = q.get("servicename").or(q.get("path")) {
            node.insert("grpc-opts".into(), json!({"grpc-service-name":service}));
        }
    }
    Ok(())
}

fn parse_uri(uri: &str, index: usize) -> Result<Value, ImportError> {
    if uri.len() > 16 * 1024 || uri.chars().any(char::is_control) {
        return Err(ImportError::Format);
    }
    if let Some(encoded) = uri.strip_prefix("vmess://") {
        let bytes = base64(encoded)?;
        let s = std::str::from_utf8(&bytes).map_err(|_| ImportError::Format)?;
        let data = profile_policy::parse_document(s).map_err(|_| ImportError::Format)?;
        let map = data.as_object().ok_or(ImportError::Format)?;
        if !map.keys().all(|k| {
            [
                "v",
                "ps",
                "add",
                "port",
                "id",
                "aid",
                "scy",
                "net",
                "type",
                "host",
                "path",
                "tls",
                "sni",
                "fp",
                "alpn",
                "allowInsecure",
            ]
            .contains(&k.as_str())
        }) {
            return Err(ImportError::Unsupported);
        }
        if map
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|s| !matches!(s, "none" | ""))
        {
            return Err(ImportError::Unsupported);
        }
        let text = |k: &str| map.get(k).and_then(Value::as_str).unwrap_or("");
        let server = text("add");
        let id = text("id");
        if server.is_empty() || uuid::Uuid::parse_str(id).is_err() {
            return Err(ImportError::Format);
        }
        let port = map.get("port").ok_or(ImportError::Format)?;
        let port = number(&port.as_str().map(str::to_owned).unwrap_or_else(|| port.to_string()))?;
        let aid = map
            .get("aid")
            .map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string()))
            .unwrap_or_else(|| "0".into())
            .parse::<u32>()
            .map_err(|_| ImportError::Format)?;
        let mut node = json!({"name": if text("ps").is_empty() {format!("vmess_{}",index+1)} else {text("ps").into()},"type":"vmess","server":server,"port":port,"udp":true,"uuid":id,"alterId":aid,"cipher":if text("scy").is_empty(){"auto"}else{text("scy")}});
        let mut q = BTreeMap::new();
        q.insert(
            "type".into(),
            if text("net").is_empty() { "tcp" } else { text("net") }.into(),
        );
        if text("tls") == "tls" {
            q.insert("security".into(), "tls".into());
        }
        for key in ["sni", "fp", "alpn", "path", "host"] {
            if !text(key).is_empty() {
                q.insert(key.into(), text(key).into());
            }
        }
        if let Some(value) = map.get("allowInsecure") {
            let v = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
            if !matches!(v.as_str(), "0" | "1" | "true" | "false") {
                return Err(ImportError::Format);
            }
            q.insert("insecure".into(), v);
        }
        if !matches!(text("tls"), "" | "none" | "tls") {
            return Err(ImportError::Unsupported);
        }
        transport(node.as_object_mut().unwrap(), &q, index)?;
        return Ok(node);
    }
    let uri = if let Some(rest) = uri.strip_prefix("ss://") {
        let (head, fragment) = rest.split_once('#').unwrap_or((rest, ""));
        if !head.contains('@') {
            let bytes = base64(head)?;
            let decoded = std::str::from_utf8(&bytes).map_err(|_| ImportError::Format)?;
            format!("ss://{decoded}#{fragment}")
        } else {
            uri.into()
        }
    } else {
        uri.into()
    };
    let u = reqwest::Url::parse(&uri).map_err(|_| ImportError::Format)?;
    let kind = match u.scheme() {
        "hy2" => "hysteria2",
        "vless" | "trojan" | "hysteria2" | "ss" => u.scheme(),
        _ => return Err(ImportError::Unsupported),
    };
    let server = u
        .host_str()
        .ok_or(ImportError::Format)?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = u.port().unwrap_or(443);
    if port == 0 || server.is_empty() {
        return Err(ImportError::Format);
    }
    let mut q = BTreeMap::new();
    for (position, (key, value)) in u.query_pairs().enumerate() {
        let key = key.to_ascii_lowercase();
        if q.contains_key(&key) {
            if key == "support-x25519mlkem768" {
                return Err(parameter_error(
                    &key,
                    index,
                    Some(position),
                    ParameterIssue::DuplicateParameter,
                ));
            }
            return Err(ImportError::Format);
        }
        q.insert(key, value.to_string());
    }
    let allowed: &[&str] = match kind {
        "vless" => &[
            "type",
            "security",
            "sni",
            "fp",
            "alpn",
            "insecure",
            "allowinsecure",
            "pbk",
            "sid",
            "flow",
            "encryption",
            "servicename",
            "path",
            "host",
            "mode",
            "spx",
            "headertype",
            "support-x25519mlkem768",
        ],
        "trojan" => &[
            "type",
            "security",
            "sni",
            "fp",
            "alpn",
            "insecure",
            "allowinsecure",
            "servicename",
            "path",
            "host",
            "mode",
        ],
        "hysteria2" => &[
            "sni",
            "fp",
            "alpn",
            "insecure",
            "allowinsecure",
            "obfs",
            "obfs-password",
            "up",
            "down",
        ],
        _ => &[],
    };
    for (position, (key, _)) in u.query_pairs().enumerate() {
        let key = key.to_ascii_lowercase();
        if !allowed.contains(&key.as_str()) {
            return Err(parameter_error(
                &key,
                index,
                Some(position),
                ParameterIssue::UnsupportedParameter,
            ));
        }
    }
    if let Some(value) = q.get("support-x25519mlkem768")
        && (kind != "vless"
            || q.get("security").map(String::as_str) != Some("reality")
            || !matches!(value.as_str(), "true" | "false"))
    {
        let position = u
            .query_pairs()
            .position(|(key, _)| key.eq_ignore_ascii_case("support-x25519mlkem768"));
        return Err(parameter_error(
            "support-x25519mlkem768",
            index,
            position,
            ParameterIssue::IncompatibleValue,
        ));
    }
    for key in ["insecure", "allowinsecure"] {
        if q.get(key)
            .is_some_and(|s| !matches!(s.as_str(), "0" | "1" | "true" | "false"))
        {
            return Err(ImportError::Format);
        }
    }
    let name = decoded(u.fragment().unwrap_or(""))?;
    let mut node = json!({"name":if name.is_empty(){format!("{kind}_{}",index+1)}else{name},"type":kind,"server":server,"port":port,"udp":true});
    let map = node.as_object_mut().unwrap();
    let username = decoded(u.username())?;
    match kind {
        "vless" => {
            if u.password().is_some() || uuid::Uuid::parse_str(&username).is_err() {
                return Err(ImportError::Format);
            }
            map.insert("uuid".into(), json!(username));
            map.insert("packet-encoding".into(), json!("xudp"));
            map.insert(
                "encryption".into(),
                json!(q.get("encryption").map(String::as_str).unwrap_or("none")),
            );
            put(map, "flow", q.get("flow"));
            if q.get("encryption").is_some_and(|v| v != "none") {
                return Err(parameter_error(
                    "encryption",
                    index,
                    None,
                    ParameterIssue::IncompatibleValue,
                ));
            }
            if q.get("flow").is_some_and(|v| {
                !v.is_empty()
                    && (v != "xtls-rprx-vision"
                        || q.get("type").is_some_and(|n| n != "tcp")
                        || !matches!(q.get("security").map(String::as_str), Some("tls" | "reality")))
            }) {
                return Err(parameter_error("flow", index, None, ParameterIssue::IncompatibleValue));
            }
            transport(map, &q, index)?;
        }
        "trojan" => {
            if username.is_empty() || u.password().is_some() {
                return Err(ImportError::Format);
            }
            map.insert("password".into(), json!(username));
            transport(map, &q, index)?;
        }
        "hysteria2" => {
            if username.is_empty() {
                return Err(ImportError::Format);
            }
            let password = match u.password() {
                Some(p) => format!("{username}:{}", decoded(p)?),
                None => username,
            };
            map.insert("password".into(), json!(password));
            for key in ["sni", "obfs", "obfs-password", "up", "down"] {
                put(map, key, q.get(key));
            }
            put(map, "client-fingerprint", q.get("fp"));
            if q.get("insecure")
                .or(q.get("allowinsecure"))
                .is_some_and(|s| s == "1" || s == "true")
            {
                map.insert("skip-cert-verify".into(), json!(true));
            }
            if let Some(a) = q.get("alpn") {
                map.insert("alpn".into(), json!(a.split(',').collect::<Vec<_>>()));
            }
        }
        "ss" => {
            if !q.is_empty() {
                return Err(ImportError::Unsupported);
            }
            let auth = if let Some(p) = u.password() {
                format!("{username}:{}", decoded(p)?)
            } else {
                String::from_utf8(base64(&username)?).map_err(|_| ImportError::Format)?
            };
            let (method, password) = auth.split_once(':').ok_or(ImportError::Format)?;
            if method.is_empty() || password.is_empty() {
                return Err(ImportError::Format);
            }
            map.insert("cipher".into(), json!(method));
            map.insert("password".into(), json!(password));
        }
        _ => return Err(ImportError::Unsupported),
    }
    Ok(node)
}

pub fn normalize(bytes: &[u8]) -> Result<Vec<u8>, ImportError> {
    let nodes = normalize_nodes(bytes)?;
    super::providers::metadata::attach(nodes, super::providers::metadata::read(bytes))
        .map_err(|_| ImportError::TooLarge)
}
fn normalize_nodes(bytes: &[u8]) -> Result<Vec<u8>, ImportError> {
    if bytes.len() > MAX_BYTES {
        return Err(ImportError::TooLarge);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ImportError::Format)?
        .trim()
        .trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Err(ImportError::Empty);
    }
    if let Ok(document) = profile_policy::parse_document(text)
        && let Some(nodes) = document.get("proxies").and_then(Value::as_array)
    {
        if nodes.is_empty() {
            return Err(ImportError::Empty);
        }
        if nodes.len() > MAX_NODES {
            return Err(ImportError::TooLarge);
        }
        // A subscription can be a complete Clash profile. Only node data crosses
        // into the managed provider; controller, routes and DNS never do.
        return checked(json!({"proxies": nodes}));
    }
    let decoded;
    let list = if text.contains("://") {
        text
    } else {
        decoded = base64(text)?;
        std::str::from_utf8(&decoded).map_err(|_| ImportError::Format)?.trim()
    };
    if list.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut nodes = Vec::new();
    let mut names = HashSet::new();
    for line in list.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if nodes.len() >= MAX_NODES {
            return Err(ImportError::TooLarge);
        }
        let mut node = parse_uri(line, nodes.len())?;
        let original = node["name"].as_str().ok_or(ImportError::Format)?.to_owned();
        let mut name = original.clone();
        let mut suffix = 2;
        while !names.insert(name.clone()) {
            name = format!("{original} ({suffix})");
            suffix += 1;
        }
        node["name"] = json!(name);
        nodes.push(node);
    }
    checked(json!({"proxies":nodes}))
}
fn checked(document: Value) -> Result<Vec<u8>, ImportError> {
    let data = serde_json::to_vec(&document).map_err(|_| ImportError::Format)?;
    if data.len() > MAX_BYTES {
        return Err(ImportError::TooLarge);
    }
    if !profile_policy::proxy_payload_complete(&data) {
        return Err(ImportError::Unsupported);
    }
    Ok(data)
}
