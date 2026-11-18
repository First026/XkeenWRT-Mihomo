use super::{ConfigError, ConfigStore, MAX_PROFILE_BYTES};
use serde::Serialize;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, PartialEq, Eq)]
pub enum PrepareError {
    Config(ConfigError),
    AmbiguousYaml,
    InvalidYaml,
    LimitExceeded,
}
impl From<ConfigError> for PrepareError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
#[derive(Debug, Serialize)]
pub struct Change {
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub reason: String,
}
#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct PreparedPreview {
    pub profile_id: String,
    pub revision: String,
    pub source: String,
    pub effective_yaml: String,
    pub mode: &'static str,
    pub core_validation: &'static str,
    pub activatable: bool,
    pub changes: Vec<Change>,
    pub diagnostics: Vec<Diagnostic>,
}

fn render(v: &Yaml, out: &mut String, depth: usize, pretty: bool) -> Result<(), PrepareError> {
    match v {
        Yaml::String(s) => {
            let escaped = serde_json::to_string(s)
                .map_err(|_| PrepareError::InvalidYaml)?
                .replace('\u{0085}', "\\u0085")
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029");
            out.push_str(&escaped);
        }
        Yaml::Integer(n) => out.push_str(&n.to_string()),
        Yaml::Real(n) => out.push_str(n),
        Yaml::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        Yaml::Null => out.push_str("null"),
        Yaml::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                render(x, out, depth + 1, pretty)?;
            }
            if pretty && !a.is_empty() {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push(']');
        }
        Yaml::Hash(h) => {
            out.push('{');
            for (i, (k, v)) in h.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                render(k, out, depth + 1, pretty)?;
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                render(v, out, depth + 1, pretty)?;
            }
            if pretty && !h.is_empty() {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push('}');
        }
        _ => return Err(PrepareError::InvalidYaml),
    }
    if out.len() > 8 * MAX_PROFILE_BYTES {
        return Err(PrepareError::LimitExceeded);
    }
    Ok(())
}

pub(crate) fn activation_yaml(preview: &PreparedPreview, secret: &str) -> Result<String, PrepareError> {
    let mut docs = YamlLoader::load_from_str(&preview.effective_yaml).map_err(|_| PrepareError::InvalidYaml)?;
    if docs.len() != 1 {
        return Err(PrepareError::InvalidYaml);
    }
    let mut doc = docs.remove(0);
    let Yaml::Hash(ref mut map) = doc else {
        return Err(PrepareError::InvalidYaml);
    };
    map.insert(
        Yaml::String("external-controller".into()),
        Yaml::String("127.0.0.1:9090".into()),
    );
    map.insert(Yaml::String("secret".into()), Yaml::String(secret.into()));
    let mut output = String::new();
    render(&doc, &mut output, 0, true)?;
    Ok(output)
}

fn repr(v: &Yaml) -> Result<String, PrepareError> {
    let mut s = String::new();
    render(v, &mut s, 0, false)?;
    Ok(s)
}
fn diagnostic(diags: &mut Vec<Diagnostic>, code: &str, path: &str, message: &str) {
    if diags.len() >= 256 {
        return;
    }
    if diags.len() == 255 {
        diags.push(Diagnostic {
            code: "ADDITIONAL_DIAGNOSTICS".into(),
            path: "$".into(),
            message: "Further settings also require review.".into(),
        });
        return;
    }
    diags.push(Diagnostic {
        code: code.into(),
        path: path.into(),
        message: message.into(),
    });
}
fn override_key(
    doc: &mut Yaml, key: &str, value: Yaml, changes: &mut Vec<Change>, reason: &str,
) -> Result<(), PrepareError> {
    let Yaml::Hash(h) = doc else {
        return Err(PrepareError::InvalidYaml);
    };
    let old = h.insert(Yaml::String(key.into()), value.clone());
    if old.as_ref() != Some(&value) {
        let sensitive = key == "secret";
        changes.push(Change {
            path: key.into(),
            before: old
                .as_ref()
                .map(|v| if sensitive { Ok("[redacted]".into()) } else { repr(v) })
                .transpose()?,
            after: Some(if sensitive { "[redacted]".into() } else { repr(&value)? }),
            reason: reason.into(),
        });
    }
    Ok(())
}
fn parsed(s: &str) -> Yaml {
    YamlLoader::load_from_str(s).expect("static overlay").remove(0)
}
impl ConfigStore {
    pub fn prepare(&self, id: &str, expected_revision: &str) -> Result<PreparedPreview, PrepareError> {
        let p = self.read(id)?;
        if p.revision != expected_revision {
            return Err(ConfigError::Conflict.into());
        }
        let mut doc = super::source_yaml::load(&p.source)?;
        let mut changes = Vec::new();
        let mut diagnostics = Vec::new();
        if let Yaml::Hash(map) = &mut doc
            && let Some(anchors) = map.remove(&Yaml::String("anchors".into()))
        {
            if !matches!(anchors, Yaml::Hash(_)) {
                return Err(PrepareError::InvalidYaml);
            }
            changes.push(Change {
                path: "anchors".into(),
                before: Some("[YAML anchor definitions]".into()),
                after: None,
                reason: "Aliases and merges expanded; template anchor definitions omitted from the effective profile."
                    .into(),
            });
        }
        let known = [
            "mode",
            "log-level",
            "ipv6",
            "unified-delay",
            "tcp-concurrent",
            "find-process-mode",
            "global-client-fingerprint",
            "keep-alive-interval",
            "keep-alive-idle",
            "disable-keep-alive",
            "etag-support",
            "external-controller-cors",
            "authentication",
            "skip-auth-prefixes",
            "lan-allowed-ips",
            "lan-disallowed-ips",
            "proxies",
            "proxy-groups",
            "rules",
            "sub-rules",
            "hosts",
            "proxy-providers",
            "rule-providers",
            "geodata-mode",
            "geodata-loader",
            "geo-auto-update",
            "geo-update-interval",
            "geox-url",
            "global-ua",
            "sniffer",
            "interface-name",
            "routing-mark",
            "external-controller-routing-mark",
            "listeners",
            "tunnels",
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
            "tun",
            "iptables",
            "ntp",
            "tuic-server",
            "dns",
            "profile",
        ];
        let h = doc.as_hash().ok_or(PrepareError::InvalidYaml)?;
        for key in h.keys() {
            if let Some(k) = key.as_str()
                && !known.contains(&k)
            {
                diagnostic(
                    &mut diagnostics,
                    "UNKNOWN_SETTING",
                    "$",
                    "An unknown top-level setting requires review.",
                );
            }
        }
        for key in ["interface-name", "external-controller-routing-mark", "listeners", "tunnels"] {
            if let Some(v) = h.get(&Yaml::String(key.into()))
                && !matches!(v, Yaml::Null)
                && v != &parsed("''")
                && v != &parsed("0")
                && v != &parsed("[]")
            {
                diagnostic(
                    &mut diagnostics,
                    "MANAGED_SETTING",
                    key,
                    "The source requests a managed routing or listener setting.",
                );
            }
        }
        for (key, val) in [
            ("mixed-port", "7890"),
            ("port", "0"),
            ("socks-port", "0"),
            ("redir-port", "0"),
            ("tproxy-port", "0"),
            ("allow-lan", "false"),
            ("bind-address", "'127.0.0.1'"),
            ("external-controller", "''"),
            ("external-controller-tls", "''"),
            ("external-controller-unix", "''"),
            ("external-controller-pipe", "''"),
            ("external-doh-server", "''"),
            ("external-ui", "''"),
            ("external-ui-url", "''"),
            ("external-ui-name", "''"),
            ("secret", "''"),
            ("ss-config", "''"),
            ("vmess-config", "''"),
            ("external-controller-routing-mark", "0"),
            ("routing-mark", "0"),
            ("interface-name", "''"),
            ("listeners", "[]"),
            ("tunnels", "[]"),
            (
                "tun",
                "{enable: false, auto-route: false, auto-redirect: false, auto-detect-interface: false, dns-hijack: []}",
            ),
            ("iptables", "{enable: false, dns-redirect: false}"),
            ("ntp", "{enable: false, write-to-system: false}"),
            ("tuic-server", "{enable: false}"),
            (
                "dns",
                "{enable: false, enhanced-mode: normal, listen: '', use-system-hosts: false, fallback-filter: {geoip: false}}",
            ),
            ("profile", "{store-selected: false, store-fake-ip: false}"),
            ("geo-auto-update", "false"),
        ] {
            override_key(
                &mut doc,
                key,
                parsed(val),
                &mut changes,
                if key == "dns" {
                    "DNS profile behavior changes; application and core name resolution may still occur."
                } else {
                    "Managed manual preview setting."
                },
            )?;
        }
        for (section, kind) in [("proxy-providers", "proxies"), ("rule-providers", "rules")] {
            if let Some(Yaml::Hash(providers)) = match &mut doc {
                Yaml::Hash(h) => h.get_mut(&Yaml::String(section.into())),
                _ => None,
            } {
                for (index, (_, provider)) in providers.iter_mut().enumerate() {
                    let path = format!("{section}[{index}]");
                    if let Yaml::Hash(map) = provider {
                        let typ = map.get(&Yaml::String("type".into())).and_then(Yaml::as_str);
                        if typ == Some("http")
                            && map
                                .get(&Yaml::String("url".into()))
                                .and_then(Yaml::as_str)
                                .is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"))
                        {
                            let cache = format!("providers/{kind}/{index}.yaml");
                            let old = map.insert(Yaml::String("path".into()), Yaml::String(cache.clone()));
                            if old.as_ref() != Some(&Yaml::String(cache.clone())) {
                                changes.push(Change {
                                    path: format!("{path}.path"),
                                    before: old.as_ref().map(repr).transpose()?,
                                    after: Some(repr(&Yaml::String(cache))?),
                                    reason: "Managed provider cache path.".into(),
                                });
                            }
                            diagnostic(
                                &mut diagnostics,
                                "PROVIDER_UNRESOLVED",
                                &path,
                                "Provider payload must be fetched and verified in isolated staging.",
                            );
                        } else {
                            diagnostic(
                                &mut diagnostics,
                                "PROVIDER_UNRESOLVED",
                                &path,
                                "Provider requires asset review in isolated staging.",
                            );
                        }
                    } else {
                        diagnostic(
                            &mut diagnostics,
                            "PROVIDER_UNRESOLVED",
                            &path,
                            "Provider requires asset review in isolated staging.",
                        );
                    }
                }
            } else if !matches!(&doc[section], Yaml::BadValue) {
                diagnostic(
                    &mut diagnostics,
                    "PROVIDER_UNRESOLVED",
                    section,
                    "Provider settings require review.",
                );
            }
        }
        if let Yaml::Array(proxies) = &doc["proxies"] {
            for (index, proxy) in proxies.iter().enumerate() {
                let path = format!("proxies[{index}]");
                let kind = proxy["type"].as_str();
                if !matches!(
                    kind,
                    Some(
                        "direct"
                            | "reject"
                            | "ss"
                            | "ssr"
                            | "vmess"
                            | "vless"
                            | "trojan"
                            | "http"
                            | "socks5"
                            | "wireguard"
                            | "hysteria"
                            | "hysteria2"
                            | "tuic"
                            | "ssh"
                            | "snell"
                    )
                ) {
                    diagnostic(
                        &mut diagnostics,
                        "OUTBOUND_UNREVIEWED",
                        &path,
                        "An outbound type requires review.",
                    );
                }
                if has_outbound_asset(proxy, kind) {
                    diagnostic(
                        &mut diagnostics,
                        "ASSET_UNRESOLVED",
                        &path,
                        "Outbound credential or certificate asset requires review.",
                    );
                }
            }
        } else if !matches!(&doc["proxies"], Yaml::BadValue) {
            diagnostic(
                &mut diagnostics,
                "OUTBOUND_UNREVIEWED",
                "proxies",
                "Outbound settings require review.",
            );
        }
        for section in ["rules", "sub-rules", "geox-url", "geodata-mode", "geodata-loader"] {
            if contains_geodata(&doc[section], section.starts_with("geo")) {
                diagnostic(
                    &mut diagnostics,
                    "ASSET_UNRESOLVED",
                    section,
                    "Geodata dependencies require isolated asset review.",
                );
            }
        }
        scan(&doc, "$", &mut diagnostics);
        let mut effective_yaml = String::new();
        render(&doc, &mut effective_yaml, 0, true)?;
        if effective_yaml.len() > 8 * MAX_PROFILE_BYTES {
            return Err(PrepareError::LimitExceeded);
        }
        let preview = PreparedPreview {
            profile_id: p.id,
            revision: p.revision,
            source: p.source,
            effective_yaml,
            mode: "manual-preview",
            core_validation: "not_run",
            activatable: false,
            changes,
            diagnostics,
        };
        if serde_json::to_vec(&preview)
            .map_err(|_| PrepareError::InvalidYaml)?
            .len()
            > 8 * MAX_PROFILE_BYTES
        {
            return Err(PrepareError::LimitExceeded);
        }
        Ok(preview)
    }
}
fn scan(v: &Yaml, path: &str, d: &mut Vec<Diagnostic>) {
    match v {
        Yaml::Hash(h) => {
            for (k, v) in h {
                if let Some(key) = k.as_str() {
                    if [
                        "interface-name",
                        "routing-mark",
                        "override-expr",
                        "credential-file",
                        "private-key-file",
                        "certificate-file",
                        "ca-file",
                    ]
                    .contains(&key)
                        && path != "$"
                    {
                        diagnostic(
                            d,
                            "UNRESOLVED_SETTING",
                            path,
                            "Nested routing, expression, or credential asset requires review.",
                        );
                    }
                    let child_path = if path == "$"
                        && [
                            "proxies",
                            "proxy-groups",
                            "proxy-providers",
                            "rule-providers",
                            "rules",
                            "sub-rules",
                            "hosts",
                            "sniffer",
                        ]
                        .contains(&key)
                    {
                        key
                    } else {
                        path
                    };
                    scan(v, child_path, d);
                }
            }
        }
        Yaml::Array(a) => {
            for (index, v) in a.iter().enumerate() {
                scan(v, &format!("{path}[{index}]"), d);
            }
        }
        _ => (),
    }
}

fn contains_geodata(v: &Yaml, geo_setting: bool) -> bool {
    match v {
        Yaml::BadValue => false,
        Yaml::String(s) => {
            geo_setting
                || s.to_ascii_uppercase()
                    .split(['(', ','])
                    .any(|token| ["GEOIP", "GEOSITE", "IP-ASN"].contains(&token.trim()))
        }
        Yaml::Array(a) => a.iter().any(|v| contains_geodata(v, geo_setting)),
        Yaml::Hash(h) => geo_setting || h.values().any(|v| contains_geodata(v, false)),
        _ => geo_setting,
    }
}

fn has_outbound_asset(v: &Yaml, kind: Option<&str>) -> bool {
    let tls_like = matches!(
        kind,
        Some(
            "ssh"
                | "ss"
                | "ssr"
                | "vmess"
                | "vless"
                | "trojan"
                | "http"
                | "socks5"
                | "hysteria"
                | "hysteria2"
                | "tuic"
                | "snell"
        )
    );
    if !tls_like {
        return false;
    }
    fn inspect(v: &Yaml) -> bool {
        match v {
            Yaml::Hash(h) => h.iter().any(|(k, v)| {
                k.as_str().is_some_and(|k| {
                    [
                        "private-key",
                        "private-key-file",
                        "certificate",
                        "certificate-file",
                        "client-certificate",
                        "client-key",
                        "ca",
                        "ca-file",
                        "ca-cert",
                    ]
                    .contains(&k)
                }) || inspect(v)
            }),
            Yaml::Array(a) => a.iter().any(inspect),
            _ => false,
        }
    }
    inspect(v)
}
