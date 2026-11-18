//! A bounded traversal report. Unknown syntax is a warning, never a fictitious
//! proven intersection. Known dangerous actions retain their own diagnostics.
use super::*;
use serde_json::json;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Blocker,
    Warning,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    #[serde(flatten)]
    pub detail: FirewallConflict,
}
#[derive(Default, Debug, serde::Serialize)]
pub struct FirewallReport {
    pub findings: Vec<Finding>,
    pub truncated: usize,
}
impl FirewallReport {
    fn push(&mut self, severity: Severity, detail: FirewallConflict) {
        if self.findings.len() < 256 {
            self.findings.push(Finding { severity, detail });
        } else {
            self.truncated += 1;
        }
    }
    pub fn blocked(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Blocker)
            || self.truncated != 0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    No,
    Yes,
    Unknown,
}
fn combine(a: Scope, b: Scope) -> Scope {
    if a == Scope::No || b == Scope::No {
        Scope::No
    } else if a == Scope::Unknown || b == Scope::Unknown {
        Scope::Unknown
    } else {
        Scope::Yes
    }
}
fn strings(v: &Value, items: &[Value], key: &ChainKey) -> Option<Vec<Value>> {
    if let Some(name) = v.as_str().and_then(|s| s.strip_prefix('@')) {
        let sets: Vec<_> = items
            .iter()
            .filter_map(|i| i.get("set"))
            .filter(|s| s["family"] == key.0 && s["table"] == key.1 && s["name"] == name)
            .collect();
        let [set] = sets.as_slice() else {
            return None;
        };
        return Some(
            set.get("elem")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
    }
    if let Some(a) = v.get("set").and_then(Value::as_array) {
        Some(a.clone())
    } else if v.is_string()
        || v.is_number()
        || v.get("prefix").is_some()
        || v.get("range").is_some()
    {
        Some(vec![v.clone()])
    } else {
        None
    }
}
fn interval(value: &Value) -> Option<(u32, u32)> {
    if let Some(ip) = value
        .as_str()
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
    {
        let n = u32::from(ip);
        return Some((n, n));
    }
    if let Some(prefix) = value.get("prefix") {
        let ip = u32::from(
            prefix["addr"]
                .as_str()?
                .parse::<std::net::Ipv4Addr>()
                .ok()?,
        );
        let n = prefix["len"].as_u64()?;
        if n > 32 {
            return None;
        }
        let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
        return Some((ip & mask, ip | !mask));
    }
    let range = value.get("range")?.as_array()?;
    if range.len() != 2 {
        return None;
    }
    let lo = u32::from(range[0].as_str()?.parse::<std::net::Ipv4Addr>().ok()?);
    let hi = u32::from(range[1].as_str()?.parse::<std::net::Ipv4Addr>().ok()?);
    (lo <= hi).then_some((lo, hi))
}
fn cidr_interval(s: &str) -> Option<(u32, u32)> {
    let (a, n) = s.split_once('/')?;
    interval(&json!({"prefix":{"addr":a,"len":n.parse::<u8>().ok()?}}))
}
fn selector(
    m: &Value,
    items: &[Value],
    key: &ChainKey,
    ingress: &[&str],
    sources: &[(u32, u32)],
    excluded: &[(u32, u32)],
) -> Scope {
    let op = m["op"].as_str().unwrap_or("");
    let left = &m["left"];
    let right = &m["right"];
    let Some(values) = strings(right, items, key) else {
        // Standard scalar/prefix expressions can intersect LAN; unknown sets cannot.
        return if right.get("prefix").is_some() || right.get("range").is_some() {
            Scope::Yes
        } else {
            Scope::Unknown
        };
    };
    if values.is_empty() && ["==", "in"].contains(&op) {
        return Scope::No;
    }
    if left == &json!({"payload":{"protocol":"ip","field":"saddr"}})
        || left == &json!({"payload":{"protocol":"ip","field":"daddr"}})
    {
        let Some(ranges) = values.iter().map(interval).collect::<Option<Vec<_>>>() else {
            return Scope::Unknown;
        };
        if !["==", "in", "!="].contains(&op) {
            return Scope::Unknown;
        }
        if left["payload"]["field"] == "saddr" {
            if sources.is_empty() {
                return Scope::Unknown;
            }
            let overlap = ranges
                .iter()
                .any(|(a, b)| sources.iter().any(|(c, d)| a <= d && c <= b));
            if op != "!=" {
                return if overlap { Scope::Yes } else { Scope::No };
            }
            let excludes_all = sources
                .iter()
                .all(|(a, b)| ranges.iter().any(|(c, d)| c <= a && b <= d));
            return if excludes_all { Scope::No } else { Scope::Yes };
        }
        if op != "!="
            && ranges
                .iter()
                .all(|(a, b)| excluded.iter().any(|(c, d)| c <= a && b <= d))
        {
            return Scope::No;
        }
        return Scope::Yes;
    }
    let excludes_all = if left == &json!({"meta":{"key":"iifname"}}) {
        if values
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.contains('*') || s.is_empty()))
        {
            return Scope::Unknown;
        }
        !ingress.is_empty()
            && ingress
                .iter()
                .all(|name| values.iter().any(|v| v.as_str() == Some(name)))
    } else if left == &json!({"meta":{"key":"nfproto"}}) {
        values.iter().any(|v| v == "ipv4" || v == "ip" || v == 2)
    } else if left == &json!({"meta":{"key":"l4proto"}}) {
        [6, 17].iter().all(|p| {
            values.iter().any(|v| {
                v.as_u64() == Some(*p) || (*p == 6 && v == "tcp") || (*p == 17 && v == "udp")
            })
        })
    } else {
        false
    };
    let matches = if left == &json!({"meta":{"key":"iifname"}}) {
        if ingress.is_empty() {
            return Scope::Yes;
        }
        Some(
            values
                .iter()
                .any(|v| v.as_str().is_some_and(|n| ingress.contains(&n))),
        )
    } else if left == &json!({"meta":{"key":"nfproto"}}) {
        Some(values.iter().any(|v| v == "ipv4" || v == "ip" || v == 2))
    } else if left == &json!({"meta":{"key":"l4proto"}}) {
        Some(
            values
                .iter()
                .any(|v| v == "tcp" || v == "udp" || v == 6 || v == 17),
        )
    } else if left["payload"]["protocol"] == "ip6" {
        return Scope::No;
    } else if left.get("payload").is_some()
        || left.get("ct").is_some()
        || left.get("&").is_some()
        || left.get("meta").is_some()
        || left.get("fib").is_some()
    {
        None
    } else {
        return Scope::Unknown;
    };
    match (matches, op) {
        (Some(false), "==" | "in") => Scope::No,
        (Some(true), "==" | "in") => Scope::Yes,
        (Some(_), "!=") => {
            if excludes_all {
                Scope::No
            } else {
                Scope::Yes
            }
        }
        (None, "==" | "!=" | "in" | "<" | ">" | "<=" | ">=") => Scope::Yes,
        _ => Scope::Unknown,
    }
}
struct Walk<'a> {
    items: &'a [Value],
    ingress: &'a [&'a str],
    local: &'a [std::net::Ipv4Addr],
    sources: Vec<(u32, u32)>,
    excluded: Vec<(u32, u32)>,
    report: FirewallReport,
    budget: usize,
}
impl Walk<'_> {
    fn chain(
        &mut self,
        key: &ChainKey,
        base: &BaseChain,
        inherited: Scope,
        path: &mut Vec<ChainKey>,
    ) {
        if path.contains(key) || path.len() > 8 || self.budget >= 4096 {
            self.report.push(
                Severity::Warning,
                FirewallConflict::new(&key.1, &key.2, &base.hook, "unknown_traversal_limit"),
            );
            return;
        }
        path.push(key.clone());
        let rules: Vec<_> = self
            .items
            .iter()
            .filter_map(|i| i.get("rule"))
            .filter(|r| r["family"] == key.0 && r["table"] == key.1 && r["chain"] == key.2)
            .collect();
        for rule in rules {
            self.budget += 1;
            if self.budget > 4096 {
                self.report.truncated += 1;
                break;
            }
            if rules::rule_safe(
                rule,
                &key.0,
                &key.1,
                base.chain_type.as_deref(),
                base.priority,
                self.items,
                self.ingress,
                self.local,
            ) {
                continue;
            }
            let Some(xs) = rule["expr"].as_array().filter(|xs| xs.len() <= 64) else {
                self.report.push(
                    Severity::Warning,
                    FirewallConflict::new(&key.1, &key.2, &base.hook, "unknown_rule")
                        .at_rule(Some(base.priority), rule),
                );
                continue;
            };
            let mut scope = inherited;
            for x in xs {
                if let Some(m) = x.get("match") {
                    scope = combine(
                        scope,
                        selector(
                            m,
                            self.items,
                            key,
                            self.ingress,
                            &self.sources,
                            &self.excluded,
                        ),
                    );
                } else if let Some(target) = x
                    .get("jump")
                    .or_else(|| x.get("goto"))
                    .and_then(|j| j["target"].as_str())
                {
                    if scope == Scope::No {
                        continue;
                    }
                    let next = (key.0.clone(), key.1.clone(), target.to_owned());
                    let decl: Vec<_> = self
                        .items
                        .iter()
                        .filter_map(|i| i.get("chain"))
                        .filter(|c| {
                            c["family"] == key.0 && c["table"] == key.1 && c["name"] == target
                        })
                        .collect();
                    if decl.len() == 1 && decl[0].get("hook").is_none() {
                        self.chain(&next, base, scope, path);
                    } else {
                        self.report.push(
                            Severity::Warning,
                            FirewallConflict::new(&key.1, &key.2, &base.hook, "unknown_jump")
                                .at_rule(Some(base.priority), rule),
                        );
                    }
                } else if scope != Scope::No {
                    let early = base.hook == "ingress"
                        || (base.hook == "prerouting"
                            && (base.chain_type.as_deref() == Some("nat") || base.priority <= -90));
                    if x == &json!({"redirect":{"port":53}})
                        && base.chain_type.as_deref() == Some("nat")
                        && base.priority > -101
                        && xs.iter().any(|e| {
                            e["match"]["op"] == "=="
                                && e["match"]["right"] == 53
                                && ["tcp", "udp"].iter().any(|p| {
                                    e["match"]["left"]
                                        == json!({"payload":{"protocol":p,"field":"dport"}})
                                })
                        })
                    {
                        continue;
                    }
                    let reason = if x.get("tproxy").is_some() && early {
                        Some("foreign_tproxy")
                    } else if x.get("redirect").is_some() && early {
                        Some("foreign_redirect")
                    } else if x.get("dnat").is_some() && early {
                        Some("foreign_dnat")
                    } else if x.get("drop").is_some() || x.get("reject").is_some() {
                        Some("foreign_drop")
                    } else if x["mangle"]["key"] == json!({"meta":{"key":"mark"}})
                        && (base.hook == "prerouting" && base.priority >= -90)
                        && super::inventory::mark_update_mask(x).is_none()
                        && (x["mangle"]["value"].is_number()
                            || x["mangle"]["value"].get("ct").is_some())
                    {
                        Some("full_mark_write_after_capture")
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        let severity = if scope == Scope::Yes {
                            Severity::Blocker
                        } else {
                            Severity::Warning
                        };
                        self.report.push(
                            severity,
                            FirewallConflict::new(&key.1, &key.2, &base.hook, reason)
                                .at_rule(Some(base.priority), rule),
                        );
                    } else if x.get("counter").is_none()
                        && x.get("accept").is_none()
                        && x.get("return").is_none()
                        && x.get("mangle").is_none()
                        && x.get("notrack").is_none()
                        && x.get("flow").is_none()
                        && x.get("log").is_none()
                        && x.get("queue").is_none()
                    {
                        self.report.push(
                            Severity::Warning,
                            FirewallConflict::new(&key.1, &key.2, &base.hook, "unknown_expression")
                                .at_rule(Some(base.priority), rule),
                        );
                    } else if scope == Scope::Unknown
                        || x.get("mangle").is_some_and(|m| {
                            m["key"].get("meta").is_some()
                                && super::inventory::mark_update_mask(x).is_none()
                        })
                    {
                        self.report.push(
                            Severity::Warning,
                            FirewallConflict::new(
                                &key.1,
                                &key.2,
                                &base.hook,
                                "unknown_selector_or_mark_effect",
                            )
                            .at_rule(Some(base.priority), rule),
                        );
                    }
                }
            }
        }
        path.pop();
    }
}
pub(super) fn evaluate_scope(
    input: &[u8],
    ingress: &[&str],
    local: &[std::net::Ipv4Addr],
    sources: &[String],
    excluded: &[String],
) -> Result<FirewallReport, InventoryError> {
    if input.len() > 1_048_576 || ingress.len() > 256 {
        return Err(InventoryError::Unsupported);
    }
    let root: Value = serde_json::from_slice(input).map_err(|_| InventoryError::Unsupported)?;
    let items = root["nftables"]
        .as_array()
        .filter(|xs| xs.len() <= 65536)
        .ok_or(InventoryError::Unsupported)?;
    let mut walk = Walk {
        items,
        ingress,
        local,
        sources: sources.iter().filter_map(|s| cidr_interval(s)).collect(),
        excluded: excluded.iter().filter_map(|s| cidr_interval(s)).collect(),
        report: FirewallReport::default(),
        budget: 0,
    };
    let mut keys = BTreeSet::new();
    for c in items.iter().filter_map(|i| i.get("chain")) {
        let key = (
            c["family"]
                .as_str()
                .ok_or(InventoryError::Unsupported)?
                .to_owned(),
            c["table"]
                .as_str()
                .ok_or(InventoryError::Unsupported)?
                .to_owned(),
            c["name"]
                .as_str()
                .ok_or(InventoryError::Unsupported)?
                .to_owned(),
        );
        if !keys.insert(key.clone()) {
            return Err(InventoryError::Unsupported);
        }
        if key.0 == "ip6" {
            continue;
        }
        if !["inet", "ip", "netdev", "bridge"].contains(&key.0.as_str()) {
            continue;
        }
        let Some(hook) = c["hook"]
            .as_str()
            .filter(|h| ["prerouting", "ingress"].contains(h))
        else {
            continue;
        };
        let base = BaseChain {
            hook: hook.into(),
            chain_type: c["type"].as_str().map(str::to_owned),
            policy: c["policy"].as_str().map(str::to_owned),
            priority: c["prio"].as_i64().ok_or(InventoryError::Unsupported)?,
        };
        if base.policy.as_deref() == Some("drop") {
            let mut d = FirewallConflict::new(&key.1, &key.2, hook, "drop_policy");
            d.priority = Some(base.priority);
            walk.report.push(Severity::Blocker, d);
        }
        walk.chain(&key, &base, Scope::Yes, &mut Vec::new());
    }
    Ok(walk.report)
}

pub(super) fn evaluate(
    input: &[u8],
    ingress: &[&str],
    local: &[std::net::Ipv4Addr],
) -> Result<FirewallReport, InventoryError> {
    evaluate_scope(input, ingress, local, &[], &[])
}
