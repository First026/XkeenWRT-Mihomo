//! Semantic admission for hooks that must run before late LAN capture.
//! Table names never grant permission. Every reachable LAN rule is checked;
//! ingress exclusion resolves a unique same-table interface set.
use crate::evidence::inventory::mark_update_mask;
use serde_json::{Value, json};

fn number(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| n.try_into().ok()).or_else(|| {
        let s = v.as_str()?;
        s.strip_prefix("0x")
            .and_then(|n| u32::from_str_radix(n, 16).ok())
            .or_else(|| s.parse().ok())
    })
}
fn iface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn same(v: &Value, family: &str, table: &str) -> bool {
    v["family"] == family && v["table"] == table
}
fn set<'a>(
    items: &'a [Value],
    family: &str,
    table: &str,
    name: &str,
    typ: &str,
) -> Option<&'a Value> {
    let mut found = items
        .iter()
        .filter_map(|i| i.get("set"))
        .filter(|s| same(s, family, table) && s["name"] == name);
    let s = found.next()?;
    if found.next().is_some() || s["type"] != typ {
        return None;
    }
    Some(s)
}
fn interfaces(v: &Value, items: &[Value], family: &str, table: &str) -> Option<Vec<String>> {
    if let Some(s) = v.as_str() {
        if let Some(name) = s.strip_prefix('@') {
            let s = set(items, family, table, name, "ifname")?;
            return names(s.get("elem").unwrap_or(&json!([])));
        }
        return iface(s).then(|| vec![s.to_owned()]);
    }
    if v.as_object()?.len() != 1 {
        return None;
    }
    names(v.get("set")?)
}
fn names(v: &Value) -> Option<Vec<String>> {
    let a = v.as_array()?;
    if a.len() > 256 {
        return None;
    }
    a.iter()
        .map(|v| v.as_str().filter(|s| iface(s)).map(str::to_owned))
        .collect()
}
fn expression(v: &Value, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    if let Some(o) = v.as_object().filter(|o| o.len() == 1) {
        if let Some(m) = o.get("meta").and_then(Value::as_object) {
            return m.len() == 1
                && matches!(
                    m.get("key").and_then(Value::as_str),
                    Some("iifname" | "oifname" | "nfproto" | "l4proto" | "mark")
                );
        }
        if let Some(m) = o.get("ct").and_then(Value::as_object) {
            return m.keys().all(|k| ["key", "dir"].contains(&k.as_str()))
                && matches!(
                    m.get("key").and_then(Value::as_str),
                    Some("state" | "status" | "mark" | "packets")
                )
                && m.get("dir")
                    .is_none_or(|d| matches!(d.as_str(), Some("original" | "reply")));
        }
        if let Some(m) = o.get("payload").and_then(Value::as_object) {
            return m.len() == 2
                && matches!(
                    (
                        m.get("protocol").and_then(Value::as_str),
                        m.get("field").and_then(Value::as_str)
                    ),
                    (Some("ip" | "ip6"), Some("saddr" | "daddr"))
                        | (Some("tcp" | "udp"), Some("sport" | "dport"))
                        | (Some("tcp"), Some("flags"))
                        | (Some("icmp" | "icmpv6"), Some("type"))
                );
        }
        if let Some(a) = o.get("&").and_then(Value::as_array) {
            return a.len() == 2 && expression(&a[0], depth + 1) && number(&a[1]).is_some();
        }
    }
    false
}
fn literal(v: &Value, depth: usize, items: &[Value], family: &str, table: &str) -> bool {
    if depth > 4 {
        return false;
    }
    if let Some(s) = v.as_str() {
        if let Some(n) = s.strip_prefix('@') {
            return ["ifname", "ipv4_addr", "ipv6_addr", "inet_service"]
                .iter()
                .any(|t| set(items, family, table, n, t).is_some());
        }
        return !s.is_empty() && s.len() <= 128 && !s.contains(['\n', '\r', '\0']);
    }
    if v.as_u64().is_some() || v.is_boolean() {
        return true;
    }
    if let Some(o) = v.as_object().filter(|o| o.len() == 1) {
        for k in ["set", "range"] {
            if let Some(a) = o.get(k).and_then(Value::as_array) {
                return !a.is_empty()
                    && a.len() <= 256
                    && a.iter()
                        .all(|x| literal(x, depth + 1, items, family, table));
            }
        }
        if let Some(p) = o.get("prefix").and_then(Value::as_object) {
            return p.len() == 2
                && p.get("addr")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
                && p.get("len")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n <= 128);
        }
    }
    false
}
fn exact_match(m: &Value, lhs: Value, rhs: Value) -> bool {
    *m == json!({"op":"==","left":lhs,"right":rhs})
}
fn telegram_ports(v: &Value) -> bool {
    let p = |x: &Value| x.as_u64().is_some_and(|n| [80, 443, 5222].contains(&n));
    p(v) || v
        .as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get("set"))
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty() && a.len() <= 3 && a.iter().all(p))
}
#[derive(Clone, Default)]
struct Proof {
    excluded: bool,
    telegram: bool,
    interfaces: Option<Vec<String>>,
    tcp_ports: bool,
    ttl: bool,
    invalid: bool,
    marked: bool,
    nat_mark: Option<u32>,
    scoped_mark_effect: bool,
}

/// An address-scoped OR in an earlier prerouting hook is the only admitted
/// source of a NAT discriminator. Inspect every writer of the tested bits;
/// one unrelated/late writer invalidates the proof, even in another table.
fn nat_mark_source(items: &[Value], mask: u32, nat_priority: i64, ingress: &[&str]) -> bool {
    if mask == 0 || ingress.is_empty() {
        return false;
    }
    let mut covered = std::collections::BTreeSet::new();
    for r in items.iter().filter_map(|i| i.get("rule")) {
        let Some(xs) = r["expr"].as_array() else {
            return false;
        };
        if !xs
            .iter()
            .any(|e| mark_update_mask(e).is_some_and(|bits| bits & mask != 0))
        {
            continue;
        }
        let (Some(family), Some(table), Some(chain)) = (
            r["family"].as_str(),
            r["table"].as_str(),
            r["chain"].as_str(),
        ) else {
            return false;
        };
        let mut bases = items
            .iter()
            .filter_map(|i| i.get("chain"))
            .filter(|c| same(c, family, table) && c["name"] == chain);
        let Some(base) = bases.next() else {
            return false;
        };
        if bases.next().is_some()
            || family != "inet"
            || base["type"] != "filter"
            || base["hook"] != "prerouting"
            || base["policy"] != "accept"
            || !base["prio"]
                .as_i64()
                .is_some_and(|p| p < nat_priority.min(-100))
        {
            return false;
        }
        let mut ifnames = None;
        let mut address = false;
        let mut effect = false;
        for (index, e) in xs.iter().enumerate() {
            if let Some(m) = e.get("match") {
                if effect {
                    return false;
                }
                if m["op"] == "==" && m["left"] == json!({"meta":{"key":"iifname"}}) {
                    if ifnames.is_some() {
                        return false;
                    }
                    ifnames = interfaces(&m["right"], items, family, table);
                    if ifnames.is_none() {
                        return false;
                    }
                } else if m["op"] == "=="
                    && m["left"] == json!({"payload":{"protocol":"ip","field":"daddr"}})
                    && m["right"]
                        .as_str()
                        .and_then(|s| s.strip_prefix('@'))
                        .is_some_and(|n| set(items, family, table, n, "ipv4_addr").is_some())
                {
                    address = true;
                } else if m["op"] == "=="
                    && m["left"] == json!({"payload":{"protocol":"tcp","field":"dport"}})
                    && telegram_ports(&m["right"])
                {
                    // A narrower producer still proves the corresponding NAT
                    // ports only when the writer has no narrower port predicate.
                    return false;
                } else {
                    return false;
                }
            } else if e.get("counter").is_some() {
                if !e["counter"].as_object().is_some_and(|o| {
                    o.len() == 2 && o["packets"].as_u64().is_some() && o["bytes"].as_u64().is_some()
                }) {
                    return false;
                }
            } else if e == &json!({"return":null}) && index + 1 == xs.len() && effect {
            } else if let Some(a) = e["mangle"]["value"]["|"].as_array() {
                if effect
                    || e["mangle"]["key"] != json!({"meta":{"key":"mark"}})
                    || a.len() != 2
                    || a[0] != json!({"meta":{"key":"mark"}})
                    || !number(&a[1]).is_some_and(|n| n & mask == mask)
                    || !address
                    || ifnames.as_ref().is_none_or(Vec::is_empty)
                {
                    return false;
                }
                effect = true;
            } else {
                return false;
            }
        }
        if !effect || !address {
            return false;
        }
        covered.extend(ifnames.unwrap_or_default());
    }
    ingress.iter().all(|n| covered.contains(*n))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn rule_safe(
    rule: &Value,
    family: &str,
    table: &str,
    typ: Option<&str>,
    priority: i64,
    items: &[Value],
    ingress: &[&str],
    local: &[std::net::Ipv4Addr],
) -> bool {
    if family != "inet" || ingress.is_empty() {
        return false;
    }
    let nat = typ == Some("nat") && [-100, -99].contains(&priority);
    if !nat && (typ != Some("filter") || priority >= -90) {
        return false;
    }
    walk(
        rule,
        family,
        table,
        nat,
        priority,
        local,
        items,
        ingress,
        Proof::default(),
        &mut Vec::new(),
        &mut 0,
    )
}
#[allow(clippy::too_many_arguments)]
fn walk(
    rule: &Value,
    family: &str,
    table: &str,
    nat: bool,
    priority: i64,
    local: &[std::net::Ipv4Addr],
    items: &[Value],
    ingress: &[&str],
    mut proof: Proof,
    path: &mut Vec<String>,
    budget: &mut usize,
) -> bool {
    *budget += 1;
    if path.len() > 8 || *budget > 4096 {
        return false;
    }
    let Some(xs) = rule
        .get("expr")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty() && a.len() <= 64)
    else {
        return false;
    };
    let mut effect = false;
    for (index, x) in xs.iter().enumerate() {
        let Some(o) = x.as_object().filter(|o| o.len() == 1) else {
            return false;
        };
        if let Some(m) = o.get("match") {
            if m.as_object().is_none_or(|o| o.len() != 3)
                || !matches!(
                    m["op"].as_str(),
                    Some("==" | "!=" | "in" | "<" | ">" | "<=" | ">=")
                )
                || !expression(&m["left"], 0)
                || !literal(&m["right"], 0, items, family, table)
            {
                return false;
            }
            if !effect
                && m["op"] == "=="
                && m["left"] == json!({"meta":{"key":"iifname"}})
                && let Some(names) = interfaces(&m["right"], items, family, table)
            {
                proof.excluded |= names.iter().all(|n| !ingress.contains(&n.as_str()));
                proof.interfaces = Some(names);
            }
            if m["op"] == "=="
                && m["left"] == json!({"payload":{"protocol":"ip","field":"daddr"}})
                && m["right"]
                    .as_str()
                    .and_then(|s| s.strip_prefix('@'))
                    .is_some_and(|n| set(items, family, table, n, "ipv4_addr").is_some())
            {
                proof.telegram = true;
            }
            if m["op"] == "=="
                && m["left"] == json!({"payload":{"protocol":"tcp","field":"dport"}})
                && telegram_ports(&m["right"])
            {
                proof.tcp_ports = true;
            }
            proof.ttl |= ["icmp", "icmpv6"].iter().any(|p| {
                exact_match(
                    m,
                    json!({"payload":{"protocol":p,"field":"type"}}),
                    json!("time-exceeded"),
                )
            });
            proof.invalid |= ["==", "in"].contains(&m["op"].as_str().unwrap_or(""))
                && m["left"] == json!({"ct":{"key":"state"}})
                && m["right"] == "invalid";
            if !effect
                && m["op"] == "=="
                && let Some(a) = m["left"]["&"].as_array()
                && a.len() == 2
                && a[0] == json!({"meta":{"key":"mark"}})
                && let Some(mask) = number(&a[1]).filter(|n| *n != 0)
                && number(&m["right"]) == Some(mask)
            {
                proof.nat_mark = Some(mask);
            }
            proof.marked |= m["op"] == "!="
                && m["right"] == 0
                && m["left"]["&"].as_array().is_some_and(|a| {
                    a.len() == 2
                        && [json!({"ct":{"key":"mark"}}), json!({"meta":{"key":"mark"}})]
                            .contains(&a[0])
                        && number(&a[1]).is_some_and(|n| n != 0)
                });
            continue;
        }
        if let Some(c) = o.get("counter").and_then(Value::as_object) {
            if c.len() == 2
                && c.get("packets").and_then(Value::as_u64).is_some()
                && c.get("bytes").and_then(Value::as_u64).is_some()
            {
                continue;
            }
            return false;
        }
        // This whole remaining branch cannot execute for LAN. No global skip by table name.
        if proof.excluded && !nat {
            return true;
        }
        if !nat && mark_update_mask(x).is_some() {
            effect = true;
            proof.scoped_mark_effect |= proof.telegram
                && proof.interfaces.as_ref().is_some_and(|n| !n.is_empty())
                && x["mangle"]["key"] == json!({"meta":{"key":"mark"}})
                && x["mangle"]["value"]["|"].as_array().is_some_and(|a| {
                    a.len() == 2
                        && a[0] == json!({"meta":{"key":"mark"}})
                        && number(&a[1]).is_some_and(|n| n != 0)
                });
            continue;
        }
        if let Some(j) = o
            .get("jump")
            .or_else(|| o.get("goto"))
            .and_then(Value::as_object)
        {
            if index + 1 != xs.len() || j.len() != 1 {
                return false;
            }
            let Some(target) = j.get("target").and_then(Value::as_str) else {
                return false;
            };
            if path.iter().any(|n| n == target) {
                return false;
            }
            let mut decl = items
                .iter()
                .filter_map(|i| i.get("chain"))
                .filter(|c| same(c, family, table) && c["name"] == target);
            let Some(c) = decl.next() else {
                return false;
            };
            if decl.next().is_some()
                || ["hook", "type", "prio", "policy"]
                    .iter()
                    .any(|k| c.get(*k).is_some())
            {
                return false;
            }
            path.push(target.to_owned());
            let ok = items
                .iter()
                .filter_map(|i| i.get("rule"))
                .filter(|r| same(r, family, table) && r["chain"] == target)
                .all(|r| {
                    walk(
                        r,
                        family,
                        table,
                        nat,
                        priority,
                        local,
                        items,
                        ingress,
                        proof.clone(),
                        path,
                        budget,
                    )
                });
            path.pop();
            return ok;
        }
        if index + 1 != xs.len() {
            return false;
        }
        if !nat && x == &json!({"drop":null}) {
            return proof.ttl && (proof.invalid || proof.marked);
        }
        if !nat && x == &json!({"return":null}) {
            return proof.scoped_mark_effect;
        }
        let nat_ingress: Vec<&str> = proof
            .interfaces
            .as_ref()
            .map(|n| n.iter().map(String::as_str).collect())
            .unwrap_or_else(|| ingress.to_vec());
        let scoped_nat = proof.telegram
            || proof
                .nat_mark
                .is_some_and(|m| nat_mark_source(items, m, priority, &nat_ingress));
        if nat && scoped_nat && proof.tcp_ports {
            if x == &json!({"redirect":{"port":8490}}) {
                return true;
            }
            if let Some(d) = o.get("dnat").and_then(Value::as_object) {
                return d
                    .keys()
                    .all(|k| ["addr", "port", "family"].contains(&k.as_str()))
                    && d.get("port") == Some(&json!(8490))
                    && d.get("addr").and_then(Value::as_str).is_some_and(|s| {
                        s.parse::<std::net::Ipv4Addr>()
                            .is_ok_and(|a| local.contains(&a))
                    })
                    && d.get("family").is_none_or(|f| f == "ip");
            }
        }
        return false;
    }
    // Counters/mark updates have no terminal verdict. Unknown empty rules are not admitted.
    effect || proof.excluded || xs.iter().any(|x| x.get("counter").is_some())
}
