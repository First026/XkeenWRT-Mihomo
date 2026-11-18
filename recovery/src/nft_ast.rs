//! Typed canonical nftables JSON generated from a validated owned manifest.
use crate::Manifest;
use serde_json::{Value, json};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
fn err() -> io::Error {
    io::Error::other("invalid nft manifest")
}
fn meta(key: &str) -> Value {
    json!({"meta":{"key":key}})
}
fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload":{"protocol":protocol,"field":field}})
}
fn eq(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn ne(left: Value, right: Value) -> Value {
    json!({"match":{"op":"!=","left":left,"right":right}})
}
fn verdict(name: &str) -> Value {
    json!({(name):null})
}
fn l4() -> Value {
    eq(meta("l4proto"), json!({"set":["tcp","udp"]}))
}
fn chain(name: &str, kind: &str, hook: &str, prio: i32) -> Value {
    json!({"chain":{"family":"inet","table":"xkeenwrt","name":name,"type":kind,"hook":hook,"prio":prio,"policy":"accept"}})
}
fn rule(name: &str, expr: Vec<Value>) -> Value {
    json!({"rule":{"family":"inet","table":"xkeenwrt","chain":name,"expr":expr}})
}
fn table(m: &Manifest) -> Value {
    json!({"table":{"family":"inet","name":"xkeenwrt","comment":format!("xkeenwrt:{}:{}",m.owner_id,m.generation)}})
}
fn prefix(s: &str, v6: bool) -> io::Result<Value> {
    let (a, p) = s.split_once('/').ok_or_else(err)?;
    let n: u32 = p.parse().map_err(|_| err())?;
    if v6 {
        let ip: Ipv6Addr = a.parse().map_err(|_| err())?;
        if n > 128 {
            return Err(err());
        }
        let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
        let net = Ipv6Addr::from(u128::from(ip) & mask);
        if n == 128 {
            Ok(json!(net.to_string()))
        } else {
            Ok(json!({"prefix":{"addr":net.to_string(),"len":n}}))
        }
    } else {
        let ip: Ipv4Addr = a.parse().map_err(|_| err())?;
        if n > 32 {
            return Err(err());
        }
        let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        if n == 32 {
            Ok(json!(net.to_string()))
        } else {
            Ok(json!({"prefix":{"addr":net.to_string(),"len":n}}))
        }
    }
}
fn port_set() -> Value {
    json!({"set":[1053,7893]})
}
fn push_ipv4_return(
    v: &mut Vec<Value>,
    seen: &mut std::collections::BTreeSet<String>,
    daddr: Value,
) {
    let Ok(key) = serde_json::to_string(&daddr) else {
        return;
    };
    if seen.insert(key) {
        v.push(rule(
            "capture",
            vec![eq(payload("ip", "daddr"), daddr), verdict("return")],
        ));
    }
}
fn ipv4_broadcast(cidr: &str) -> io::Result<Option<Ipv4Addr>> {
    let (address, prefix) = cidr.split_once('/').ok_or_else(err)?;
    let address: Ipv4Addr = address.parse().map_err(|_| err())?;
    let prefix: u8 = prefix.parse().map_err(|_| err())?;
    if prefix > 32 {
        return Err(err());
    }
    if prefix >= 31 {
        return Ok(None);
    }
    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(address) & mask;
    Ok(Some(Ipv4Addr::from(network | !mask)))
}
impl Manifest {
    fn source4(&self) -> io::Result<Vec<Value>> {
        if let Some(scope) = &self.lan_scope {
            Ok(vec![eq(payload("ip", "saddr"), prefix(scope, false)?)])
        } else {
            Ok(vec![
                eq(payload("ether", "saddr"), json!(self.selected_mac)),
                eq(payload("ip", "saddr"), json!(self.source_ipv4.to_string())),
            ])
        }
    }
    fn source6(&self) -> Vec<Value> {
        let mut filters = vec![];
        if !self.whole_lan() {
            filters.push(eq(payload("ether", "saddr"), json!(self.selected_mac)));
        }
        filters.push(eq(meta("nfproto"), json!("ipv6")));
        filters
    }
    /// Expected kernel-list JSON before dynamic handles/counters. VM roundtrip is required.
    pub fn expected_nft_ast(&self) -> io::Result<Value> {
        if !self.valid() {
            return Err(err());
        }
        let mut v = vec![
            table(self),
            chain("dns", "nat", "prerouting", -151),
            chain(
                "capture",
                "filter",
                "prerouting",
                if self.capture_version == Some(1) {
                    -90
                } else {
                    -150
                },
            ),
            chain("ipv6block", "filter", "forward", -1),
            chain("inputguard", "filter", "input", -1),
        ];
        let mut dns = vec![eq(meta("iifname"), json!(self.lan_interface))];
        dns.extend(self.source4()?);
        dns.extend([
            l4(),
            eq(payload("th", "dport"), json!(53)),
            json!({"redirect":{"port":1053}}),
        ]);
        v.push(rule("dns", dns));
        v.push(rule(
            "capture",
            vec![
                ne(meta("iifname"), json!(self.lan_interface)),
                verdict("return"),
            ],
        ));
        if !self.whole_lan() {
            v.push(rule(
                "capture",
                vec![
                    ne(payload("ether", "saddr"), json!(self.selected_mac)),
                    verdict("return"),
                ],
            ));
        }

        v.push(rule(
            "capture",
            vec![ne(meta("nfproto"), json!("ipv4")), verdict("return")],
        ));
        v.push(rule(
            "capture",
            vec![
                ne(
                    payload("ip", "saddr"),
                    match &self.lan_scope {
                        Some(scope) => prefix(scope, false)?,
                        None => json!(self.source_ipv4.to_string()),
                    },
                ),
                verdict("return"),
            ],
        ));
        v.push(rule(
            "capture",
            vec![
                l4(),
                eq(payload("th", "dport"), json!(53)),
                verdict("return"),
            ],
        ));
        v.push(rule(
            "capture",
            vec![
                l4(),
                eq(payload("th", "dport"), json!(1053)),
                verdict("return"),
            ],
        ));
        let mut ipv4_bypass = std::collections::BTreeSet::new();
        push_ipv4_return(
            &mut v,
            &mut ipv4_bypass,
            json!(self.management_ipv4.to_string()),
        );
        push_ipv4_return(&mut v, &mut ipv4_bypass, prefix("127.0.0.0/8", false)?);
        for n in &self.local_ipv4 {
            let network = prefix(n, false)?;
            push_ipv4_return(&mut v, &mut ipv4_bypass, network);
            if let Some(broadcast) = ipv4_broadcast(n)? {
                push_ipv4_return(&mut v, &mut ipv4_bypass, json!(broadcast.to_string()));
            }
        }
        push_ipv4_return(&mut v, &mut ipv4_bypass, prefix("224.0.0.0/4", false)?);
        push_ipv4_return(&mut v, &mut ipv4_bypass, json!("255.255.255.255"));
        if self.capture_version == Some(1) {
            v.push(rule(
                "capture",
                vec![
                    json!({"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}}),
                    verdict("return"),
                ],
            ));
        }
        v.push(rule(
            "capture",
            vec![
                l4(),
                json!({"mangle":{"key":meta("mark"),"value":{"|":[meta("mark"),self.mark]}}}),
                json!({"tproxy":{"family":"ip","addr":self.lan_address.to_string(),"port":7893}}),
                verdict("accept"),
            ],
        ));
        v.push(rule(
            "ipv6block",
            vec![
                ne(meta("iifname"), json!(self.lan_interface)),
                verdict("return"),
            ],
        ));
        v.push(rule(
            "ipv6block",
            vec![
                eq(
                    payload("icmpv6", "type"),
                    json!({"set":["destination-unreachable","packet-too-big","time-exceeded","parameter-problem","nd-router-solicit","nd-router-advert","nd-neighbor-solicit","nd-neighbor-advert","nd-redirect"]}),
                ),
                verdict("return"),
            ],
        ));
        for ip in &self.management_ipv6 {
            v.push(rule(
                "ipv6block",
                vec![
                    eq(payload("ip6", "daddr"), json!(ip.to_string())),
                    verdict("return"),
                ],
            ));
        }
        for n in &self.local_ipv6 {
            v.push(rule(
                "ipv6block",
                vec![
                    eq(payload("ip6", "daddr"), prefix(n, true)?),
                    verdict("return"),
                ],
            ));
        }
        let mut block6 = self.source6();
        block6.push(verdict("drop"));
        v.push(rule("ipv6block", block6));
        v.push(rule(
            "inputguard",
            vec![
                eq(meta("iifname"), json!("lo")),
                l4(),
                eq(payload("th", "dport"), port_set()),
                verdict("return"),
            ],
        ));
        let mut input = vec![eq(meta("iifname"), json!(self.lan_interface))];
        input.extend(self.source4()?);
        input.extend([
            l4(),
            eq(payload("th", "dport"), port_set()),
            verdict("return"),
        ]);
        v.push(rule("inputguard", input));
        v.push(rule(
            "inputguard",
            vec![
                l4(),
                eq(payload("th", "dport"), port_set()),
                verdict("drop"),
            ],
        ));
        Ok(json!({"nftables":v}))
    }
    pub fn expected_failblock_ast(&self, owner: &Manifest) -> io::Result<Value> {
        if !self.valid() || !owner.valid() || self.owner_id != owner.owner_id {
            return Err(err());
        }
        let mut v = vec![table(owner), chain("failblock", "filter", "forward", -1)];
        v.push(rule(
            "failblock",
            vec![
                ne(meta("iifname"), json!(self.lan_interface)),
                verdict("return"),
            ],
        ));
        v.push(rule(
            "failblock",
            vec![
                eq(
                    payload("ip", "daddr"),
                    json!(self.management_ipv4.to_string()),
                ),
                verdict("return"),
            ],
        ));
        for ip in &self.management_ipv6 {
            v.push(rule(
                "failblock",
                vec![
                    eq(payload("ip6", "daddr"), json!(ip.to_string())),
                    verdict("return"),
                ],
            ));
        }
        for n in &self.local_ipv4 {
            v.push(rule(
                "failblock",
                vec![
                    eq(payload("ip", "daddr"), prefix(n, false)?),
                    verdict("return"),
                ],
            ));
        }
        for n in &self.local_ipv6 {
            v.push(rule(
                "failblock",
                vec![
                    eq(payload("ip6", "daddr"), prefix(n, true)?),
                    verdict("return"),
                ],
            ));
        }
        v.push(rule(
            "failblock",
            vec![
                eq(
                    payload("icmpv6", "type"),
                    json!({"set":["destination-unreachable","packet-too-big","time-exceeded","parameter-problem","nd-router-solicit","nd-router-advert","nd-neighbor-solicit","nd-neighbor-advert","nd-redirect"]}),
                ),
                verdict("return"),
            ],
        ));
        let mut block4 = self.source4()?;
        block4.push(verdict("drop"));
        v.push(rule("failblock", block4));
        let mut block6 = self.source6();
        block6.push(verdict("drop"));
        v.push(rule("failblock", block6));
        Ok(json!({"nftables":v}))
    }
    pub fn nft_json_batch(&self, replace: bool) -> io::Result<String> {
        json_batch(self.expected_nft_ast()?, replace)
    }
    pub fn failblock_json_batch(&self, owner: &Manifest, replace: bool) -> io::Result<String> {
        json_batch(self.expected_failblock_ast(owner)?, replace)
    }
}
fn json_batch(ast: Value, replace: bool) -> io::Result<String> {
    let entries = ast
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(err)?;
    let mut commands = Vec::new();
    if replace {
        commands.push(json!({"delete":{"table":{"family":"inet","name":"xkeenwrt"}}}));
    }
    commands.extend(entries.iter().map(|entry| json!({"add":entry})));
    serde_json::to_string(&json!({"nftables":commands})).map_err(io::Error::other)
}
