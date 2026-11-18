//! Shared semantic admission and revalidation of foreign firewall traversal.
//! Inputs come from bounded trusted OS inventory; table names grant no trust.
use crate::evidence::inventory::{self, InventoryError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
mod report;
mod rules;
pub use report::{Finding, FirewallReport, Severity};

type ChainKey = (String, String, String);
struct BaseChain {
    hook: String,
    chain_type: Option<String>,
    policy: Option<String>,
    priority: i64,
}
/// Caller must prove the complete set of physical/bridge ingress interfaces.
/// Unknown syntax is reported separately from a proven conflict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FirewallConflict {
    pub table: String,
    pub chain: String,
    pub hook: String,
    pub reason: &'static str,
    pub priority: Option<i64>,
    pub rule_id: String,
    pub affected_traffic: &'static str,
}
impl FirewallConflict {
    fn new(table: &str, chain: &str, hook: &str, reason: &'static str) -> Self {
        fn safe(s: &str) -> String {
            if !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                s.into()
            } else {
                "unknown".into()
            }
        }
        Self {
            table: safe(table),
            chain: safe(chain),
            hook: safe(hook),
            reason,
            priority: None,
            rule_id: "chain-policy".into(),
            affected_traffic: "IPv4 LAN",
        }
    }
    fn at_rule(mut self, priority: Option<i64>, rule: &Value) -> Self {
        self.priority = priority;
        let mut r = rule.clone();
        if let Some(o) = r.as_object_mut() {
            o.remove("handle");
        }
        if let Some(xs) = r["expr"].as_array_mut() {
            for e in xs {
                if e.get("counter").is_some() {
                    e["counter"] = serde_json::json!({"packets":0,"bytes":0});
                }
            }
        }
        self.rule_id = format!(
            "sha256-{}",
            Sha256::digest(serde_json::to_vec(&r).unwrap_or_default())
                .iter()
                .take(6)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        self
    }
    pub fn message(&self) -> String {
        format!(
            "Конфликт firewall: таблица {}, цепочка {}, hook {}, priority {:?}, правило {}, вид {}, трафик {}. Перехват не включён.",
            self.table,
            self.chain,
            self.hook,
            self.priority,
            self.rule_id,
            self.reason,
            self.affected_traffic
        )
    }
}
pub fn hook_topology_for_ingress(input: &[u8], ingress: &[&str]) -> Result<bool, InventoryError> {
    topology_conflict(input, ingress).map(|c| c.is_none())
}
pub fn topology_conflict(
    input: &[u8],
    ingress: &[&str],
) -> Result<Option<FirewallConflict>, InventoryError> {
    classify(input, ingress, &[])
}

/// `addresses` is the raw kernel `ip -j address` snapshot, never an HTTP flag.
/// Exact local addresses, rather than connected subnets, prove DNAT locality.
pub fn topology_conflict_with_inventory(
    input: &[u8],
    ingress: &[&str],
    addresses: &[u8],
) -> Result<Option<FirewallConflict>, InventoryError> {
    let report = compatibility_report(input, ingress, addresses)?;
    if report.truncated != 0 {
        return Err(InventoryError::Unsupported);
    }
    Ok(report
        .findings
        .into_iter()
        .find(|f| f.severity == Severity::Blocker)
        .map(|f| f.detail))
}
pub fn compatibility_report(
    input: &[u8],
    ingress: &[&str],
    addresses: &[u8],
) -> Result<FirewallReport, InventoryError> {
    if addresses.is_empty() {
        return report::evaluate(input, ingress, &[]);
    }
    let facts = inventory::address_facts(
        addresses,
        ingress
            .first()
            .copied()
            .ok_or(InventoryError::Unsupported)?,
    )?;
    let locals: Vec<_> = facts
        .local_ipv4
        .iter()
        .filter_map(|c| c.split_once('/')?.0.parse().ok())
        .collect();
    report::evaluate_scope(input, ingress, &locals, &facts.lan_cidrs, &facts.local_ipv4)
}

fn classify(
    input: &[u8],
    ingress: &[&str],
    local: &[std::net::Ipv4Addr],
) -> Result<Option<FirewallConflict>, InventoryError> {
    let report = report::evaluate(input, ingress, local)?;
    if report.truncated != 0 {
        return Err(InventoryError::Unsupported);
    }
    Ok(report
        .findings
        .into_iter()
        .find(|f| f.severity == Severity::Blocker)
        .map(|f| f.detail))
}
