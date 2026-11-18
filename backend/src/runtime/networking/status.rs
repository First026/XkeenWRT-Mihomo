//! Conservative classification of the authoritative recovery journal.
use xkeenwrt_recovery::{Decision, Journal, Operation, State};

#[derive(Debug, PartialEq, Eq)]
pub enum NetworkState {
    Inactive,
    Pending,
    Active,
    Recovering,
    Degraded,
}
/// Evidence must come from a fresh semantic nft dump, exact routing objects,
/// local core health and revoke-fence check, all for this same generation.
pub struct OperationalEvidence<'a> {
    pub nft_semantic_sha256: &'a str,
    pub route_and_rule_match: bool,
    pub core_healthy: bool,
    pub fence_absent: bool,
    /// No owned interception, policy rule or route remains.
    pub network_absent: bool,
}
/// No token or profile material is returned by this read-only classification.
pub fn classify(
    journal: &Journal, boot_id: &str, now_ms: u64, evidence: Option<&OperationalEvidence<'_>>, restarted: bool,
) -> NetworkState {
    if journal.boot_id != boot_id && journal.state == State::Confirmed {
        return NetworkState::Recovering;
    }
    match journal.decision(boot_id, now_ms, restarted) {
        Decision::Invalid => NetworkState::Degraded,
        Decision::Revoke => NetworkState::Recovering,
        Decision::Wait => {
            if evidence.is_some_and(|e| !e.fence_absent) {
                NetworkState::Recovering
            } else {
                NetworkState::Pending
            }
        }
        Decision::Settled => {
            let Some(e) = evidence else {
                return NetworkState::Degraded;
            };
            let inactive_terminal = (journal.state == State::Disabled
                || (journal.state == State::RolledBack && journal.previous_good.is_none()))
                && e.network_absent;
            if !e.fence_absent && !inactive_terminal {
                return NetworkState::Degraded;
            }
            match (journal.state, journal.operation) {
                (State::Confirmed, Operation::Apply)
                    if journal.applied
                        && e.core_healthy
                        && e.route_and_rule_match
                        && e.nft_semantic_sha256 == journal.current.nft_semantic_sha256 =>
                {
                    NetworkState::Active
                }
                (State::Confirmed, Operation::Disable) if journal.applied && e.network_absent => NetworkState::Inactive,
                (State::Disabled, _) if e.network_absent => NetworkState::Inactive,
                (State::RolledBack, _) => match &journal.previous_good {
                    None if e.network_absent => NetworkState::Inactive,
                    Some(previous)
                        if e.core_healthy
                            && e.route_and_rule_match
                            && e.nft_semantic_sha256 == previous.nft_semantic_sha256 =>
                    {
                        NetworkState::Active
                    }
                    _ => NetworkState::Degraded,
                },
                _ => NetworkState::Degraded,
            }
        }
    }
}

fn json_number(value: Option<&serde_json::Value>) -> Option<u32> {
    match value? {
        serde_json::Value::Number(n) => u32::try_from(n.as_u64()?).ok(),
        serde_json::Value::String(s) => s
            .parse()
            .ok()
            .or_else(|| s.strip_prefix("0x").and_then(|v| u32::from_str_radix(v, 16).ok())),
        _ => None,
    }
}

/// Verify absence of every possible object owned by either journal generation.
/// Unknown shapes fail closed; table names alone never prove ownership.
fn owned_resources_absent(
    journal: &Journal, nft: &[u8], rules4: &[u8], routes4: &[u8], rules6: &[u8], routes6: &[u8],
) -> Result<bool, ()> {
    use serde_json::Value;
    if [nft, rules4, routes4, rules6, routes6]
        .iter()
        .any(|bytes| bytes.len() > 1_048_576)
    {
        return Err(());
    }
    let manifests = std::iter::once(&journal.current)
        .chain(journal.previous_good.iter())
        .collect::<Vec<_>>();
    let nft: Value = serde_json::from_slice(nft).map_err(|_| ())?;
    let objects = nft.get("nftables").and_then(Value::as_array).ok_or(())?;
    for item in objects {
        let object = item.as_object().ok_or(())?;
        if object.len() != 1 {
            return Err(());
        }
        let (kind, value) = object.iter().next().ok_or(())?;
        if kind == "table"
            && value.get("family").and_then(Value::as_str) == Some("inet")
            && value.get("name").and_then(Value::as_str) == Some("xkeenwrt")
        {
            return Ok(false);
        }
    }
    for (bytes, is_route) in [(rules4, false), (routes4, true), (rules6, false), (routes6, true)] {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
        let rows = value.as_array().ok_or(())?;
        for row in rows {
            let row = row.as_object().ok_or(())?;
            if is_route {
                let table = match row.get("table") {
                    None => Some(254),
                    Some(Value::String(v)) if v == "main" => Some(254),
                    Some(Value::String(v)) if v == "local" => Some(255),
                    Some(Value::String(v)) if v == "default" => Some(253),
                    Some(v) => json_number(Some(v)),
                }
                .ok_or(())?;
                if manifests.iter().any(|m| table == m.route_table) {
                    return Ok(false);
                }
            } else {
                let priority = json_number(row.get("priority")).ok_or(())?;
                if manifests.iter().any(|m| priority == m.priority) {
                    return Ok(false);
                }
                let mark = match row.get("fwmark") {
                    None if row.contains_key("fwmask") => return Err(()),
                    None => None,
                    Some(Value::String(raw)) => {
                        let (value, inline_mask) = match raw.split_once('/') {
                            Some((value, mask)) => (
                                json_number(Some(&Value::String(value.into()))).ok_or(())?,
                                json_number(Some(&Value::String(mask.into()))).ok_or(())?,
                            ),
                            None => (json_number(Some(&Value::String(raw.into()))).ok_or(())?, u32::MAX),
                        };
                        let mask = if let Some(explicit_mask) = row.get("fwmask") {
                            if inline_mask != u32::MAX {
                                return Err(());
                            }
                            json_number(Some(explicit_mask)).ok_or(())?
                        } else {
                            inline_mask
                        };
                        Some((value, mask))
                    }
                    Some(value) => Some((json_number(Some(value)).ok_or(())?, u32::MAX)),
                };
                if mark.is_some_and(|(_, mask)| manifests.iter().any(|m| mask & m.mask != 0)) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Compare owned routing objects and reject ambiguous duplicates or later rules
/// that overlap the reserved mask. Unknown JSON shapes fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingMatchError;
impl std::fmt::Display for RoutingMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unsupported routing evidence")
    }
}
impl std::error::Error for RoutingMatchError {}

pub fn routing_matches(
    manifest: &xkeenwrt_recovery::Manifest, rules: &[u8], routes: &[u8],
) -> Result<bool, RoutingMatchError> {
    routing_matches_inner(manifest, rules, routes).map_err(|_| RoutingMatchError)
}

fn routing_matches_inner(manifest: &xkeenwrt_recovery::Manifest, rules: &[u8], routes: &[u8]) -> Result<bool, ()> {
    use serde_json::Value;
    fn number(value: &Value) -> Option<u32> {
        match value {
            Value::Number(v) => u32::try_from(v.as_u64()?).ok(),
            Value::String(v) => {
                if let Some(h) = v.strip_prefix("0x") {
                    u32::from_str_radix(h, 16).ok()
                } else {
                    v.parse().ok()
                }
            }
            _ => None,
        }
    }
    fn table(value: Option<&Value>) -> Option<u32> {
        match value {
            None => Some(254),
            Some(Value::String(s)) if s == "main" => Some(254),
            Some(Value::String(s)) if s == "local" => Some(255),
            Some(Value::String(s)) if s == "default" => Some(253),
            Some(v) => number(v),
        }
    }
    fn mark(rule: &serde_json::Map<String, Value>) -> Result<Option<(u32, u32)>, ()> {
        let Some(raw) = rule.get("fwmark") else {
            return if rule.contains_key("fwmask") { Err(()) } else { Ok(None) };
        };
        let (value, mask) = if let Some(s) = raw.as_str() {
            if let Some((value, mask)) = s.split_once('/') {
                (
                    number(&Value::String(value.into())).ok_or(())?,
                    number(&Value::String(mask.into())).ok_or(())?,
                )
            } else {
                (number(raw).ok_or(())?, u32::MAX)
            }
        } else {
            (number(raw).ok_or(())?, u32::MAX)
        };
        let mask = match rule.get("fwmask") {
            Some(v) => {
                if mask != u32::MAX {
                    return Err(());
                }
                number(v).ok_or(())?
            }
            None => mask,
        };
        Ok(Some((value, mask)))
    }
    if rules.len() > 1_048_576 || routes.len() > 1_048_576 {
        return Err(());
    }
    let rules: Value = serde_json::from_slice(rules).map_err(|_| ())?;
    let routes: Value = serde_json::from_slice(routes).map_err(|_| ())?;
    let mut matching = 0;
    for rule in rules.as_array().ok_or(())? {
        let rule = rule.as_object().ok_or(())?;
        let priority = number(rule.get("priority").ok_or(())?).ok_or(())?;
        let observed_mark = mark(rule)?;
        if priority == manifest.priority {
            if table(rule.get("table")) != Some(manifest.route_table)
                || observed_mark != Some((manifest.mark, manifest.mask))
                || rule.get("src").is_some_and(|v| v.as_str() != Some("all"))
                || rule
                    .keys()
                    .any(|k| !["priority", "table", "fwmark", "fwmask", "src"].contains(&k.as_str()))
            {
                return Ok(false);
            }
            matching += 1;
        } else if observed_mark.is_some_and(|(_, mask)| mask & manifest.mask != 0) {
            return Ok(false);
        }
    }
    if matching != 1 {
        return Ok(false);
    }
    let mut matching_routes = 0;
    for route in routes.as_array().ok_or(())? {
        let route = route.as_object().ok_or(())?;
        if table(route.get("table")).ok_or(())? != manifest.route_table {
            continue;
        }
        let dst = route.get("dst").and_then(Value::as_str);
        if !matches!(dst, Some("default") | Some("0.0.0.0/0"))
            || route.get("type").and_then(Value::as_str) != Some("local")
            || route.get("dev").and_then(Value::as_str) != Some("lo")
            || route.get("gateway").is_some()
            || route.get("scope").is_some_and(|v| v.as_str() != Some("host"))
            || route
                .get("flags")
                .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
            || route
                .keys()
                .any(|k| !["dst", "type", "dev", "table", "protocol", "scope", "flags"].contains(&k.as_str()))
        {
            return Ok(false);
        }
        matching_routes += 1;
    }
    Ok(matching_routes == 1)
}

/// Read fresh kernel evidence through fixed bounded commands. Caller supplies
/// core health from its fixed local control path and the authoritative journal.
pub fn inspect_existing(journal: &Journal, core_healthy: bool, cgroup: &std::fs::File) -> NetworkState {
    use super::{
        helper,
        read::{self, Query},
    };
    let run = || -> std::io::Result<NetworkState> {
        use std::io::Read;
        let mut boot = String::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")?
            .take(128)
            .read_to_string(&mut boot)?;
        let boot = boot.trim();
        let parsed = uuid::Uuid::parse_str(boot).map_err(std::io::Error::other)?;
        if parsed.to_string() != boot {
            return Err(std::io::Error::other("invalid boot id"));
        }
        let now = xkeenwrt_recovery::boottime_ms()?;
        let active_generation = xkeenwrt_recovery::active::active_manifest(journal)
            .map(|manifest| manifest.generation)
            .unwrap_or(journal.generation);
        let unfenced = helper::generation_unfenced(active_generation)?;
        let inactive_terminal =
            journal.state == State::Disabled || (journal.state == State::RolledBack && journal.previous_good.is_none());
        if !unfenced && !inactive_terminal {
            return Ok(NetworkState::Recovering);
        }
        if classify(journal, boot, now, None, false) == NetworkState::Recovering {
            return Ok(NetworkState::Recovering);
        }
        let target = match journal.state {
            State::Confirmed if journal.operation == Operation::Apply => Some(&journal.current),
            State::RolledBack => journal.previous_good.as_ref(),
            _ => None,
        };
        if let Some(target) = target {
            let table = read::query(Query::NftOwned, cgroup)?;
            let digest = xkeenwrt_recovery::nft_semantic_digest(&table)?;
            let rules = read::query(Query::Rules4, cgroup)?;
            let routes = read::query(Query::Routes4, cgroup)?;
            let route_and_rule_match = routing_matches(target, &rules, &routes)
                .map_err(|_| std::io::Error::other("invalid routing output"))?;
            let evidence = OperationalEvidence {
                nft_semantic_sha256: &digest,
                route_and_rule_match,
                core_healthy,
                fence_absent: unfenced,
                network_absent: false,
            };
            Ok(classify(journal, boot, now, Some(&evidence), false))
        } else if matches!(journal.state, State::Disabled)
            || (journal.state == State::Confirmed && journal.operation == Operation::Disable)
            || (journal.state == State::RolledBack && journal.previous_good.is_none())
        {
            let nft = read::query(Query::NftRuleset, cgroup)?;
            let rules4 = read::query(Query::Rules4, cgroup)?;
            let routes4 = read::query(Query::Routes4, cgroup)?;
            let rules6 = read::query(Query::Rules6, cgroup)?;
            let routes6 = read::query(Query::Routes6, cgroup)?;
            let network_absent = owned_resources_absent(journal, &nft, &rules4, &routes4, &rules6, &routes6)
                .map_err(|_| std::io::Error::other("invalid owned network evidence"))?;
            let evidence = OperationalEvidence {
                nft_semantic_sha256: "",
                route_and_rule_match: false,
                core_healthy,
                fence_absent: unfenced,
                network_absent,
            };
            Ok(classify(journal, boot, now, Some(&evidence), false))
        } else {
            let evidence = OperationalEvidence {
                nft_semantic_sha256: "",
                route_and_rule_match: false,
                core_healthy,
                fence_absent: unfenced,
                network_absent: false,
            };
            Ok(classify(journal, boot, now, Some(&evidence), false))
        }
    };
    run().unwrap_or(NetworkState::Degraded)
}

/// A settled generation can be archived only when no one holds any of its
/// formerly owned reservations and the project table is absent. Conflicting
/// foreign reuse is ambiguous and therefore also returns false.
pub fn retired_resources_absent(journal: &Journal, inventory: &crate::network::Inventory) -> bool {
    if !inventory.complete || !inventory.hook_topology_verified || inventory.xkeenwrt_table_exists {
        return false;
    }
    let free = |m: &xkeenwrt_recovery::Manifest| {
        !inventory.occupied_tables.contains(&m.route_table)
            && !inventory.occupied_priorities.contains(&m.priority)
            && !inventory.occupied_marks.iter().any(|(_, mask)| mask & m.mask != 0)
    };
    free(&journal.current) && journal.previous_good.as_ref().is_none_or(free)
}
