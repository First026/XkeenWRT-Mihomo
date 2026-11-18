//! Restore only resources identified by the journal's validated manifests.
use crate::commands::{ip, nft};
use serde_json::Value;
use std::io;
use xkeenwrt_recovery::{Journal, Manifest};
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn table_snapshot() -> io::Result<Option<(String, Vec<u8>)>> {
    let list = nft(&["-j", "list", "tables"], None)?;
    if !list.success {
        return Err(fail("cannot inspect nft tables"));
    }
    let parsed: Value = serde_json::from_slice(&list.bytes).map_err(io::Error::other)?;
    let Some(items) = parsed.get("nftables").and_then(Value::as_array) else {
        return Err(fail("invalid nft inventory"));
    };
    let present = items.iter().filter_map(|item| item.get("table")).any(|t| {
        t.get("family").and_then(Value::as_str) == Some("inet")
            && t.get("name").and_then(Value::as_str) == Some("xkeenwrt")
    });
    if !present {
        return Ok(None);
    }
    let output = nft(&["-j", "list", "table", "inet", "xkeenwrt"], None)?;
    if !output.success {
        return Err(fail("cannot inspect owned table"));
    }
    let parsed: Value = serde_json::from_slice(&output.bytes).map_err(io::Error::other)?;
    let items = parsed
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("invalid nft table"))?;
    let table = items
        .iter()
        .filter_map(|v| v.get("table"))
        .find(|v| {
            v.get("family").and_then(Value::as_str) == Some("inet")
                && v.get("name").and_then(Value::as_str) == Some("xkeenwrt")
        })
        .ok_or_else(|| fail("missing table metadata"))?;
    let comment = table
        .get("comment")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("table lacks owner"))?;
    Ok(Some((comment.to_owned(), output.bytes)))
}
fn table_owner() -> io::Result<Option<String>> {
    table_snapshot().map(|snapshot| snapshot.map(|(owner, _)| owner))
}
fn owned_states(owner: &Manifest, failblock_sources: &[&Manifest]) -> io::Result<Vec<Value>> {
    let mut states = vec![owner.expected_nft_ast()?];
    for source in failblock_sources {
        states.push(source.expected_failblock_ast(owner)?);
    }
    Ok(states)
}
fn prove_owned_table(
    bytes: &[u8],
    owner: &Manifest,
    failblock_sources: &[&Manifest],
) -> io::Result<()> {
    let states = owned_states(owner, failblock_sources)?;
    if xkeenwrt_recovery::nft_ownership_proof(bytes, &states)? {
        Ok(())
    } else {
        Err(fail("nft table does not match a generated ownership shape"))
    }
}
fn numeric(v: &Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    let s = v.as_str()?;
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
fn objects(rule: bool) -> io::Result<Vec<Value>> {
    let args: Vec<String> = if rule {
        vec!["-j", "-4", "rule", "show"]
    } else {
        vec!["-j", "-4", "route", "show", "table", "all"]
    }
    .into_iter()
    .map(String::from)
    .collect();
    let output = ip(&args)?;
    if !output.success {
        return Err(fail("cannot inventory policy routing"));
    }
    serde_json::from_slice::<Vec<Value>>(&output.bytes).map_err(io::Error::other)
}
fn exists(m: &Manifest, rule: bool) -> io::Result<bool> {
    let items = objects(rule)?;
    if rule {
        let matching: Vec<_> = items
            .iter()
            .filter(|item| item.get("priority").and_then(numeric) == Some(m.priority))
            .collect();
        if matching.is_empty() {
            return Ok(false);
        }
        if matching.len() != 1 {
            return Err(fail("duplicate rules at priority"));
        }
        let item = matching[0];
        let allowed = [
            "priority", "src", "table", "fwmark", "fwmask", "protocol", "type", "flags",
        ];
        let valid_fields = item
            .as_object()
            .is_some_and(|o| o.keys().all(|key| allowed.contains(&key.as_str())));
        let protocol = item.get("protocol").and_then(Value::as_str);
        let rule_type = item.get("type").and_then(Value::as_str);
        let flags = item.get("flags").and_then(Value::as_array);
        if valid_fields
            && item.get("src").and_then(Value::as_str) == Some("all")
            && (protocol.is_none() || protocol == Some("boot"))
            && (rule_type.is_none() || rule_type == Some("unicast"))
            && flags.is_none_or(|f| f.is_empty())
            && item.get("fwmark").and_then(numeric) == Some(m.mark)
            && item.get("fwmask").and_then(numeric).unwrap_or(u32::MAX) == m.mask
            && item.get("table").and_then(numeric) == Some(m.route_table)
        {
            return Ok(true);
        }
        Err(fail("foreign rule occupies priority"))
    } else {
        let routes: Vec<_> = items
            .iter()
            .filter(|item| item.get("table").and_then(numeric) == Some(m.route_table))
            .collect();
        if routes.is_empty() {
            return Ok(false);
        }
        if routes.len() != 1 {
            return Err(fail("multiple routes in table"));
        }
        let item = routes[0];
        let allowed = ["type", "dst", "dev", "table", "protocol", "scope", "flags"];
        let valid_fields = item
            .as_object()
            .is_some_and(|o| o.keys().all(|key| allowed.contains(&key.as_str())));
        let protocol = item.get("protocol").and_then(Value::as_str);
        let scope = item.get("scope").and_then(Value::as_str);
        let flags = item.get("flags").and_then(Value::as_array);
        if valid_fields
            && item.get("type").and_then(Value::as_str) == Some("local")
            && matches!(
                item.get("dst").and_then(Value::as_str),
                Some("default" | "0.0.0.0/0")
            )
            && item.get("dev").and_then(Value::as_str) == Some("lo")
            && (protocol.is_none() || protocol == Some("boot"))
            && (scope.is_none() || scope == Some("host"))
            && flags.is_none_or(|f| f.is_empty())
        {
            return Ok(true);
        }
        Err(fail("foreign route occupies table"))
    }
}
fn reconcile_ip(m: &Manifest, add: bool, rule: bool) -> io::Result<()> {
    if exists(m, rule)? == add {
        return Ok(());
    }
    checked_ip(args(m, if add { "add" } else { "del" }, rule))?;
    if exists(m, rule)? != add {
        return Err(fail("policy routing verification failed"));
    }
    Ok(())
}
fn verify_digest(expected: &str) -> io::Result<()> {
    let table = nft(&["-j", "list", "table", "inet", "xkeenwrt"], None)?;
    if !table.success {
        return Err(fail("cannot verify nft table semantics"));
    }
    let actual = xkeenwrt_recovery::nft_semantic_digest(&table.bytes)?;
    if actual != expected {
        return Err(fail("nft semantic digest mismatch"));
    }
    Ok(())
}
fn verify_semantics(m: &Manifest) -> io::Result<()> {
    verify_digest(&m.nft_semantic_sha256)
}
fn checked_ip(args: Vec<String>) -> io::Result<()> {
    if ip(&args)?.success {
        Ok(())
    } else {
        Err(fail("ip operation failed"))
    }
}
fn remove_nft(current: &Manifest, previous: Option<&Manifest>) -> io::Result<()> {
    let Some((owner, bytes)) = table_snapshot()? else {
        return Ok(());
    };
    let expected = format!("xkeenwrt:{}:{}", current.owner_id, current.generation);
    if owner != expected {
        if let Some(p) = previous
            && owner == format!("xkeenwrt:{}:{}", p.owner_id, p.generation)
        {
            prove_owned_table(&bytes, p, &[p])?;
            let result = nft(&["delete", "table", "inet", "xkeenwrt"], None)?;
            if !result.success {
                return Err(fail("cannot remove previous nft table"));
            }
            return Ok(());
        }
        return Err(fail("nft table is not owned by transaction"));
    }
    let mut failblock_sources = vec![current];
    if let Some(previous) = previous {
        failblock_sources.push(previous);
    }
    prove_owned_table(&bytes, current, &failblock_sources)?;
    let result = nft(&["delete", "table", "inet", "xkeenwrt"], None)?;
    if !result.success {
        return Err(fail("cannot remove own nft table"));
    }
    Ok(())
}
fn args(m: &Manifest, action: &str, rule: bool) -> Vec<String> {
    if rule {
        vec![
            "-4".into(),
            "rule".into(),
            action.into(),
            "priority".into(),
            m.priority.to_string(),
            "fwmark".into(),
            format!("{:#x}/{:#x}", m.mark, m.mask),
            "table".into(),
            m.route_table.to_string(),
        ]
    } else {
        vec![
            "-4".into(),
            "route".into(),
            action.into(),
            "local".into(),
            "0.0.0.0/0".into(),
            "dev".into(),
            "lo".into(),
            "table".into(),
            m.route_table.to_string(),
        ]
    }
}
/// Do not use until idempotence and inventory collision handling have passed VM testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    Previous,
    Direct,
    /// A snapshot the rollback needed was missing or corrupt. The core is
    /// stopped, both generations' nft and routes are removed: terminal Direct.
    SnapshotMissing {
        snapshot_id: String,
    },
}
/// Restore the safe baseline for a terminal Direct; an unusable baseline
/// snapshot leaves the core stopped instead of aborting recovery.
fn direct_baseline(j: &Journal) -> io::Result<RestoreOutcome> {
    Ok(match crate::core::restore_or_stop(&j.baseline_core)? {
        None => RestoreOutcome::Direct,
        Some(snapshot_id) => RestoreOutcome::SnapshotMissing { snapshot_id },
    })
}
pub fn restore(j: &Journal) -> io::Result<RestoreOutcome> {
    if j.cancel_capture {
        remove_for_uninstall(j)?;
        let outcome = direct_baseline(j)?;
        verify_removed(j)?;
        return Ok(outcome);
    }
    let block = j.previous_good.as_ref().is_some_and(|p| {
        p.failure_policy == xkeenwrt_recovery::FailurePolicy::BlockSelectedOnFailure
    });
    if block {
        let previous = j
            .previous_good
            .as_ref()
            .ok_or_else(|| fail("missing previous policy"))?;
        let snapshot = table_snapshot()?;
        if let Some((ref owner, ref bytes)) = snapshot {
            let current = format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation);
            let prior = format!("xkeenwrt:{}:{}", previous.owner_id, previous.generation);
            if owner != &current && owner != &prior {
                return Err(fail("foreign nft table"));
            }
            if owner == &prior {
                prove_owned_table(bytes, previous, &[previous])?;
            } else {
                prove_owned_table(bytes, &j.current, &[previous, &j.current])?;
            }
        }
        let batch = previous.failblock_json_batch(&j.current, snapshot.is_some())?;
        if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success {
            return Err(fail("failblock check failed"));
        }
        if !nft(&["-j", "-f", "-"], Some(&batch))?.success {
            return Err(fail("failblock install failed"));
        }
        verify_digest(
            j.failblock_semantic_sha256
                .as_deref()
                .ok_or_else(|| fail("missing failblock digest"))?,
        )?;
    } else {
        remove_nft(&j.current, j.previous_good.as_ref())?;
    }
    reconcile_ip(&j.current, false, true)?;
    reconcile_ip(&j.current, false, false)?;
    if let Some(previous) = &j.previous_good {
        reconcile_ip(previous, false, true)?;
        reconcile_ip(previous, false, false)?;
    }
    if let Err(error) = crate::core::restore(&j.previous_core) {
        let Some(missing) = crate::core::snapshot_unavailable(&error) else {
            return Err(error);
        };
        // Never loop on a snapshot that cannot exist again (decision 023):
        // stop the core, remove both generations' capture, end Direct.
        let snapshot_id = missing.snapshot_id.clone();
        crate::core::stop_without_snapshot()?;
        remove_for_uninstall(j)?;
        verify_removed(j)?;
        return Ok(RestoreOutcome::SnapshotMissing { snapshot_id });
    }
    if let Some(previous) = &j.previous_good {
        // A version reply is insufficient to restore interception. Confirm the
        // exact pinned instance, listeners, grant and active home first.
        if !matches!(
            crate::health::observe(&j.previous_core),
            Ok(xkeenwrt_recovery::active::CoreHealth::Healthy)
        ) {
            return Err(fail("previous core identity or health unavailable"));
        }
        let pinned = j
            .previous_network_evidence
            .as_ref()
            .ok_or_else(|| fail("missing previous topology evidence"))?;
        let nft_digest = if block {
            j.failblock_semantic_sha256.as_deref()
        } else {
            None
        };
        if crate::active_inventory::verify_failure_topology(
            previous,
            pinned,
            nft_digest,
            (false, false),
        )
        .is_err()
        {
            // A neighbour changed during the pending transaction. Preserve its
            // new lifecycle and return direct LAN plus the previous explicit
            // input; never reinstall capture from a stale fingerprint.
            // Remove a prior failblock as well: the terminal fallback is direct.
            remove_nft(&j.current, j.previous_good.as_ref())?;
            verify_removed(j)?;
            let outcome = direct_baseline(j)?;
            verify_removed(j)?;
            return Ok(outcome);
        }
        let flow_scope = match prepare_flow_transition(previous) {
            Ok(scope) => scope,
            Err(_) => {
                remove_nft(&j.current, j.previous_good.as_ref())?;
                let outcome = direct_baseline(j)?;
                verify_removed(j)?;
                return Ok(outcome);
            }
        };
        reconcile_ip(previous, true, false)?;
        reconcile_ip(previous, true, true)?;
        if block {
            let batch = previous.nft_json_batch(true)?;
            if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success {
                return Err(fail("previous nft check failed"));
            }
            if !nft(&["-j", "-f", "-"], Some(&batch))?.success {
                return Err(fail("previous nft restore failed"));
            }
        } else if table_owner()?.is_none() {
            let batch = previous.nft_json_batch(false)?;
            if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success {
                return Err(fail("previous nft check failed"));
            }
            if !nft(&["-j", "-f", "-"], Some(&batch))?.success {
                return Err(fail("previous nft restore failed"));
            }
        }
        if finish_flow_transition(previous, flow_scope.as_ref()).is_err() {
            remove_nft(&j.current, j.previous_good.as_ref())?;
            reconcile_ip(previous, false, true)?;
            reconcile_ip(previous, false, false)?;
            let outcome = direct_baseline(j)?;
            verify_removed(j)?;
            return Ok(outcome);
        }
        verify_semantics(previous)?;
    }
    Ok(RestoreOutcome::Previous)
}
/// Verify the fixed platform commands and ownership before acknowledging a transaction.
pub fn preflight(j: &Journal) -> io::Result<()> {
    let owner = table_owner()?;
    if let Some(ref owner) = owner {
        let current = format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation);
        let previous = j
            .previous_good
            .as_ref()
            .map(|p| format!("xkeenwrt:{}:{}", p.owner_id, p.generation));
        if owner != &current && previous.as_deref() != Some(owner.as_str()) {
            return Err(fail("foreign nft table"));
        }
        if owner == &current {
            verify_semantics(&j.current)?;
        }
        if previous.as_deref() == Some(owner.as_str()) {
            verify_semantics(
                j.previous_good
                    .as_ref()
                    .ok_or_else(|| fail("missing previous manifest"))?,
            )?;
        }
    }
    let _ = exists(&j.current, true)?;
    let _ = exists(&j.current, false)?;
    if let Some(previous) = &j.previous_good {
        let batch = previous.nft_json_batch(owner.is_some())?;
        if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success {
            return Err(fail("previous nft check failed"));
        }
    }
    Ok(())
}

/// Removal path: delete only journal-proven objects; never start a core.
pub fn remove_for_uninstall(j: &Journal) -> io::Result<()> {
    if let Some((owner, bytes)) = table_snapshot()? {
        let current = format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation);
        let previous = j
            .previous_good
            .as_ref()
            .map(|p| format!("xkeenwrt:{}:{}", p.owner_id, p.generation));
        if owner == current {
            let mut failblock_sources = vec![&j.current];
            if let Some(previous) = &j.previous_good {
                failblock_sources.push(previous);
            }
            prove_owned_table(&bytes, &j.current, &failblock_sources)?;
        } else if previous.as_deref() == Some(owner.as_str()) {
            let previous_manifest = j
                .previous_good
                .as_ref()
                .ok_or_else(|| fail("missing previous manifest"))?;
            prove_owned_table(&bytes, previous_manifest, &[previous_manifest])?;
        } else {
            return Err(fail("foreign nft table"));
        }
        if !nft(&["delete", "table", "inet", "xkeenwrt"], None)?.success {
            return Err(fail("cannot delete own nft table"));
        }
        if table_owner()?.is_some() {
            return Err(fail("nft table remains"));
        }
    }
    reconcile_ip(&j.current, false, true)?;
    reconcile_ip(&j.current, false, false)?;
    if let Some(previous) = &j.previous_good {
        reconcile_ip(previous, false, true)?;
        reconcile_ip(previous, false, false)?;
    }
    Ok(())
}

pub fn no_project_table() -> io::Result<bool> {
    Ok(table_owner()?.is_none())
}

/// Read-only proof for migration of an already completed lifecycle. Unknown
/// occupants at either generation's reservations are errors, not absence.
pub fn verify_removed(j: &Journal) -> io::Result<()> {
    if table_owner()?.is_some() {
        return Err(fail("project nft table still present"));
    }
    for manifest in std::iter::once(&j.current).chain(j.previous_good.iter()) {
        if exists(manifest, true)? || exists(manifest, false)? {
            return Err(fail("project routing still present"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActiveNftState {
    Missing,
    Current,
    Failblock,
}
pub(crate) fn active_nft_state(j: &Journal) -> io::Result<ActiveNftState> {
    let Some(owner) = table_owner()? else {
        return Ok(ActiveNftState::Missing);
    };
    if owner != format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation) {
        return Err(fail("foreign active nft table"));
    }
    if verify_semantics(&j.current).is_ok() {
        return Ok(ActiveNftState::Current);
    }
    if let Some(expected) = &j.active_failblock_semantic_sha256
        && verify_digest(expected).is_ok()
    {
        return Ok(ActiveNftState::Failblock);
    }
    Err(fail("unknown active nft semantics"))
}
pub(crate) fn active_remove_nft(j: &Journal) -> io::Result<()> {
    let Some((owner, bytes)) = table_snapshot()? else {
        return Ok(());
    };
    if owner != format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation) {
        return Err(fail("foreign active nft table"));
    }
    let mut failblock_sources = vec![&j.current];
    if let Some(previous) = &j.previous_good {
        failblock_sources.push(previous);
    }
    prove_owned_table(&bytes, &j.current, &failblock_sources)?;
    if !nft(&["delete", "table", "inet", "xkeenwrt"], None)?.success {
        return Err(fail("cannot remove active nft table"));
    }
    if active_nft_state(j)? != ActiveNftState::Missing {
        return Err(fail("active nft table remains"));
    }
    Ok(())
}
pub(crate) fn active_block_nft(j: &Journal) -> io::Result<()> {
    let Some((owner, bytes)) = table_snapshot()? else {
        return Err(fail("missing active nft table"));
    };
    if owner != format!("xkeenwrt:{}:{}", j.current.owner_id, j.current.generation) {
        return Err(fail("foreign active nft table"));
    }
    if let Ok(digest) = xkeenwrt_recovery::nft_semantic_digest(&bytes) {
        if j.active_failblock_semantic_sha256.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        if digest != j.current.nft_semantic_sha256 {
            let mut failblock_sources = vec![&j.current];
            if let Some(previous) = &j.previous_good {
                failblock_sources.push(previous);
            }
            prove_owned_table(&bytes, &j.current, &failblock_sources)?;
        }
    } else {
        return Err(fail("cannot inspect active nft semantics"));
    }
    let expected = j
        .active_failblock_semantic_sha256
        .as_deref()
        .ok_or_else(|| fail("missing active failblock digest"))?;
    let batch = j.current.failblock_json_batch(&j.current, true)?;
    if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success
        || !nft(&["-j", "-f", "-"], Some(&batch))?.success
    {
        return Err(fail("active failblock install failed"));
    }
    verify_digest(expected)
}
pub(crate) fn active_routing_state(j: &Journal) -> io::Result<(bool, bool)> {
    Ok((exists(&j.current, false)?, exists(&j.current, true)?))
}
pub(crate) fn active_remove_routes(j: &Journal) -> io::Result<()> {
    reconcile_ip(&j.current, false, true)?;
    reconcile_ip(&j.current, false, false)
}
pub(crate) fn active_restore_route(j: &Journal) -> io::Result<()> {
    reconcile_ip(&j.current, true, false)
}
pub(crate) fn active_restore_rule(j: &Journal) -> io::Result<()> {
    reconcile_ip(&j.current, true, true)
}
/// Fresh software transition for every path which republishes interception.
/// Hardware changes are refused before publication; no timer guesses teardown.
fn prepare_flow_transition(
    m: &Manifest,
) -> io::Result<Option<xkeenwrt_recovery::flow_offload::Scope>> {
    let raw = crate::active_inventory::capture()?;
    xkeenwrt_recovery::flow_offload::verify_for_lan(
        &raw.nft,
        &raw.flowtables,
        &raw.links,
        &m.lan_interface,
    )?;
    if !xkeenwrt_recovery::flow_offload::transition_required(
        &raw.flowtables,
        &raw.links,
        &m.lan_interface,
    )? {
        return Ok(None);
    }
    xkeenwrt_recovery::flow_offload::Scope::prove(
        m,
        &raw.addresses,
        &raw.links,
        &raw.nft,
        &raw.rules4,
        &raw.routes6,
    )
    .map(Some)
}
fn finish_flow_transition(
    m: &Manifest,
    scope: Option<&xkeenwrt_recovery::flow_offload::Scope>,
) -> io::Result<()> {
    let raw = crate::active_inventory::capture()?;
    xkeenwrt_recovery::flow_offload::verify_for_lan(
        &raw.nft,
        &raw.flowtables,
        &raw.links,
        &m.lan_interface,
    )?;
    let new_scope = if xkeenwrt_recovery::flow_offload::transition_required(
        &raw.flowtables,
        &raw.links,
        &m.lan_interface,
    )? {
        Some(xkeenwrt_recovery::flow_offload::Scope::prove(
            m,
            &raw.addresses,
            &raw.links,
            &raw.nft,
            &raw.rules4,
            &raw.routes6,
        )?)
    } else {
        None
    };
    if let Some(scope) = new_scope.as_ref().or(scope) {
        xkeenwrt_recovery::flow_offload::invalidate(
            scope,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )?;
        let after = crate::active_inventory::capture()?;
        xkeenwrt_recovery::flow_offload::verify_for_lan(
            &after.nft,
            &after.flowtables,
            &after.links,
            &m.lan_interface,
        )?;
        xkeenwrt_recovery::flow_offload::Scope::prove(
            m,
            &after.addresses,
            &after.links,
            &after.nft,
            &after.rules4,
            &after.routes6,
        )?;
    }
    Ok(())
}
pub(crate) fn active_restore_nft(j: &Journal) -> io::Result<()> {
    let state = active_nft_state(j)?;
    if state == ActiveNftState::Current {
        return Ok(());
    }
    let flow_scope = prepare_flow_transition(&j.current)?;
    let batch = j
        .current
        .nft_json_batch(state == ActiveNftState::Failblock)?;
    if !nft(&["-j", "-c", "-f", "-"], Some(&batch))?.success
        || !nft(&["-j", "-f", "-"], Some(&batch))?.success
    {
        return Err(fail("active nft restore failed"));
    }
    if let Err(error) = finish_flow_transition(&j.current, flow_scope.as_ref()) {
        active_remove_nft(j)?;
        return Err(error);
    }
    verify_semantics(&j.current)
}
pub(crate) fn active_verify(j: &Journal, state: ActiveNftState, routes: bool) -> io::Result<()> {
    if active_nft_state(j)? != state
        || exists(&j.current, true)? != routes
        || exists(&j.current, false)? != routes
    {
        return Err(fail("active network verification failed"));
    }
    Ok(())
}
