//! A shared display observation. It never grants permission to mutate or Confirm.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(super) struct StatusSnapshot {
    epoch: AtomicU64,
    value: Mutex<Option<Observed>>,
    refresh: tokio::sync::Mutex<()>,
}
struct Observed {
    epoch: u64,
    at: Instant,
    value: serde_json::Value,
}
pub(super) struct Mutation(Arc<StatusSnapshot>);
impl Drop for Mutation {
    fn drop(&mut self) {
        self.0.epoch.fetch_add(1, Ordering::AcqRel);
    }
}
impl StatusSnapshot {
    pub(super) fn mutation(self: &Arc<Self>) -> Mutation {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Mutation(self.clone())
    }
    fn cached(&self, epoch: u64, stale: bool) -> Option<serde_json::Value> {
        let state = self.value.lock().ok()?;
        let old = state.as_ref().filter(|old| old.epoch == epoch)?;
        if !stale && old.at.elapsed() >= Duration::from_secs(1) {
            return None;
        }
        let mut value = old.value.clone();
        value["stale"] = serde_json::json!(stale);
        value["observed_age_ms"] = serde_json::json!(old.at.elapsed().as_millis().min(u64::MAX as u128) as u64);
        Some(value)
    }
    pub(super) async fn read(&self, app: &App, fresh: bool) -> Result<serde_json::Value, String> {
        let epoch = self.epoch.load(Ordering::Acquire);
        if !fresh && let Some(value) = self.cached(epoch, false) {
            return Ok(value);
        }
        let _refresh = self.refresh.lock().await;
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err("BUSY".into());
        }
        if !fresh && let Some(value) = self.cached(epoch, false) {
            return Ok(value);
        }
        let result = match app.runtime_capacity.clone().try_acquire_owned() {
            Ok(permit) => tokio::task::spawn_blocking(move || {
                let _permit = permit;
                crate::runtime::ipc::RuntimeClient::status()
            })
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(|| "RUNTIME_UNAVAILABLE".to_owned()),
            Err(_) => Err("BUSY".into()),
        };
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err("BUSY".into());
        }
        let result = result.and_then(|reply| {
            if reply.code != "OK" { return Err(reply.code) }
            if reply.running.is_none() || reply.network.as_ref().and_then(|n| n["state"].as_str()) == Some("unknown") {
                return Err("RUNTIME_UNAVAILABLE".into());
            }
            Ok(serde_json::json!({
                "success":true,"currentCore":"mihomo","running":reply.running,
                "network":reply.network,"inputs":reply.inputs,"activeProfileId":reply.active_profile_id,
                "activeProfileRevision":reply.active_profile_revision,"providerMetadata":reply.provider_metadata.unwrap_or_default(),
                "resumeRequestId":reply.resume_request_id,
                "capabilities":reply.capabilities.unwrap_or_default().iter().map(|c|c.as_str()).collect::<Vec<_>>(),
                "stale":false,"observed_age_ms":0,
            }))
        });
        match result {
            Ok(value) => {
                if let Ok(mut stored) = self.value.lock() {
                    // The epoch is checked while publishing as well as after IPC.
                    if self.epoch.load(Ordering::Acquire) != epoch {
                        return Err("BUSY".into());
                    }
                    *stored = Some(Observed {
                        epoch,
                        at: Instant::now(),
                        value: value.clone(),
                    });
                }
                Ok(value)
            }
            Err(code) if !fresh && matches!(code.as_str(), "BUSY" | "RUNTIME_UNAVAILABLE") => {
                self.cached(epoch, true).ok_or(code)
            }
            Err(code) => Err(code),
        }
    }
}
