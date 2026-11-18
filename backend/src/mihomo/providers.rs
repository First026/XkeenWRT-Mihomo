//! Provider downloads are pinned to inspected public addresses and never write caller paths.
use profile_policy::{Asset, PolicyError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

pub mod diagnostic;
mod download;
pub mod metadata;
use diagnostic::{Diagnostic, Reason};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
}
#[derive(Debug)]
pub struct PreparedAssets {
    pub config: String,
    pub files: Vec<Asset>,
    pub providers: Vec<ProviderSummary>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    Detailed(Diagnostic),
    InvalidProfile,
    Unsupported,
    Network,
    TooLarge,
}
impl From<PolicyError> for ProviderError {
    fn from(_: PolicyError) -> Self {
        Self::InvalidProfile
    }
}

pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                || v == Ipv4Addr::BROADCAST)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000 && s[0] != 0x2002 && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
        }
    }
}

/// List opaque provider IDs from a revision-checked profile without network access.
pub fn list_providers(config: &str) -> Result<Vec<ProviderSummary>, ProviderError> {
    let doc = profile_policy::parse_document(config)?;
    let root = doc.as_object().ok_or(ProviderError::InvalidProfile)?;
    let mut result = Vec::new();
    for (section, prefix) in [("proxy-providers", "proxy"), ("rule-providers", "rule")] {
        if let Some(value) = root.get(section) {
            let map = value.as_object().ok_or(ProviderError::InvalidProfile)?;
            if map.len() + result.len() > profile_policy::MAX_PROVIDER_FILES {
                return Err(ProviderError::TooLarge);
            }
            for (index, (name, provider)) in map.iter().enumerate() {
                if name.is_empty()
                    || name.len() > 256
                    || name.chars().any(char::is_control)
                    || !matches!(
                        provider.get("type").and_then(Value::as_str),
                        Some("http" | "file" | "inline")
                    )
                {
                    return Err(ProviderError::Unsupported);
                }
                result.push(ProviderSummary {
                    id: format!("{prefix}-{index}"),
                    name: name.clone(),
                });
            }
        }
    }
    Ok(result)
}

/// Fetch all managed HTTP proxy providers from immutable, already revision-checked config.
/// The returned files are in-memory; only runtime may persist them under its owned home.
pub async fn prepare_assets(config: &str) -> Result<PreparedAssets, ProviderError> {
    tokio::time::timeout(Duration::from_secs(45), prepare(config, None, &[], None))
        .await
        .map_err(|_| ProviderError::Network)?
}
/// Refresh exactly one opaque provider ID, reusing verified files from the same profile revision.
pub async fn refresh_assets(config: &str, provider_id: &str, prior: &[Asset]) -> Result<PreparedAssets, ProviderError> {
    tokio::time::timeout(Duration::from_secs(45), prepare(config, Some(provider_id), prior, None))
        .await
        .map_err(|_| ProviderError::Network)?
}
pub async fn prepare_profile_assets(config: &str, profile_id: &str) -> Result<PreparedAssets, ProviderError> {
    tokio::time::timeout(Duration::from_secs(45), prepare(config, None, &[], Some(profile_id)))
        .await
        .map_err(|_| ProviderError::Network)?
}
pub async fn refresh_profile_assets(
    config: &str, profile_id: &str, provider_id: &str, prior: &[Asset],
) -> Result<PreparedAssets, ProviderError> {
    tokio::time::timeout(
        Duration::from_secs(45),
        prepare(config, Some(provider_id), prior, Some(profile_id)),
    )
    .await
    .map_err(|_| ProviderError::Network)?
}
async fn prepare(
    config: &str, selected: Option<&str>, prior: &[Asset], profile_id: Option<&str>,
) -> Result<PreparedAssets, ProviderError> {
    let references = profile_policy::leaf_rule_provider_names(config)?;
    let mut matched = false;
    let mut document = profile_policy::parse_document(config)?;
    let root = document.as_object_mut().ok_or(ProviderError::InvalidProfile)?;
    let global_ua = root
        .get("global-ua")
        .map(|v| v.as_str().ok_or(ProviderError::InvalidProfile))
        .transpose()?
        .map(str::to_owned);
    let mut files = Vec::new();
    let mut summaries = Vec::new();
    for (section, directory, prefix) in [("proxy-providers", "proxies", "proxy"), ("rule-providers", "rules", "rule")] {
        if let Some(providers) = root.get_mut(section) {
            let map = providers.as_object_mut().ok_or(ProviderError::InvalidProfile)?;
            if map.len() > profile_policy::MAX_PROVIDER_FILES {
                return Err(ProviderError::TooLarge);
            }
            for (index, (name, provider)) in map.iter_mut().enumerate() {
                let p = provider.as_object().ok_or(ProviderError::InvalidProfile)?;
                let allowed: &[&str] = if prefix == "proxy" {
                    &[
                        "type",
                        "url",
                        "path",
                        "interval",
                        "header",
                        "health-check",
                        "filter",
                        "exclude-filter",
                        "exclude-type",
                        "override",
                        "size-limit",
                        "payload",
                    ]
                } else {
                    &["type", "url", "path", "interval", "header", "behavior", "format", "payload"]
                };
                if !matches!(p.get("type").and_then(Value::as_str), Some("http" | "file" | "inline"))
                    || !p.keys().all(|k| allowed.contains(&k.as_str()))
                {
                    return Err(ProviderError::Unsupported);
                }
                let behavior = if prefix == "rule" {
                    Some(
                        p.get("behavior")
                            .and_then(Value::as_str)
                            .ok_or(ProviderError::InvalidProfile)?
                            .to_string(),
                    )
                } else {
                    None
                };
                let source_format = p.get("format").and_then(Value::as_str).unwrap_or("yaml").to_owned();
                if prefix == "rule" && !matches!(source_format.as_str(), "yaml" | "text" | "mrs") {
                    return Err(ProviderError::Unsupported);
                }
                let path = format!("providers/{directory}/{index}.yaml");
                let id = format!("{prefix}-{index}");
                let refreshed = selected.is_none() || selected == Some(id.as_str());
                let mut subscription_info = None;
                let mut payload = if refreshed {
                    matched = true;
                    if p.get("type").and_then(Value::as_str) == Some("inline") {
                        if source_format != "yaml" {
                            return Err(ProviderError::Unsupported);
                        }
                        let entries = p
                            .get("payload")
                            .filter(|v| v.is_array())
                            .ok_or(ProviderError::InvalidProfile)?;
                        let key = if prefix == "proxy" { "proxies" } else { "payload" };
                        serde_json::to_vec(&serde_json::json!({(key):entries}))
                            .map_err(|_| ProviderError::InvalidProfile)?
                    } else if p.get("type").and_then(Value::as_str) == Some("file") {
                        let resource = p
                            .get("path")
                            .and_then(Value::as_str)
                            .and_then(|p| p.strip_prefix("resources/"))
                            .ok_or(ProviderError::Unsupported)?;
                        crate::resources::read(profile_id.ok_or(ProviderError::Unsupported)?, resource)
                            .map_err(|_| ProviderError::Unsupported)?
                    } else {
                        let download = download::fetch(provider, global_ua.as_deref())
                            .await
                            .map_err(|e| e.at(&id))?;
                        subscription_info = download.info;
                        download.bytes
                    }
                } else {
                    prior
                        .iter()
                        .find(|a| a.path == path)
                        .ok_or(ProviderError::Unsupported)?
                        .content
                        .clone()
                };
                let compact_mrs = prefix == "rule"
                    && ((refreshed && source_format == "mrs")
                        || (!refreshed && payload.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])));
                if prefix == "proxy" {
                    payload = super::subscription::normalize(&payload).map_err(|e| ProviderError::from(e).at(&id))?;
                    if subscription_info.is_some() {
                        payload = metadata::attach(payload, subscription_info).map_err(|e| e.at(&id))?;
                    }
                } else if compact_mrs {
                    let metadata = profile_policy::mrs::inspect(&payload).map_err(|e| {
                        ProviderError::failure(if e == profile_policy::mrs::Error::Limit {
                            Reason::MrsLimit
                        } else {
                            Reason::RuleFormat
                        })
                        .at(&id)
                    })?;
                    if Some(metadata.behavior) != behavior.as_deref() {
                        return Err(ProviderError::failure(Reason::RuleBehavior).at(&id));
                    }
                } else {
                    if refreshed && source_format == "text" {
                        let lines: Vec<_> = std::str::from_utf8(&payload)
                            .map_err(|_| ProviderError::failure(Reason::RuleFormat).at(&id))?
                            .lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty() && !s.starts_with('#'))
                            .collect();
                        payload = serde_json::to_vec(&serde_json::json!({"payload":lines}))
                            .map_err(|_| ProviderError::failure(Reason::RuleFormat).at(&id))?;
                    }
                    if !profile_policy::rule_payload_complete_with_refs(
                        &payload,
                        behavior.as_deref().unwrap_or(""),
                        &references,
                    ) {
                        return Err(ProviderError::failure(Reason::RuleFormat).at(&id));
                    }
                    // Mihomo reads YAML rule providers one item per line. Keep MRS compact.
                    let parsed = profile_policy::parse_document(
                        std::str::from_utf8(&payload)
                            .map_err(|_| ProviderError::failure(Reason::RuleFormat).at(&id))?,
                    )?;
                    let entries = parsed
                        .get("payload")
                        .and_then(Value::as_array)
                        .ok_or(ProviderError::Unsupported)?;
                    let mut yaml = String::from("payload:\n");
                    for entry in entries {
                        yaml.push_str("  - ");
                        yaml.push_str(
                            &serde_json::to_string(entry.as_str().ok_or(ProviderError::Unsupported)?)
                                .map_err(|_| ProviderError::Unsupported)?,
                        );
                        yaml.push('\n');
                    }
                    payload = yaml.into_bytes();
                }
                if files.iter().map(|a: &Asset| a.content.len()).sum::<usize>() + payload.len() > 8 * 1024 * 1024
                    || files.len() >= profile_policy::MAX_PROVIDER_FILES
                {
                    return Err(ProviderError::TooLarge);
                }
                let p = provider.as_object_mut().ok_or(ProviderError::InvalidProfile)?;
                p.insert("type".into(), Value::String("file".into()));
                p.insert("path".into(), Value::String(path.clone()));
                if prefix == "rule" {
                    p.insert(
                        "format".into(),
                        Value::String(if compact_mrs { "mrs" } else { "yaml" }.into()),
                    );
                }
                p.remove("url");
                p.remove("interval");
                p.remove("header");
                p.remove("payload");
                files.push(Asset { path, content: payload });
                summaries.push(ProviderSummary { id, name: name.clone() });
            }
        }
    }
    if selected.is_some() && !matched {
        return Err(ProviderError::InvalidProfile);
    }
    let config = serde_json::to_string(&document).map_err(|_| ProviderError::InvalidProfile)?;
    if !profile_policy::complete(&config, &files) {
        return Err(ProviderError::Unsupported);
    }
    Ok(PreparedAssets {
        config,
        files,
        providers: summaries,
    })
}

/// A private, newly created home containing only this immutable asset set.
pub struct StagedHome {
    path: std::path::PathBuf,
    names: Vec<String>,
}
impl StagedHome {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    /// Transfer ownership to the runtime without deleting the staged directory.
    pub fn into_path(self) -> std::path::PathBuf {
        self.path
    }
    /// Remove only files created by `stage_assets` and then empty directories.
    /// Additional files are never recursively removed.
    pub fn cleanup(self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { nix::libc::geteuid() };
        for dir in [
            &self.path,
            &self.path.join("providers"),
            &self.path.join("providers/proxies"),
            &self.path.join("providers/rules"),
        ] {
            match std::fs::symlink_metadata(dir) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() && m.uid() == uid && m.mode() & 0o077 == 0 => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unsafe staging directory",
                    ));
                }
            }
        }
        for name in &self.names {
            let p = self.path.join("providers").join(name);
            let m = std::fs::symlink_metadata(&p)?;
            if !m.is_file() || m.file_type().is_symlink() || m.uid() != uid || m.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unsafe staging file",
                ));
            }
            std::fs::remove_file(p)?;
        }
        for dir in [
            self.path.join("providers/proxies"),
            self.path.join("providers/rules"),
            self.path.join("providers"),
        ] {
            match std::fs::remove_dir(dir) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        std::fs::remove_dir(self.path)
    }
}

pub fn stage_assets(base: &std::path::Path, assets: &[Asset]) -> std::io::Result<StagedHome> {
    stage_with_refs(base, assets, &std::collections::HashSet::new())
}
/// Runtime has already checked `complete_for` against this exact config and asset set.
pub fn stage_profile_assets(base: &std::path::Path, assets: &[Asset], config: &str) -> std::io::Result<StagedHome> {
    let references = profile_policy::leaf_rule_provider_names(config)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid staged profile"))?;
    stage_with_refs(base, assets, &references)
}
fn stage_with_refs(
    base: &std::path::Path, assets: &[Asset], references: &std::collections::HashSet<String>,
) -> std::io::Result<StagedHome> {
    use std::{
        collections::HashSet,
        io::{Error, ErrorKind, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let bad = || Error::new(ErrorKind::InvalidInput, "invalid staged assets");
    if assets.len() > profile_policy::MAX_PROVIDER_FILES
        || assets
            .iter()
            .try_fold(0usize, |n, a| n.checked_add(a.content.len()))
            .is_none_or(|n| n > 8 * 1024 * 1024)
    {
        return Err(bad());
    }
    let mut paths = HashSet::new();
    let mut names = Vec::new();
    for asset in assets {
        let (dir, name) = if let Some(n) = asset.path.strip_prefix("providers/proxies/") {
            ("proxies", n)
        } else if let Some(n) = asset.path.strip_prefix("providers/rules/") {
            ("rules", n)
        } else {
            return Err(bad());
        };
        let number = name
            .strip_suffix(".yaml")
            .ok_or_else(bad)?
            .parse::<usize>()
            .map_err(|_| bad())?;
        let valid = if dir == "proxies" {
            profile_policy::proxy_payload_complete(&asset.content)
        } else {
            profile_policy::mrs::inspect(&asset.content).is_ok()
                || ["domain", "ipcidr", "classical"]
                    .iter()
                    .any(|b| profile_policy::rule_payload_complete_with_refs(&asset.content, b, references))
        };
        if number >= profile_policy::MAX_PROVIDER_FILES
            || name != format!("{number}.yaml")
            || !paths.insert(asset.path.clone())
            || !valid
        {
            return Err(bad());
        }
        names.push(format!("{dir}/{name}"));
    }
    let metadata = std::fs::symlink_metadata(base)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe staging base"));
    }
    let path = base.join(format!("candidate-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    let mut staged = StagedHome {
        path,
        names: Vec::new(),
    };
    let result = (|| {
        if !assets.is_empty() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(staged.path.join("providers"))?;
            for kind in ["proxies", "rules"] {
                if assets.iter().any(|a| a.path.starts_with(&format!("providers/{kind}/"))) {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(staged.path.join("providers").join(kind))?;
                }
            }
        }
        for (asset, name) in assets.iter().zip(names) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(staged.path.join("providers").join(&name))?;
            staged.names.push(name);
            file.write_all(&asset.content)?;
            file.sync_all()?;
        }
        if !assets.is_empty() {
            for kind in ["proxies", "rules"] {
                let dir = staged.path.join("providers").join(kind);
                if dir.exists() {
                    std::fs::File::open(dir)?.sync_all()?;
                }
            }
            std::fs::File::open(staged.path.join("providers"))?.sync_all()?;
        }
        std::fs::File::open(&staged.path)?.sync_all()?;
        std::fs::File::open(base)?.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = staged.cleanup();
        return Err(e);
    }
    Ok(staged)
}
