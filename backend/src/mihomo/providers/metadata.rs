//! Numeric subscription metadata travels with the immutable provider asset.
//! A YAML comment keeps it outside the core's node/config schema and asset paths.
use serde::{Deserialize, Serialize};
const PREFIX: &str = "# xkeenwrt-subscription-info: ";
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct SubscriptionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<u64>,
}
impl SubscriptionInfo {
    fn valid(&self) -> bool {
        let values = [self.upload, self.download, self.total, self.expire];
        values.iter().any(Option::is_some) && values.iter().flatten().all(|n| *n <= MAX_INTEGER)
    }
}
pub fn parse_header(value: &str) -> Option<SubscriptionInfo> {
    if value.len() > 512 {
        return None;
    }
    let mut info = SubscriptionInfo::default();
    for part in value.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, text) = part.split_once('=')?;
        let field = match key.trim().to_ascii_lowercase().as_str() {
            "upload" => &mut info.upload,
            "download" => &mut info.download,
            "total" => &mut info.total,
            "expire" => &mut info.expire,
            _ => return None,
        };
        if field.is_some() || text.trim().is_empty() || !text.trim().bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *field = Some(text.trim().parse().ok()?);
    }
    info.valid().then_some(info)
}
pub fn read(payload: &[u8]) -> Option<SubscriptionInfo> {
    let first = payload.split(|b| *b == b'\n').next()?;
    if first.len() > 512 {
        return None;
    }
    let info: SubscriptionInfo = serde_json::from_str(std::str::from_utf8(first).ok()?.strip_prefix(PREFIX)?).ok()?;
    info.valid().then_some(info)
}
pub fn attach(payload: Vec<u8>, info: Option<SubscriptionInfo>) -> Result<Vec<u8>, super::ProviderError> {
    let Some(info) = info.filter(SubscriptionInfo::valid) else {
        return Ok(payload);
    };
    let mut bytes = format!(
        "{PREFIX}{}\n",
        serde_json::to_string(&info).map_err(|_| super::ProviderError::InvalidProfile)?
    )
    .into_bytes();
    if bytes.len() + payload.len() > crate::mihomo::subscription::MAX_BYTES {
        return Err(super::ProviderError::TooLarge);
    }
    bytes.extend(payload);
    Ok(bytes)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedProvider {
    pub id: String,
    pub name: String,
    pub subscription_info: Option<SubscriptionInfo>,
}
pub fn applied(config: &str, assets: &[profile_policy::Asset]) -> Vec<AppliedProvider> {
    super::list_providers(config)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| {
            let index = p.id.strip_prefix("proxy-")?;
            let path = format!("providers/proxies/{index}.yaml");
            Some(AppliedProvider {
                id: p.id,
                name: p.name,
                subscription_info: assets.iter().find(|a| a.path == path).and_then(|a| read(&a.content)),
            })
        })
        .collect()
}
