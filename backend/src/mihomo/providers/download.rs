use super::{
    ProviderError,
    diagnostic::{Diagnostic, Reason},
    is_public_address,
};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION},
};
use serde_json::Value;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
const LIMIT: usize = 2 * 1024 * 1024;
fn err(reason: Reason) -> ProviderError {
    ProviderError::failure(reason)
}
fn checked(url: Url) -> Result<Url, ProviderError> {
    if url.as_str().len() > 4096
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !matches!(
            (url.scheme(), url.port_or_known_default()),
            ("http", Some(80)) | ("https", Some(443))
        )
    {
        return Err(err(Reason::InvalidUrl));
    }
    Ok(url)
}
fn headers(provider: &Value, global_ua: Option<&str>) -> Result<HeaderMap, ProviderError> {
    let mut headers = HeaderMap::new();
    if let Some(value) = provider.get("header") {
        for (key, value) in value.as_object().ok_or(ProviderError::InvalidProfile)? {
            if ![
                "user-agent",
                "x-hwid",
                "x-device-id",
                "x-device-model",
                "x-platform",
                "x-platform-version",
            ]
            .contains(&key.to_ascii_lowercase().as_str())
            {
                return Err(ProviderError::Unsupported);
            }
            let value = value
                .as_str()
                .or_else(|| value.as_array().filter(|a| a.len() == 1).and_then(|a| a[0].as_str()))
                .ok_or(ProviderError::InvalidProfile)?;
            if value.len() > 512 || value.chars().any(char::is_control) {
                return Err(ProviderError::InvalidProfile);
            }
            headers.insert(
                HeaderName::from_bytes(key.as_bytes()).map_err(|_| ProviderError::InvalidProfile)?,
                HeaderValue::from_str(value).map_err(|_| ProviderError::InvalidProfile)?,
            );
        }
    }
    if let Some(ua) = global_ua.filter(|_| !headers.contains_key("user-agent")) {
        if ua.len() > 512 || ua.chars().any(char::is_control) {
            return Err(ProviderError::InvalidProfile);
        }
        headers.insert(
            "user-agent",
            HeaderValue::from_str(ua).map_err(|_| ProviderError::InvalidProfile)?,
        );
    }
    Ok(headers)
}
async fn addresses(url: &Url) -> Result<Vec<SocketAddr>, ProviderError> {
    let host = url.host_str().ok_or_else(|| err(Reason::InvalidUrl))?;
    let port = url.port_or_known_default().ok_or_else(|| err(Reason::InvalidUrl))?;
    let literal = host.trim_matches(['[', ']']);
    let all = if let Ok(ip) = literal.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        let addresses = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| err(Reason::Timeout))?
            .map_err(|_| err(Reason::Dns))?;
        // Inspect all returned addresses; reject an excessive set instead of truncating it.
        let mut all = Vec::new();
        for a in addresses {
            if !is_public_address(a.ip()) {
                return Err(err(Reason::AddressForbidden));
            }
            if !all.contains(&a) {
                all.push(a);
            }
            if all.len() > 32 {
                return Err(err(Reason::Dns));
            }
        }
        all
    };
    if all.is_empty() {
        return Err(err(Reason::Dns));
    }
    if all.iter().any(|a| !is_public_address(a.ip())) {
        return Err(err(Reason::AddressForbidden));
    }
    Ok(all)
}
fn redirect(current: &Url, location: &str, seen: &HashSet<String>, hops: usize) -> Result<Url, ProviderError> {
    if hops >= 5 {
        return Err(err(Reason::RedirectLimit));
    }
    if location.len() > 4096 {
        return Err(err(Reason::RedirectInvalid));
    }
    let next = checked(current.join(location).map_err(|_| err(Reason::RedirectInvalid))?)?;
    // Redirect support is deliberately HTTPS-only, including the starting request.
    if current.scheme() != "https" || next.scheme() != "https" {
        return Err(err(Reason::RedirectForbidden));
    }
    if seen.contains(next.as_str()) {
        return Err(err(Reason::RedirectLoop));
    }
    Ok(next)
}
#[derive(Debug)]
pub struct Download {
    pub bytes: Vec<u8>,
    pub info: Option<super::metadata::SubscriptionInfo>,
}
pub async fn fetch(provider: &Value, global_ua: Option<&str>) -> Result<Download, ProviderError> {
    tokio::time::timeout(Duration::from_secs(20), fetch_inner(provider, global_ua))
        .await
        .map_err(|_| err(Reason::Timeout))?
}
async fn fetch_inner(provider: &Value, global_ua: Option<&str>) -> Result<Download, ProviderError> {
    let raw = provider
        .get("url")
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidProfile)?;
    let mut url = checked(Url::parse(raw).map_err(|_| err(Reason::InvalidUrl))?)?;
    let mut headers = headers(provider, global_ua)?;
    let mut seen = HashSet::new();
    for hops in 0..=5 {
        seen.insert(url.to_string());
        let addresses = addresses(&url).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .resolve_to_addrs(url.host_str().ok_or_else(|| err(Reason::InvalidUrl))?, &addresses)
            .build()
            .map_err(|_| err(Reason::Transport))?;
        let mut response = client
            .get(url.clone())
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| {
                err(if e.is_timeout() {
                    Reason::Timeout
                } else {
                    Reason::Transport
                })
            })?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| err(Reason::RedirectInvalid))?;
            let next = redirect(&url, location, &seen, hops)?;
            if next.origin() != url.origin() {
                headers.clear();
            } // Never restore credentials after leaving the origin.
            url = next;
            continue;
        }
        if !response.status().is_success() {
            let mut d = Diagnostic::new(Reason::HttpStatus);
            d.http_status = Some(response.status().as_u16());
            return Err(ProviderError::Detailed(d));
        }
        if response.content_length().is_some_and(|n| n > LIMIT as u64) {
            return Err(err(Reason::TooLarge));
        }
        let info = response
            .headers()
            .get("subscription-userinfo")
            .and_then(|v| v.to_str().ok())
            .and_then(super::metadata::parse_header);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            err(if e.is_timeout() {
                Reason::Timeout
            } else {
                Reason::Transport
            })
        })? {
            if bytes.len() + chunk.len() > LIMIT {
                return Err(err(Reason::TooLarge));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(Download { bytes, info });
    }
    Err(err(Reason::RedirectLimit))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirect_policy() {
        let u = Url::parse("https://github.com/a").unwrap();
        let seen = HashSet::from([u.to_string()]);
        assert!(redirect(&u, "https://release-assets.githubusercontent.com/file", &seen, 0).is_ok());
        for (location, hops, reason) in [
            ("http://example.org", 0, Reason::RedirectForbidden),
            ("/a", 0, Reason::RedirectLoop),
            ("/b", 5, Reason::RedirectLimit),
            ("https://user:secret@example.org", 0, Reason::InvalidUrl),
        ] {
            assert_eq!(
                redirect(&u, location, &seen, hops).unwrap_err().diagnostic().reason,
                reason
            );
        }
    }
    #[tokio::test]
    async fn private_hops_fail_before_connect() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[2002:7f00:1::]",
        ] {
            assert_eq!(
                fetch(&serde_json::json!({"url":format!("https://{host}/secret")}), None)
                    .await
                    .unwrap_err()
                    .diagnostic()
                    .reason,
                Reason::AddressForbidden
            );
        }
    }
}
