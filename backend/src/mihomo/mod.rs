pub mod providers;
pub mod subscription;
// Restricted relay to the locally managed Mihomo controller.
use axum::{
    body::Bytes,
    extract::ws::{Message, WebSocket},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashSet, time::Duration};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    protocol::{Message as UpstreamMessage, WebSocketConfig},
};

const LIMIT: usize = 2 * 1024 * 1024;

/// Returns a canonical relative controller URI only for explicitly supported operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectedRequest;

pub fn canonical_request(method: &Method, raw_path: &str, query: Option<&str>) -> Result<String, RejectedRequest> {
    if raw_path.len() > 2048 || raw_path.starts_with('/') || raw_path.ends_with('/') {
        return Err(RejectedRequest);
    }
    let parts: Vec<String> = raw_path
        .split('/')
        .map(|part| {
            let decoded = urlencoding::decode(part).map_err(|_| RejectedRequest)?.into_owned();
            if decoded.is_empty()
                || decoded == "."
                || decoded == ".."
                || decoded.len() > 256
                || decoded
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\' | '%' | '?' | '#'))
            {
                return Err(RejectedRequest);
            }
            Ok(decoded)
        })
        .collect::<Result<_, RejectedRequest>>()?;
    let s: Vec<&str> = parts.iter().map(String::as_str).collect();
    let allowed = matches!(
        (method, s.as_slice()),
        (
            &Method::GET,
            ["version" | "configs" | "proxies" | "group" | "rules" | "connections"]
        ) | (&Method::GET, ["proxies" | "group", _])
            | (&Method::GET, ["proxies", _, "delay"])
            | (&Method::GET, ["providers", "proxies" | "rules"])
            | (&Method::GET, ["providers", "proxies" | "rules", _])
            | (&Method::GET, ["providers", "proxies", _, _, "healthcheck"])
            | (&Method::GET, ["dns", "query"])
            | (&Method::PUT, ["proxies", _])
            | (&Method::PATCH, ["configs"])
            | (&Method::DELETE, ["proxies", _])
            | (&Method::DELETE, ["connections"] | ["connections", _])
            | (&Method::DELETE, ["connections", "smart", _])
            | (&Method::POST, ["cache", "dns" | "smart", "flush"])
    );
    if !allowed {
        return Err(RejectedRequest);
    }
    let allowed_params: &[&str] = match s.as_slice() {
        ["proxies", _, "delay"] | ["providers", "proxies", _, _, "healthcheck"] => &["url", "timeout"],
        ["dns", "query"] => &["name", "type"],
        _ => &[],
    };
    let mut output = parts
        .iter()
        .map(|s| urlencoding::encode(s).into_owned())
        .collect::<Vec<_>>()
        .join("/");
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        if q.len() > 4096 {
            return Err(RejectedRequest);
        }
        let mut seen = HashSet::new();
        let mut encoded = Vec::new();
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').ok_or(RejectedRequest)?;
            let key = urlencoding::decode(k).map_err(|_| RejectedRequest)?;
            let val = urlencoding::decode(v).map_err(|_| RejectedRequest)?;
            if !allowed_params.contains(&key.as_ref())
                || !seen.insert(key.to_string())
                || val.is_empty()
                || val.len() > 2048
                || val.chars().any(char::is_control)
            {
                return Err(RejectedRequest);
            }
            if key == "timeout" && !val.parse::<u32>().is_ok_and(|n| (1..=30000).contains(&n)) {
                return Err(RejectedRequest);
            }
            if key == "url" {
                let url = reqwest::Url::parse(&val).map_err(|_| RejectedRequest)?;
                if !matches!(
                    (url.scheme(), url.port_or_known_default()),
                    ("http", Some(80)) | ("https", Some(443))
                ) || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || match url.host_str() {
                        Some(host) => match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                            Ok(ip) => !providers::is_public_address(ip),
                            Err(_) => {
                                !host.contains('.')
                                    || [".local", ".lan", ".home.arpa"]
                                        .iter()
                                        .any(|suffix| host.ends_with(suffix))
                            }
                        },
                        None => true,
                    }
                {
                    return Err(RejectedRequest);
                }
            }
            encoded.push(format!("{}={}", urlencoding::encode(&key), urlencoding::encode(&val)));
        }
        output.push('?');
        output.push_str(&encoded.join("&"));
    }
    Ok(output)
}

/// Config changes through the relay are limited to the three routing modes.
/// Ports, listeners, controller credentials and file paths remain runtime-owned.
pub fn valid_body(method: &Method, body: &[u8]) -> bool {
    if body.len() > 16 * 1024 {
        return false;
    }
    if !matches!(*method, Method::PUT | Method::PATCH) {
        return body.is_empty();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let Some(object) = value.as_object().filter(|object| object.len() == 1) else {
        return false;
    };
    if *method == Method::PATCH {
        matches!(
            object.get("mode").and_then(|value| value.as_str()),
            Some("rule" | "global" | "direct")
        )
    } else {
        object
            .get("name")
            .and_then(|value| value.as_str())
            .is_some_and(|name| !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control))
    }
}

pub fn sanitize_response(value: &mut serde_json::Value, secret: &str) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                let key = key.to_ascii_lowercase();
                if [
                    "secret",
                    "password",
                    "authorization",
                    "authentication",
                    "auth",
                    "auth-str",
                    "ss-config",
                    "vmess-config",
                    "header",
                    "headers",
                    "private-key",
                    "private_key",
                    "header-protection-key",
                    "pre-shared-key",
                    "preshared-key",
                    "token",
                    "uuid",
                    "url",
                ]
                .iter()
                .any(|s| key == *s)
                    || key.ends_with("url")
                {
                    *v = serde_json::Value::String("[redacted]".into());
                } else {
                    sanitize_response(v, secret);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for v in values {
                sanitize_response(v, secret);
            }
        }
        serde_json::Value::String(s) if !secret.is_empty() => *s = s.replace(secret, "[redacted]"),
        _ => (),
    }
}

/// Classify known Mihomo messages into fixed diagnostics without echoing free text.
pub fn sanitize_log(value: &serde_json::Value, _secret: &str) -> serde_json::Value {
    let level = value
        .get("type")
        .and_then(|v| v.as_str())
        .filter(|s| matches!(*s, "debug" | "info" | "warning" | "error" | "fatal" | "silent"))
        .unwrap_or("info");
    let raw = value.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let lower = raw.chars().take(4096).collect::<String>().to_ascii_lowercase();
    let protocol = if lower.starts_with("[tcp]") {
        "tcp"
    } else if lower.starts_with("[udp]") {
        "udp"
    } else if lower.starts_with("[dns]") {
        "dns"
    } else {
        "unknown"
    };
    let (category, payload) = if lower.contains("connection refused") {
        ("connection_refused", "connection refused")
    } else if (protocol == "dns" || lower.contains("dns"))
        && (lower.contains("no such host") || lower.contains("failed") || lower.contains("timeout"))
    {
        ("dns_failure", "DNS lookup failed")
    } else if (lower.contains("dial") || lower.contains("connect"))
        && (lower.contains("i/o timeout") || lower.contains("timed out") || lower.contains("deadline exceeded"))
    {
        ("connect_timeout", "connection timed out")
    } else if lower.contains("provider") && (lower.contains("failed") || lower.contains("error")) {
        ("provider_failure", "provider update failed")
    } else if lower.contains("listening")
        && (lower.contains("proxy") || lower.contains("tproxy") || lower.contains("dns"))
    {
        ("listener_started", "listener started")
    } else if lower.contains("configuration") && (lower.contains("complete") || lower.contains("loaded")) {
        ("configuration_loaded", "configuration loaded")
    } else if lower.contains("request") && lower.contains("failed") {
        ("request_failed", "request failed")
    } else {
        ("unknown", "log details suppressed")
    };
    let mut output = serde_json::json!({"type":level,"category":category,"protocol":protocol,"payload":payload});
    if let Some(time) = value
        .get("time")
        .and_then(|v| v.as_str())
        .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
    {
        output["time"] = serde_json::json!(time);
    }
    output
}

/// The caller must authenticate and authorize the browser before invoking this function.
pub async fn http(method: Method, path: &str, query: Option<&str>, body: Bytes, secret: &str) -> Response {
    let Ok(uri) = canonical_request(&method, path, query) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !valid_body(&method, &body) || secret.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(35))
        .build()
    else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Ok(mut response) = client
        .request(method, format!("http://127.0.0.1:9090/{uri}"))
        .bearer_auth(secret)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = response.status();
    if !status.is_success() {
        return status.into_response();
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len() + chunk.len() > LIMIT {
                    return StatusCode::BAD_GATEWAY.into_response();
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        }
    }
    if bytes.is_empty() {
        return status.into_response();
    }
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    sanitize_response(&mut json, secret);
    (status, axum::Json(json)).into_response()
}

/// Streams only server-originated, size-limited JSON messages. Browser messages are ignored.
pub async fn websocket(socket: WebSocket, stream: &str, query: Option<&str>, secret: &str) {
    if !matches!(stream, "logs" | "traffic" | "memory" | "connections")
        || query.is_some_and(|q| !q.is_empty())
        || secret.is_empty()
    {
        return;
    }
    let Ok(mut request) = format!("ws://127.0.0.1:9090/{stream}").into_client_request() else {
        return;
    };
    let Ok(auth) = format!("Bearer {secret}").parse() else {
        return;
    };
    request.headers_mut().insert(http::header::AUTHORIZATION, auth);
    let config = WebSocketConfig::default()
        .max_message_size(Some(LIMIT))
        .max_frame_size(Some(LIMIT));
    let Ok(Ok((upstream, _))) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async_with_config(request, Some(config), false),
    )
    .await
    else {
        return;
    };
    let (_, mut incoming) = upstream.split();
    let (mut out, mut client) = socket.split();
    loop {
        tokio::select! {
            event = client.next() => if !matches!(event, Some(Ok(Message::Ping(_) | Message::Pong(_)))) { break; },
            event = incoming.next() => match event {
                Some(Ok(UpstreamMessage::Text(text))) if text.len() <= LIMIT => {
                    let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&text) else { break };
                    sanitize_response(&mut json, secret);
                    // Log payloads may contain credentials in free text; never forward them unfiltered.
                    if stream == "logs" { json = sanitize_log(&json, secret); }
                    if !matches!(tokio::time::timeout(Duration::from_secs(5), out.send(Message::Text(json.to_string().into()))).await, Ok(Ok(()))) { break; }
                },
                Some(Ok(UpstreamMessage::Ping(_) | UpstreamMessage::Pong(_))) => (),
                _ => break,
            }
        }
    }
}
