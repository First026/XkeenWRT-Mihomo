use http::Method;
use xkeen_ui::mihomo::canonical_request;

#[test]
fn relay_restricts_methods_paths_and_queries() {
    assert!(
        canonical_request(
            &Method::GET,
            "proxies/Office%20VPN/delay",
            Some("timeout=5000&url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204")
        )
        .is_ok()
    );
    for path in [
        "configs",
        "providers/proxies/foo",
        "%2e%2e/configs",
        "proxies/a%2fb",
        "proxies/%252e%252e",
    ] {
        assert!(canonical_request(&Method::PUT, path, None).is_err(), "{path}");
    }
    assert!(canonical_request(&Method::GET, "version", Some("token=secret")).is_err());
    assert!(canonical_request(&Method::GET, "dns/query", Some("name=example.com&type=A")).is_ok());
}

#[test]
fn log_sanitization_preserves_useful_text_without_known_secrets() {
    let value = serde_json::json!({"type":"warning", "payload":"request https://example.com/sub?token=abc password=pass1 Bearer auth1 controller-abc failed"});
    let output = xkeen_ui::mihomo::sanitize_log(&value, "controller-abc");
    let text = output.to_string();
    assert_eq!(output["type"], "warning");
    assert!(text.contains("request") && text.contains("failed"));
    for secret in ["example.com", "abc", "pass1", "auth1", "controller-abc"] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn log_categories_explain_failure_without_exposing_free_text() {
    use xkeen_ui::mihomo::sanitize_log;
    let cases = [
        (
            "[TCP] dial DIRECT synthetic-user:secret@example.net:443 error: connect: connection refused",
            "connection_refused",
            "tcp",
        ),
        (
            "[UDP] dial Proxy example.net:443 error: i/o timeout",
            "connect_timeout",
            "udp",
        ),
        (
            "[DNS] lookup synthetic.example failed: no such host",
            "dns_failure",
            "dns",
        ),
        (
            "failed to update provider synthetic https://example.net/secret",
            "provider_failure",
            "unknown",
        ),
    ];
    for (payload, category, protocol) in cases {
        let result = sanitize_log(&serde_json::json!({"type":"warning", "payload":payload}), "synthetic");
        assert_eq!(result["category"], category);
        assert_eq!(result["protocol"], protocol);
        let text = result.to_string();
        for secret in ["example.net", "synthetic", "secret"] {
            assert!(!text.contains(secret));
        }
    }
    let result = sanitize_log(
        &serde_json::json!({"type":"info", "payload":"arbitrary unlabeledsecret"}),
        "",
    );
    assert_eq!(result["category"], "unknown");
    assert!(!result.to_string().contains("unlabeledsecret"));
}

#[test]
fn controller_response_hides_authentication_and_credential_fields() {
    let mut data = serde_json::json!({"authentication":["user:password1"],"ss-config":"ss-secret","testUrl":"https://example.net/sub-token","proxies":[{"auth":"credential","header-protection-key":"awg-secret"}],"mode":"rule"});
    xkeen_ui::mihomo::sanitize_response(&mut data, "controller-secret");
    let s = data.to_string();
    for secret in ["password1", "ss-secret", "credential", "awg-secret", "sub-token"] {
        assert!(!s.contains(secret));
    }
    assert_eq!(data["mode"], "rule");
}

#[test]
fn original_mihomo_controls_have_narrow_relay_routes() {
    for (method, path) in [
        (Method::PATCH, "configs"),
        (Method::DELETE, "proxies/Auto"),
        (Method::POST, "cache/smart/flush"),
        (Method::DELETE, "connections/smart/synthetic-id"),
        (Method::GET, "providers/proxies/sub/Node/healthcheck"),
    ] {
        assert!(canonical_request(&method, path, None).is_ok(), "{method} {path}");
    }
}

#[test]
fn mode_change_cannot_modify_controller_or_network_listeners() {
    use xkeen_ui::mihomo::valid_body;
    for mode in ["rule", "global", "direct"] {
        assert!(valid_body(&Method::PATCH, format!(r#"{{"mode":"{mode}"}}"#).as_bytes()));
    }
    for body in [
        r#"{"mode":"direct","port":1234}"#,
        r#"{"external-controller":"0.0.0.0:9090"}"#,
        r#"{"mode":"invalid"}"#,
    ] {
        assert!(!valid_body(&Method::PATCH, body.as_bytes()));
    }
    assert!(!valid_body(&Method::DELETE, b"{}"));
    assert!(
        canonical_request(
            &Method::GET,
            "proxies/DIRECT/delay",
            Some("url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=5000")
        )
        .is_ok()
    );
    assert!(
        canonical_request(
            &Method::GET,
            "proxies/DIRECT/delay",
            Some("url=http%3A%2F%2F127.0.0.1%2F&timeout=5000")
        )
        .is_err()
    );
}
