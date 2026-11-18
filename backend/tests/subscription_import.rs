use base64::{Engine, engine::general_purpose::STANDARD};

#[test]
fn vless_reality_accepts_compatible_spx_and_none_tcp_header() {
    let uri = "vless://00000000-0000-4000-8000-000000000001@vpn.example.invalid:443?security=reality&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&sid=01234567&sni=example.org&type=tcp#synthetic";
    let extended = uri.replace("#synthetic", "&spx=%2F&headerType=none#synthetic");
    let expected = xkeen_ui::mihomo::subscription::normalize(uri.as_bytes()).unwrap();
    assert_eq!(
        xkeen_ui::mihomo::subscription::normalize(STANDARD.encode(extended).as_bytes()).unwrap(),
        expected
    );
}

#[test]
fn base64_single_vless_becomes_the_same_typed_node_as_direct_import() {
    let uri = "vless://00000000-0000-4000-8000-000000000001@vpn.example.invalid:443?security=reality&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&sid=01234567&sni=example.org&type=grpc&serviceName=0123#synthetic";
    let body = STANDARD.encode(uri);
    let payload = xkeen_ui::mihomo::subscription::normalize(body.as_bytes()).unwrap();
    assert!(profile_policy::proxy_payload_complete(&payload));
    let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(v["proxies"][0]["reality-opts"]["short-id"], "01234567");
    assert_eq!(v["proxies"][0]["grpc-opts"]["grpc-service-name"], "0123");
    assert_eq!(
        xkeen_ui::mihomo::subscription::normalize(uri.as_bytes()).unwrap(),
        payload
    );
}

#[test]
fn same_contract_as_the_six_ui_importers() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("fixtures/subscription-import.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let payload = xkeen_ui::mihomo::subscription::normalize(case["uri"].as_str().unwrap().as_bytes()).unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(actual["proxies"][0], case["node"]);
    }
}
#[test]
fn subscriptions_are_atomic_bounded_and_preserve_yaml() {
    use xkeen_ui::mihomo::subscription::{ImportError, MAX_BYTES, normalize};
    let cases: serde_json::Value = serde_json::from_str(include_str!("fixtures/subscription-import.json")).unwrap();
    let a = cases[0]["uri"].as_str().unwrap();
    let b = cases[2]["uri"].as_str().unwrap();
    let list = format!("{a}\r\n\n{b}\n{a}");
    let output = normalize(list.as_bytes()).unwrap();
    for encoder in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        assert_eq!(normalize(encoder.encode(&list).as_bytes()).unwrap(), output);
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["proxies"].as_array().unwrap().len(), 3);
    assert_eq!(parsed["proxies"][2]["name"], "synthetic (2)");
    assert_eq!(normalize(&output).unwrap(), output);
    for bad in [
        "",
        "proxies: []",
        "%%%",
        "proxies: [",
        "proxies: [{name: x, name: y}]",
        "\u{fffd}",
    ] {
        assert!(normalize(bad.as_bytes()).is_err());
    }
    for tail in ["unsupported://secret", "not-a-uri", "trojan://secret@host:443?unsupported=1"] {
        assert!(normalize(format!("{a}\n{tail}").as_bytes()).is_err());
    }
    assert_eq!(normalize(&vec![b'A'; MAX_BYTES + 1]), Err(ImportError::TooLarge));
    assert_eq!(
        normalize((a.to_owned() + "\n").repeat(2049).as_bytes()),
        Err(ImportError::TooLarge)
    );
}

#[test]
fn full_yaml_subscription_extracts_only_validated_proxies() {
    use xkeen_ui::mihomo::subscription::normalize;
    let provider = "proxies: [{name: direct, type: ss, server: vpn.example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}]\n";
    let full = format!(
        "{provider}proxy-groups: [{{name: SELECT, type: select, proxies: [direct]}}]\nrules: [\"MATCH,SELECT\"]\nexternal-controller: 0.0.0.0:9999\n"
    );
    assert_eq!(
        normalize(full.as_bytes()).unwrap(),
        normalize(provider.as_bytes()).unwrap()
    );
    assert!(normalize(b"proxies: [{name: unsafe, type: direct, interface-name: eth0}]\nrules: []").is_err());
}
#[test]
fn provider_errors_never_echo_input() {
    use xkeen_ui::mihomo::providers::{ProviderError, diagnostic::Reason};
    let e = ProviderError::failure(Reason::SubscriptionFormat)
        .at("proxy-0")
        .diagnostic();
    assert!(e.message().contains("proxy-0"));
    assert_eq!(e.stage(), "subscription");
    let mut d = e;
    d.provider = Some("https://secret.invalid/token".into());
    assert!(!d.message().contains("secret"));
}

#[test]
fn unknown_and_incompatible_uri_parameters_have_redacted_location() {
    use xkeen_ui::mihomo::{providers::ProviderError, subscription::normalize};
    let base = "vless://00000000-0000-4000-8000-000000000001@vpn.example.invalid:443?type=tcp&";
    for (query, name) in [
        ("private-credential-name=secret", "unknown"),
        ("headerType=http", "headerType"),
        ("spx=%2F", "spx"),
    ] {
        let d = ProviderError::from(normalize(format!("{base}{query}").as_bytes()).unwrap_err())
            .at("proxy-0")
            .diagnostic();
        let value = serde_json::to_value(&d).unwrap();
        assert_eq!(value["import"]["node"], 1);
        assert_eq!(value["import"]["parameter"], name);
        let display = format!("{}{}", value, d.message());
        for secret in ["private-credential-name", "secret", "vpn.example", "vless://"] {
            assert!(!display.contains(secret));
        }
    }
}

#[test]
fn bounded_subscription_metadata_survives_normalization_without_entering_nodes() {
    use xkeen_ui::mihomo::{providers::metadata, subscription::normalize};
    let input = b"proxies: [{name: test, type: ss, server: vpn.example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}]";
    let info = metadata::parse_header("upload=0; download=1024; total=4096; expire=1893456000").unwrap();
    let attached = metadata::attach(normalize(input).unwrap(), Some(info.clone())).unwrap();
    let normalized = normalize(&attached).unwrap();
    assert_eq!(metadata::read(&normalized), Some(info));
    assert!(profile_policy::proxy_payload_complete(&normalized));
    assert_eq!(
        profile_policy::parse_document(std::str::from_utf8(&normalized).unwrap())
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        1
    );
    for invalid in ["upload=-1", "upload=1; upload=2", "token=secret", "download=9007199254740992"] {
        assert!(metadata::parse_header(invalid).is_none());
    }
}

#[test]
fn shared_incompatible_uri_cases_fail_atomically_in_plain_and_base64_lists() {
    let cases: Vec<String> = serde_json::from_str(include_str!("fixtures/subscription-negative.json")).unwrap();
    for uri in cases {
        for bytes in [uri.as_bytes().to_vec(), STANDARD.encode(&uri).into_bytes()] {
            assert!(xkeen_ui::mihomo::subscription::normalize(&bytes).is_err());
        }
    }
}

#[test]
fn three_xui_reality_mlkem_explicit_boolean_is_preserved() {
    use xkeen_ui::mihomo::{providers::ProviderError, subscription::normalize};
    let fixtures: serde_json::Value = serde_json::from_str(include_str!("fixtures/subscription-import.json")).unwrap();
    let case = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["case"] == "3x-ui-reality-mlkem-true")
        .unwrap();
    let uri = case["uri"].as_str().unwrap();
    for (source, expected) in [
        (uri.to_owned(), true),
        (
            uri.replace("support-x25519mlkem768=true", "support-x25519mlkem768=false"),
            false,
        ),
        (uri.replace("&support-x25519mlkem768=true", ""), true),
    ] {
        for input in [source.as_bytes().to_vec(), STANDARD.encode(&source).into_bytes()] {
            let result = normalize(&input).map_err(|e| ProviderError::from(e).at("proxy-0").diagnostic());
            assert!(
                result.is_ok(),
                "REGRESSION_REJECTION {}",
                serde_json::to_string(&result.unwrap_err()).unwrap()
            );
            let nodes: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
            assert_eq!(nodes["proxies"][0]["reality-opts"]["support-x25519mlkem768"], expected);
            assert_eq!(nodes["proxies"][0]["reality-opts"]["short-id"], "01234567");
        }
    }
}

#[test]
fn three_xui_mlkem_invalid_context_values_and_duplicates_name_only_the_known_field() {
    use xkeen_ui::mihomo::{providers::ProviderError, subscription::normalize};
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/subscription-mlkem-negative.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let uri = case["uri"].as_str().unwrap();
        for bytes in [uri.as_bytes().to_vec(), STANDARD.encode(uri).into_bytes()] {
            let d = ProviderError::from(normalize(&bytes).unwrap_err())
                .at("proxy-0")
                .diagnostic();
            let value = serde_json::to_value(&d).unwrap();
            assert_eq!(
                value["import"]["parameter"], "support-x25519mlkem768",
                "{}",
                case["case"]
            );
            assert_eq!(value["import"]["issue"], case["issue"]);
            assert_eq!(value["import"]["position"], case["position"]);
            assert!(d.message().contains("support-x25519mlkem768"));
            assert!(!d.message().contains("vpn.example") && !d.message().contains("vless://"));
        }
    }
}
