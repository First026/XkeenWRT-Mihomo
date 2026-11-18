use profile_policy::Asset;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use xkeen_ui::mihomo::providers::stage_assets;

#[test]
fn staging_accepts_only_generated_paths_and_keeps_private_files() {
    let root = std::env::temp_dir().join(format!("xkeenwrt-assets-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let content = b"proxies:\n  - name: test\n    type: trojan\n    server: example.org\n    port: 443\n    password: synthetic\n".to_vec();
    let asset = Asset {
        path: "providers/proxies/0.yaml".into(),
        content: content.clone(),
    };
    let staged = stage_assets(&root, &[asset]).unwrap();
    let path = staged.path().join("providers/proxies/0.yaml");
    assert_eq!(std::fs::read(&path).unwrap(), content);
    assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    staged.cleanup().unwrap();
    assert!(
        stage_assets(
            &root,
            &[Asset {
                path: "providers/proxies/../../outside.yaml".into(),
                content
            }]
        )
        .is_err()
    );
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn stages_and_removes_mixed_rule_and_proxy_assets() {
    let root = std::env::temp_dir().join(format!("xkeenwrt-assets-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let files = vec![
        Asset {
            path: "providers/proxies/0.yaml".into(),
            content: b"proxies:\n  - {name: p, type: trojan, server: example.org, port: 443, password: synthetic}\n"
                .to_vec(),
        },
        Asset {
            path: "providers/rules/0.yaml".into(),
            content: b"payload:\n  - '+.example.org'\n".to_vec(),
        },
    ];
    let staged = stage_assets(&root, &files).unwrap();
    for file in &files {
        assert_eq!(std::fs::read(staged.path().join(&file.path)).unwrap(), file.content);
    }
    staged.cleanup().unwrap();
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn provider_destination_policy_rejects_non_public_addresses() {
    use xkeen_ui::mihomo::providers::is_public_address;
    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "100.64.0.1",
        "192.0.2.1",
        "::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::1",
        "2001:db8::1",
    ] {
        assert!(!is_public_address(address.parse().unwrap()), "{address}");
    }
    assert!(is_public_address("1.1.1.1".parse().unwrap()));
    assert!(is_public_address("2606:4700:4700::1111".parse().unwrap()));
}

#[test]
fn provider_listing_uses_opaque_stable_ids_and_hides_urls() {
    use xkeen_ui::mihomo::providers::list_providers;
    let profile = r#"proxy-providers:
  zed: {type: http, url: 'https://example.org/secret'}
  alpha: {type: http, url: 'https://example.org/another-secret'}
rule-providers:
  rules: {type: http, url: 'https://example.org/rules', behavior: domain}
"#;
    let list = list_providers(profile).unwrap();
    let output = serde_json::to_string(&list).unwrap();
    assert!(output.contains("proxy-0") && output.contains("rule-0"));
    assert!(!output.contains("example.org") && !output.contains("secret"));
    assert_eq!(list[0].name, "alpha");
}

#[tokio::test]
async fn provider_refresh_rejects_private_address_before_connecting() {
    use xkeen_ui::mihomo::providers::{diagnostic::Reason, prepare_assets};
    let config = r#"proxy-providers:
  local: {type: http, url: 'http://127.0.0.1/secret'}
"#;
    assert_eq!(
        prepare_assets(config).await.unwrap_err().diagnostic().reason,
        Reason::AddressForbidden
    );
}

#[tokio::test]
async fn provider_refresh_rejects_ipv6_loopback_literal() {
    use xkeen_ui::mihomo::providers::{diagnostic::Reason, prepare_assets};
    let config = "proxy-providers:\n  local: {type: http, url: 'http://[::1]/secret'}\n";
    assert_eq!(
        prepare_assets(config).await.unwrap_err().diagnostic().reason,
        Reason::AddressForbidden
    );
}
