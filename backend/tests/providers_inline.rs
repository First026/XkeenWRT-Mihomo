use xkeen_ui::{configuration::ConfigStore, mihomo::providers::prepare_assets};
fn managed(source: &str) -> String {
    let dir = std::env::temp_dir().join(format!("xkeen-inline-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&dir).unwrap();
    let profile = store.save("config", source, None).unwrap();
    let preview = store.prepare("config", &profile.revision).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let mut config: serde_json::Value = serde_json::from_str(&preview.effective_yaml).unwrap();
    config["external-controller"] = serde_json::json!("127.0.0.1:9090");
    config["secret"] = serde_json::json!("synthetic-test-secret");
    config.to_string()
}

#[tokio::test]
async fn inline_sources_become_validated_immutable_assets_without_fetching() {
    let prepared = prepare_assets(&managed("proxy-providers:\n  local:\n    type: inline\n    payload:\n      - {name: example, type: vless, server: example.org, port: 443, uuid: 00000000-0000-4000-8000-000000000001}\nrule-providers:\n  local:\n    type: inline\n    behavior: domain\n    payload: ['+.example.org']\nproxy-groups:\n  - {name: Select, type: select, use: [local]}\nrules:\n  - RULE-SET,local,Select\n  - MATCH,DIRECT\n")).await;
    assert_eq!(prepared.unwrap().files.len(), 2);
    let prepared = prepare_assets(&managed("rule-providers:\n  local:\n    type: inline\n    behavior: domain\n    payload: ['+.example.org']\nrules:\n  - RULE-SET,local,DIRECT\n  - MATCH,DIRECT\n")).await.unwrap();
    assert_eq!(prepared.files.len(), 1);
    // Contract with Mihomo's line-oriented YAML rule provider reader, which
    // rejects a one-line JSON/flow mapping even when generic YAML accepts it.
    assert_eq!(prepared.files[0].content, b"payload:\n  - \"+.example.org\"\n");
    assert!(prepared.config.contains("providers/rules/0.yaml"));
    assert!(!prepared.config.contains("inline"));
}

#[tokio::test]
async fn upstream_template_shape_with_41_sources_reaches_complete_staged_profile() {
    let mut source = String::from(
        "find-process-mode: off\nrouting-mark: 255\nanchors:\n  inline: &inline {type: inline, behavior: classical}\nsniffer:\n  enable: true\n  sniff: {HTTP: {ports: [80, 8080]}, TLS: {ports: [443, 8443]}, QUIC: {ports: [443]}}\n  skip-dst-address: ['rule-set:rules0']\n  skip-domain: ['+.example.org']\nproxies: [{name: test, type: vless, server: example.invalid, port: 443, uuid: 00000000-0000-4000-8000-000000000001, tls: true, reality-opts: {public-key: synthetic, short-id: \"01234567\", support-x25519mlkem768: true}}]\nproxy-groups:\n  - {name: PROXY, type: select, include-all: true, proxies: [DIRECT]}\n  - {name: Fastest, type: url-test, include-all: true, max-failed-times: 3, url: 'https://www.gstatic.com/generate_204', interval: 300}\nrule-providers:\n",
    );
    for i in 0..41 {
        source.push_str(&format!(
            "  rules{i}: {{<<: *inline, payload: ['AND,((DST-PORT,443),(NETWORK,UDP))']}}\n"
        ));
    }
    source.push_str("rules: ['RULE-SET,rules0,PROXY', 'MATCH,DIRECT']\n");
    let prepared = prepare_assets(&managed(&source)).await.unwrap();
    assert_eq!(prepared.files.len(), 41);
    assert!(profile_policy::complete(&prepared.config, &prepared.files));
    let root = std::env::temp_dir().join(format!("xkeen-template-assets-{}", uuid::Uuid::new_v4()));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let stage = xkeen_ui::mihomo::providers::stage_assets(&root, &prepared.files).unwrap();
    assert_eq!(
        std::fs::read(stage.path().join("providers/rules/40.yaml")).unwrap(),
        prepared.files[40].content
    );
    stage.cleanup().unwrap();
    std::fs::remove_dir(root).unwrap();
    // Sniffer references and nested logical rules must not introduce unstaged assets.
    assert!(
        prepare_assets(&managed(&source.replace("rule-set:rules0", "rule-set:missing")))
            .await
            .is_err()
    );
    assert!(
        prepare_assets(&managed(&source.replace("(DST-PORT,443)", "(GEOIP,CN)")))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn classical_rules_may_reference_only_staged_leaf_sets() {
    let source = "rule-providers:\n  leaf: {type: inline, behavior: ipcidr, payload: ['203.0.113.0/24']}\n  composite: {type: inline, behavior: classical, payload: ['PROCESS-NAME-REGEX,^([Dd]iscord(\\.exe)?|com\\.discord)$', 'AND,((RULE-SET,leaf,no-resolve),(NETWORK,TCP))']}\nrules: ['RULE-SET,composite,DIRECT', 'MATCH,DIRECT']\n";
    let prepared = prepare_assets(&managed(source)).await.unwrap();
    assert!(profile_policy::complete(&prepared.config, &prepared.files));
    use std::os::unix::fs::DirBuilderExt;
    let root = std::env::temp_dir().join(format!("xkeen-classical-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    xkeen_ui::mihomo::providers::stage_profile_assets(&root, &prepared.files, &prepared.config)
        .unwrap()
        .cleanup()
        .unwrap();
    std::fs::remove_dir(root).unwrap();
    assert!(
        prepare_assets(&managed(&source.replace("RULE-SET,leaf", "RULE-SET,missing")))
            .await
            .is_err()
    );
    assert!(
        prepare_assets(&managed(&source.replace("RULE-SET,leaf", "RULE-SET,composite")))
            .await
            .is_err()
    );
}
