#[test]
#[ignore = "requires the downloaded, checksummed public template corpus"]
fn full_public_adlist_is_accepted_without_truncation() {
    let path = std::env::var("XKEEN_PUBLIC_ADLIST").expect("public fixture path");
    let bytes = std::fs::read(path).unwrap();
    let mrs = profile_policy::mrs::inspect(&bytes).expect("full compact MRS remains intact");
    assert_eq!(mrs.rule_count, 226825);
    assert_eq!(mrs.behavior, "domain");
    assert_eq!(mrs.decoded_bytes, 3553463);
}

#[test]
#[ignore = "requires the downloaded, checksummed public template corpus"]
fn every_public_mrs_is_bounded_and_structurally_valid() {
    let dir = std::path::PathBuf::from(std::env::var("XKEEN_PUBLIC_ADLIST").unwrap())
        .parent()
        .unwrap()
        .to_owned();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let mut count = 0;
    for item in manifest["files"].as_array().unwrap() {
        let name = item["file"].as_str().unwrap();
        if !name.ends_with(".mrs") {
            continue;
        }
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let data = profile_policy::mrs::inspect(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(data.decoded_bytes <= 16 * 1024 * 1024);
        count += 1;
        println!("{name} {} {} {}", data.behavior, data.rule_count, data.decoded_bytes);
        assert!(profile_policy::mrs::inspect(&bytes[..bytes.len() - 1]).is_err());
        let mut with_tail = bytes;
        with_tail.push(0);
        assert!(profile_policy::mrs::inspect(&with_tail).is_err());
    }
    assert_eq!(count, 41);
}

#[test]
#[ignore = "requires the downloaded, checksummed public template corpus"]
fn actual_discord_rules_keep_safe_dependencies() {
    let dir = std::path::PathBuf::from(std::env::var("XKEEN_PUBLIC_ADLIST").unwrap())
        .parent()
        .unwrap()
        .to_owned();
    let text = std::fs::read_to_string(dir.join("e8bd78fafd4390de0d6b.txt")).unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"payload":text.lines().collect::<Vec<_>>()})).unwrap();
    let refs = std::collections::HashSet::from(["cloudflare@ipcidr".into(), "google@ipcidr".into()]);
    assert!(profile_policy::rule_payload_complete_with_refs(
        &payload,
        "classical",
        &refs
    ));
    assert!(!profile_policy::rule_payload_complete(&payload, "classical"));
    assert!(!profile_policy::rule_payload_complete_with_refs(
        &payload,
        "classical",
        &std::collections::HashSet::from(["google@ipcidr".into()])
    ));
    let bad = serde_json::to_vec(&serde_json::json!({"payload":["RULE-SET,google@ipcidr"]})).unwrap();
    assert!(!profile_policy::rule_payload_complete_with_refs(
        &bad,
        "classical",
        &refs
    ));
}

#[tokio::test]
#[ignore = "requires the downloaded, checksummed public template corpus"]
async fn both_exact_templates_with_all_real_files_complete_the_provider_pipeline() {
    use xkeen_ui::{
        configuration::ConfigStore,
        mihomo::{providers::refresh_assets, subscription},
    };
    let dir = std::path::PathBuf::from(std::env::var("XKEEN_PUBLIC_ADLIST").unwrap())
        .parent()
        .unwrap()
        .to_owned();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let cases: serde_json::Value = serde_json::from_str(include_str!("fixtures/subscription-import.json")).unwrap();
    for template in ["config.yaml", "config_2.yaml"] {
        let source = std::fs::read_to_string(dir.join(template)).unwrap()
            + "\nproxy-providers:\n  subscription_1: {type: http, url: 'https://example.invalid/subscription'}\n";
        let temp = std::env::temp_dir().join(format!("xkeen-public-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::new(&temp).unwrap();
        let p = store.save("config", &source, None).unwrap();
        let preview = store.prepare("config", &p.revision).unwrap();
        let mut config: serde_json::Value = serde_json::from_str(&preview.effective_yaml).unwrap();
        config["external-controller"] = serde_json::json!("127.0.0.1:9090");
        config["secret"] = serde_json::json!("synthetic-test-secret");
        let mut assets = vec![profile_policy::Asset {
            path: "providers/proxies/0.yaml".into(),
            content: subscription::normalize(cases[0]["uri"].as_str().unwrap().as_bytes()).unwrap(),
        }];
        let mut selected = String::new();
        for (i, (name, p)) in config["rule-providers"].as_object().unwrap().iter().enumerate() {
            let content = if p["type"] == "inline" {
                selected = format!("rule-{i}");
                serde_json::to_vec(&serde_json::json!({"payload":p["payload"]})).unwrap()
            } else {
                let entry = manifest["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["url"] == p["url"])
                    .unwrap();
                let bytes = std::fs::read(dir.join(entry["file"].as_str().unwrap())).unwrap();
                if p["format"] == "text" {
                    serde_json::to_vec(&serde_json::json!({"payload":std::str::from_utf8(&bytes).unwrap().lines().collect::<Vec<_>>()})).unwrap()
                } else {
                    bytes
                }
            };
            assert!(!name.is_empty());
            assets.push(profile_policy::Asset {
                path: format!("providers/rules/{i}.yaml"),
                content,
            });
        }
        let result = refresh_assets(&config.to_string(), &selected, &assets)
            .await
            .unwrap_or_else(|e| panic!("{template}: {e:?}"));
        assert!(profile_policy::complete(&result.config, &result.files));
        let staged = xkeen_ui::mihomo::providers::stage_profile_assets(&temp, &result.files, &result.config).unwrap();
        staged.cleanup().unwrap();
        let broken = result
            .config
            .replace("RULE-SET,meta@domain", "RULE-SET,missing")
            .replace("RULE-SET,category-ru@domain", "RULE-SET,missing");
        assert!(!profile_policy::complete(&broken, &result.files));
        println!(
            "{template}: {} assets, {} bytes",
            result.files.len(),
            result.files.iter().map(|a| a.content.len()).sum::<usize>()
        );
        std::fs::remove_dir_all(temp).unwrap();
    }
}
