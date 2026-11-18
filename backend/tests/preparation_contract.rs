use xkeen_ui::configuration::{ConfigStore, PrepareError};
use yaml_rust2::YamlLoader;

#[test]
fn preview_preserves_snapshot_and_disables_managed_settings() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "# source\nsecret: private\nexternal-controller: 0.0.0.0:9090\nproxies:\n  - {name: awg, type: wireguard, private-key: key, ip: 10.0.0.1}\nrules: [MATCH,awg]\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    assert_eq!(preview.source, source);
    assert_eq!(preview.revision, saved.revision);
    assert_eq!(preview.mode, "manual-preview");
    assert!(preview.effective_yaml.contains('\n'));
    assert!(!preview.activatable);
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(doc["mixed-port"].as_i64(), Some(7890));
    assert_eq!(doc["external-controller"].as_str(), Some(""));
    assert_eq!(doc["secret"].as_str(), Some(""));
    assert_eq!(doc["proxies"][0]["private-key"].as_str(), Some("key"));
    assert!(!format!("{:?}", preview.changes).contains("private"));
    assert_eq!(store.read("home").unwrap(), saved);
    assert!(matches!(store.prepare("home", "stale"), Err(PrepareError::Config(_))));
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ambiguous_documents_fail_without_changing_saved_source() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    for source in [
        "a: 1\na: 2\n",
        "a: {b: 1, b: 2}\n",
        "a: !custom value\n",
        "a: {<<: 1}\n",
        "1: value\n",
        "a: 0123\n",
        "a: 0XFF\n",
        "a: 1_000.5\n",
        "a: Null\n",
        "a: 2026-11-12\n",
        "a: 18446744073709551616\n",
    ] {
        let saved = store
            .save("home", source, store.read("home").ok().map(|p| p.revision).as_deref())
            .unwrap();
        assert_eq!(
            store.prepare("home", &saved.revision).unwrap_err(),
            PrepareError::AmbiguousYaml
        );
        assert_eq!(store.read("home").unwrap(), saved);
    }
    let saved = store
        .save(
            "home",
            "proxies: [{name: '0123', type: wireguard, reserved: [4294967295], values: ['0XFF', '1_000.5', 'Null', '2026-11-12']}]\n",
            Some(&store.read("home").unwrap().revision),
        )
        .unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(doc["proxies"][0]["name"].as_str(), Some("0123"));
    for (i, value) in ["0XFF", "1_000.5", "Null", "2026-11-12"].iter().enumerate() {
        assert_eq!(doc["proxies"][0]["values"][i].as_str(), Some(*value));
    }
    assert_eq!(doc["proxies"][0]["reserved"][0].as_i64(), Some(4294967295));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mihomo_template_anchors_off_and_keenetic_mark_prepare_without_losing_source() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    // Shape of both templates offered by the upstream Mihomo template catalog.
    let source = "# template\nfind-process-mode: off\nrouting-mark: 255\nanchors:\n  defaults: &domain {type: http, format: mrs, behavior: domain, interval: 86400}\nrule-providers:\n  example: {<<: *domain, url: 'https://example.invalid/example.mrs'}\nproxies: [{name: test, type: direct}]\nrules: ['RULE-SET,example,test', 'MATCH,DIRECT']\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(doc["find-process-mode"].as_str(), Some("off"));
    assert_eq!(doc["routing-mark"].as_i64(), Some(0));
    assert!(doc["anchors"].is_badvalue());
    let provider = &doc["rule-providers"]["example"];
    assert_eq!(provider["type"].as_str(), Some("http"));
    assert_eq!(provider["format"].as_str(), Some("mrs"));
    assert_eq!(provider["interval"].as_i64(), Some(86400));
    assert!(provider["<<"].is_badvalue());
    assert!(preview.diagnostics.iter().all(|d| d.code == "PROVIDER_UNRESOLVED"));
    assert!(preview.changes.iter().any(|c| c.path == "anchors"));
    assert!(preview.changes.iter().any(|c| c.path == "routing-mark"));
    assert_eq!(preview.source, source);
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn yaml_merges_preserve_explicit_overrides_and_first_mapping_precedence() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "anchors:\n  base: &base {type: direct, name: first, udp: true}\n  second: &second {name: second, udp: false}\n  inherited: &inherited {<<: *base, name: inherited}\nproxies:\n  - {name: explicit, <<: [*base, *second]}\n  - {<<: *inherited, name: last}\nrules: &rules ['MATCH,DIRECT']\nsub-rules: {same: *rules}\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    assert!(preview.diagnostics.is_empty());
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(doc["proxies"][0]["name"].as_str(), Some("explicit"));
    assert_eq!(doc["proxies"][0]["udp"].as_bool(), Some(true));
    assert_eq!(doc["proxies"][1]["name"].as_str(), Some("last"));
    assert_eq!(doc["proxies"][1]["type"].as_str(), Some("direct"));
    assert_eq!(doc["rules"], doc["sub-rules"]["same"]);
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn yaml_aliases_cannot_bypass_expansion_depth_or_duplicate_limits() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let mut bomb = String::from("a: &a [value]\n");
    for (prev, next) in [('a', 'b'), ('b', 'c'), ('c', 'd'), ('d', 'e')] {
        bomb.push_str(&format!(
            "{next}: &{next} [{}]\n",
            vec![format!("*{prev}"); 20].join(",")
        ));
    }
    let mut deep = String::from("a0: &a0 [value]\n");
    for i in 1..66 {
        deep.push_str(&format!("a{i}: &a{i} [*a{}]\n", i - 1));
    }
    let bytes = format!("a: &a '{}'\nb: [{}]\n", "x".repeat(100_000), vec!["*a"; 100].join(","));
    for source in [&bomb, &deep, &bytes] {
        let saved = store
            .save("home", source, store.read("home").ok().map(|p| p.revision).as_deref())
            .unwrap();
        assert_eq!(
            store.prepare("home", &saved.revision).unwrap_err(),
            PrepareError::LimitExceeded
        );
    }
    for source in [
        "a: &a [*a]\n",
        "a: &a {b: 1, b: 2}\n",
        "a: {<<: [{b: 1}, 3]}\n",
        "find-process-mode: off\na: on\n",
    ] {
        let saved = store
            .save("home", source, Some(&store.read("home").unwrap().revision))
            .unwrap();
        assert!(store.prepare("home", &saved.revision).is_err());
        assert_eq!(store.read("home").unwrap(), saved);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn http_provider_path_is_remapped_without_touching_sentinel() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let sentinel = root.with_extension("sentinel");
    std::fs::write(&sentinel, "unchanged").unwrap();
    let store = ConfigStore::new(&root).unwrap();
    let source = format!(
        "proxy-providers:\n  private: {{type: http, url: 'https://example.invalid/private', path: '{}'}}\nrule-providers:\n  local: {{type: file, path: '{}'}}\nrules: ['MATCH,DIRECT']\n",
        sentinel.display(),
        sentinel.display()
    );
    let saved = store.save("home", &source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(
        doc["proxy-providers"]["private"]["path"].as_str(),
        Some("providers/proxies/0.yaml")
    );
    assert_eq!(doc["rule-providers"]["local"]["path"].as_str(), sentinel.to_str());
    assert_eq!(
        preview
            .diagnostics
            .iter()
            .filter(|d| d.code == "PROVIDER_UNRESOLVED")
            .count(),
        2
    );
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "unchanged");
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_file(sentinel).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn too_many_nodes_fail_with_a_stable_limit() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = format!("rules: [{}]\n", "x,".repeat(50_001));
    let saved = store.save("home", &source, None).unwrap();
    assert_eq!(
        store.prepare("home", &saved.revision).unwrap_err(),
        PrepareError::LimitExceeded
    );
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unresolved_outbounds_and_geodata_are_reported_without_values() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "proxies: [{name: secretname, type: tailscale, credential-file: /private/key}]\nrules: ['GEOIP,CN,DIRECT']\nmystery-setting: privatevalue\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    for code in [
        "UNKNOWN_SETTING",
        "UNRESOLVED_SETTING",
        "OUTBOUND_UNREVIEWED",
        "ASSET_UNRESOLVED",
    ] {
        assert!(preview.diagnostics.iter().any(|d| d.code == code), "missing {code}");
    }
    let json = serde_json::to_string(&preview.diagnostics).unwrap();
    for secret in ["secretname", "/private/key", "privatevalue"] {
        assert!(!json.contains(secret));
    }
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_overlay_disables_endpoints_and_preserves_user_rules() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "port: 80\nsocks-port: 81\nredir-port: 82\ntproxy-port: 83\nallow-lan: true\nbind-address: '*'\nexternal-controller-tls: ':9443'\nexternal-controller-unix: /tmp/controller\nexternal-controller-pipe: pipe\nexternal-doh-server: ':443'\nexternal-ui: /tmp/ui\nexternal-ui-url: 'https://example.invalid/ui'\nexternal-ui-name: custom\nss-config: secret\nvmess-config: secret\nrouting-mark: 123\ninterface-name: eth0\nlisteners: [{type: mixed, port: 3}]\ntunnels: ['tcp,1,2,DIRECT']\ntun: {enable: true}\ndns: {enable: true, listen: ':53'}\niptables: {enable: true}\nntp: {enable: true}\ntuic-server: {enable: true}\nprofile: {store-selected: true}\ngeo-auto-update: true\nproxy-groups: [{name: select, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,select']\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    let doc = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    for k in [
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "routing-mark",
        "external-controller-routing-mark",
    ] {
        assert_eq!(doc[k].as_i64(), Some(0), "{k}");
    }
    for k in [
        "external-controller",
        "external-controller-tls",
        "external-controller-unix",
        "external-controller-pipe",
        "external-doh-server",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "ss-config",
        "vmess-config",
        "interface-name",
    ] {
        assert_eq!(doc[k].as_str(), Some(""), "{k}");
    }
    for k in ["tun", "iptables", "ntp", "tuic-server", "dns"] {
        assert_eq!(doc[k]["enable"].as_bool(), Some(false), "{k}");
    }
    assert_eq!(doc["profile"]["store-selected"].as_bool(), Some(false));
    assert_eq!(doc["geo-auto-update"].as_bool(), Some(false));
    assert_eq!(doc["listeners"].as_vec().unwrap().len(), 0);
    assert_eq!(doc["tunnels"].as_vec().unwrap().len(), 0);
    assert_eq!(doc["proxy-groups"][0]["name"].as_str(), Some("select"));
    assert_eq!(doc["rules"][0].as_str(), Some("MATCH,select"));
    assert!(preview.diagnostics.iter().any(|d| d.code == "MANAGED_SETTING"));
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn decimal_lexemes_and_unicode_line_separators_survive_preview() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "small: 1.5\nprecise: 1.2345678901234567890123456789e+30\ntext: \"a\\Nb\\Lc\\Pd\"\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    assert!(preview.effective_yaml.contains("1.5"));
    assert!(preview.effective_yaml.contains("1.2345678901234567890123456789e+30"));
    let original = &YamlLoader::load_from_str(source).unwrap()[0];
    let effective = &YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0];
    assert_eq!(original["text"], effective["text"]);
    assert!(preview.effective_yaml.contains("\\u0085"));
    assert!(preview.effective_yaml.contains("\\u2028"));
    assert!(preview.effective_yaml.contains("\\u2029"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_geo_and_type_specific_assets_have_safe_indexed_paths() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "proxies:\n  - {name: private, type: ssh, private-key: /sensitive/key}\n  - {name: wg, type: wireguard, private-key: base64secret}\n  - {name: tls, type: vless, certificate: /private/cert}\nrules: ['AND,((NETWORK,UDP),(GEOIP,CN)),DIRECT']\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    let assets: Vec<_> = preview
        .diagnostics
        .iter()
        .filter(|d| d.code == "ASSET_UNRESOLVED")
        .map(|d| d.path.as_str())
        .collect();
    assert!(assets.contains(&"proxies[0]"));
    assert!(!assets.contains(&"proxies[1]"));
    assert!(assets.contains(&"proxies[2]"));
    assert!(assets.contains(&"rules"));
    let json = serde_json::to_string(&preview.diagnostics).unwrap();
    assert!(!json.contains("/sensitive/key"));
    assert!(!json.contains("private/cert"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn escaped_unicode_line_separators_are_preserved() {
    let root = std::env::temp_dir().join(format!("prepare-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = "text: \"a\\Nb\\Lc\\Pd\"\n";
    let saved = store.save("home", source, None).unwrap();
    let preview = store.prepare("home", &saved.revision).unwrap();
    assert_eq!(
        YamlLoader::load_from_str(source).unwrap()[0]["text"],
        YamlLoader::load_from_str(&preview.effective_yaml).unwrap()[0]["text"]
    );
    std::fs::remove_dir_all(root).unwrap();
}
