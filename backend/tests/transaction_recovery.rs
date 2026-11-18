use xkeen_ui::configuration::{Activation, ActivationError, ConfigStore, Validator};

struct Accept;
impl Validator for Accept {
    fn validate(&self, _: &str) -> Result<(), ActivationError> {
        Ok(())
    }
}

#[test]
fn validated_candidate_is_bound_to_saved_revision() {
    let root = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    let candidate = activation.validate("home", &first.revision).unwrap();
    assert_eq!(candidate.profile_id, "home");
    assert_eq!(candidate.revision, first.revision);
    let store = ConfigStore::new(&root).unwrap();
    store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    assert_eq!(
        activation.check_candidate("home", &first.revision, &candidate.candidate_id),
        Err(ActivationError::Conflict)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancelled_candidate_cannot_be_applied_and_wrong_scope_does_not_cancel_it() {
    let root = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    let candidate = activation.validate("home", &saved.revision).unwrap();
    activation.cancel_candidate("other", &saved.revision, &candidate.candidate_id);
    assert_eq!(
        activation.check_candidate("home", &saved.revision, &candidate.candidate_id),
        Ok(())
    );
    activation.cancel_candidate("home", &saved.revision, &candidate.candidate_id);
    assert_eq!(
        activation.check_candidate("home", &saved.revision, &candidate.candidate_id),
        Err(ActivationError::Conflict)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[derive(Default)]
struct Core {
    running: Option<String>,
    reject: bool,
}
impl xkeen_ui::configuration::ManualCore for Core {
    fn running(&self) -> Result<bool, ActivationError> {
        Ok(self.running.is_some())
    }
    fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError> {
        if self.reject && config.is_some() {
            self.reject = false;
            return Err(ActivationError::Unavailable);
        }
        self.running = config.map(str::to_owned);
        Ok(())
    }
}

#[test]
fn failed_manual_apply_restores_previous_good_and_duplicate_returns_same_transaction() {
    let base = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, Accept, "synthetic-secret".into());
    let c = a.validate("home", &first.revision).unwrap();
    let mut core = Core::default();
    let tx = a
        .apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "one")
        .unwrap();
    a.start(&base, &mut core).unwrap();
    let previous = core.running.clone();
    let repeat = a
        .apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "one")
        .unwrap();
    assert_eq!(repeat.id, tx.id);
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    let c = a.validate("home", &second.revision).unwrap();
    core.reject = true;
    assert_eq!(
        a.apply(&base, &mut core, "home", &second.revision, &c.candidate_id, "two"),
        Err(ActivationError::Unavailable)
    );
    assert_eq!(core.running, previous);
    std::fs::remove_dir_all(base).unwrap();
}

struct Capture(std::sync::Arc<std::sync::Mutex<String>>);
impl Validator for Capture {
    fn validate(&self, yaml: &str) -> Result<(), ActivationError> {
        *self.0.lock().unwrap() = yaml.to_owned();
        Ok(())
    }
}
#[test]
fn core_receives_the_exact_validated_bytes_with_managed_controller() {
    let base = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let saved = store
        .save(
            "home",
            "external-controller: 0.0.0.0:9090\nsecret: unsafe\nmode: rule\n",
            None,
        )
        .unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut a = Activation::new(store, Capture(seen.clone()), "synthetic-secret".into());
    let candidate = a.validate("home", &saved.revision).unwrap();
    let mut core = Core::default();
    a.apply(
        &base,
        &mut core,
        "home",
        &saved.revision,
        &candidate.candidate_id,
        "once",
    )
    .unwrap();
    assert!(core.running.is_none(), "Apply must leave a stopped core stopped");
    a.start(&base, &mut core).unwrap();
    assert_eq!(core.running.as_ref().unwrap(), &*seen.lock().unwrap());
    assert!(core.running.as_ref().unwrap().contains("127.0.0.1:9090"));
    assert!(!core.running.as_ref().unwrap().contains("0.0.0.0:9090"));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn failed_rollback_is_retried_from_durable_pending_transaction() {
    struct Failing {
        failures: u8,
        running: Option<String>,
    }
    impl xkeen_ui::configuration::ManualCore for Failing {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(self.running.is_some())
        }
        fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError> {
            if self.failures > 0 {
                self.failures -= 1;
                return Err(ActivationError::Unavailable);
            }
            self.running = config.map(str::to_owned);
            Ok(())
        }
    }
    let base = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, Accept, "synthetic-secret".into());
    let c = a.validate("home", &first.revision).unwrap();
    let mut core = Failing {
        failures: 0,
        running: None,
    };
    a.apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "first")
        .unwrap();
    a.start(&base, &mut core).unwrap();
    let previous = core.running.clone();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    let c = a.validate("home", &second.revision).unwrap();
    core.failures = 2;
    assert_eq!(
        a.apply(&base, &mut core, "home", &second.revision, &c.candidate_id, "second"),
        Err(ActivationError::CommitUncertain)
    );
    core.running = None;
    a.recover(&base, &mut core).unwrap();
    assert_eq!(core.running, previous);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn stopped_apply_commits_without_start_and_failed_start_remains_stopped() {
    let base = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, Accept, "synthetic-secret".into());
    let c = a.validate("home", &first.revision).unwrap();
    let mut core = Core::default();
    a.apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "first")
        .unwrap();
    a.stop(&base, &mut core).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    let c = a.validate("home", &second.revision).unwrap();
    core.reject = true;
    a.apply(&base, &mut core, "home", &second.revision, &c.candidate_id, "second")
        .unwrap();
    assert!(core.running.is_none());
    assert_eq!(a.start(&base, &mut core), Err(ActivationError::Unavailable));
    assert!(core.running.is_none());
    a.start(&base, &mut core).unwrap();
    assert!(core.running.unwrap().contains("\"direct\""));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn unresolved_provider_cannot_become_a_candidate() {
    let root = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store
        .save(
            "home",
            "proxy-providers:\n  demo:\n    type: http\n    url: https://example.invalid/provider\n",
            None,
        )
        .unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    assert!(matches!(
        activation.validate("home", &saved.revision),
        Err(ActivationError::Unavailable)
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn provider_candidate_binds_validated_config_and_asset_bytes_to_revision() {
    struct Assets;
    impl Validator for Assets {
        fn validate(&self, _: &str) -> Result<(), ActivationError> {
            Err(ActivationError::Invalid)
        }
        fn validate_assets(&self, config: &str, assets: &[profile_policy::Asset]) -> Result<(), ActivationError> {
            assert!(config.contains("providers/proxies/0.yaml"));
            assert_eq!(assets.len(), 1);
            assert_eq!(assets[0].path, "providers/proxies/0.yaml");
            assert!(assets[0].content.starts_with(b"proxies:\n  - name: test\n"));
            Ok(())
        }
    }
    fn prepare_candidate(
        activation: &mut Activation<Assets>, revision: &str, password: &str,
    ) -> xkeen_ui::configuration::ValidatedCandidate {
        activation
            .validate_with_loader("home", revision, |effective| {
                let mut json: serde_json::Value = serde_json::from_str(effective).unwrap();
                let provider = &mut json["proxy-providers"]["demo"];
                provider["type"] = "file".into();
                provider["path"] = "providers/proxies/0.yaml".into();
                provider.as_object_mut().unwrap().remove("url");
                provider.as_object_mut().unwrap().remove("interval");
                let bytes = format!(
                    "proxies:\n  - name: test\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: {password}\n"
                );
                Ok((
                    serde_json::to_string(&json).unwrap(),
                    vec![profile_policy::Asset { path: "providers/proxies/0.yaml".into(), content: bytes.into_bytes() }],
                ))
            })
            .unwrap()
    }
    let root = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store
        .save(
            "home",
            "proxy-providers:\n  demo:\n    type: http\n    url: https://example.invalid/provider\n",
            None,
        )
        .unwrap();
    let mut a = Activation::new(store, Assets, "synthetic-secret".into());
    let candidate = prepare_candidate(&mut a, &saved.revision, "previous");
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PublishedBundle {
        config: String,
        assets: Vec<(String, Vec<u8>)>,
    }
    struct CaptureCore {
        home: Option<PublishedBundle>,
        fail_next_publish: bool,
    }
    impl xkeen_ui::configuration::ManualCore for CaptureCore {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(self.home.is_some())
        }
        fn replace(&mut self, _: Option<&str>) -> Result<(), ActivationError> {
            self.home = None;
            Ok(())
        }
        fn replace_assets(
            &mut self, config: Option<&str>, assets: &[profile_policy::Asset],
        ) -> Result<(), ActivationError> {
            let Some(config) = config else {
                self.home = None;
                return Ok(());
            };
            self.home = Some(PublishedBundle {
                config: config.to_owned(),
                assets: assets
                    .iter()
                    .map(|asset| (asset.path.clone(), asset.content.clone()))
                    .collect(),
            });
            if self.fail_next_publish {
                self.fail_next_publish = false;
                return Err(ActivationError::Unavailable);
            }
            Ok(())
        }
    }
    let mut core = CaptureCore {
        home: None,
        fail_next_publish: false,
    };
    a.apply(
        &root,
        &mut core,
        "home",
        &saved.revision,
        &candidate.candidate_id,
        "assets-first",
    )
    .unwrap();
    assert!(core.home.is_none());
    a.start(&root, &mut core).unwrap();
    let previous = core.home.clone().unwrap();
    assert_eq!(previous.assets[0].1, b"proxies:\n  - name: test\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: previous\n");

    let store = ConfigStore::new(&root).unwrap();
    let next = store
        .save(
            "home",
            "proxy-providers:\n  demo:\n    type: http\n    url: https://example.invalid/provider?v=2\n",
            Some(&saved.revision),
        )
        .unwrap();
    let candidate = prepare_candidate(&mut a, &next.revision, "next");
    core.fail_next_publish = true;
    assert_eq!(
        a.apply(
            &root,
            &mut core,
            "home",
            &next.revision,
            &candidate.candidate_id,
            "assets-failed"
        ),
        Err(ActivationError::Unavailable)
    );
    assert_eq!(core.home, Some(previous.clone()));

    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("transaction.json")).unwrap()).unwrap();
    assert!(journal["pending"].is_null());
    assert_eq!(journal["current"]["tx"]["revision"], saved.revision);
    assert!(journal["current"].get("config").is_none());
    let reference = &journal["current"]["payload"];
    let object = root.join("payloads").join(reference["digest"].as_str().unwrap());
    assert_eq!(
        std::fs::read_to_string(object.join("config.yaml")).unwrap(),
        previous.config
    );
    let provider = reference["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == previous.assets[0].0)
        .unwrap();
    assert_eq!(
        std::fs::read(object.join(provider["file"].as_str().unwrap())).unwrap(),
        previous.assets[0].1
    );
    assert!(std::fs::read_dir(root.join("history")).unwrap().next().is_some());

    assert_eq!(
        a.check_candidate("home", &next.revision, &candidate.candidate_id),
        Err(ActivationError::Conflict)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn network_candidate_requires_fresh_validation_of_exact_managed_overlay() {
    use profile_policy::{ManagedOverlay, NetworkOverlay};
    struct NetworkValidator;
    impl Validator for NetworkValidator {
        fn validate(&self, _: &str) -> Result<(), ActivationError> {
            Ok(())
        }
        fn validate_overlay(
            &self, config: &str, assets: &[profile_policy::Asset], overlay: &ManagedOverlay,
        ) -> Result<(), ActivationError> {
            if profile_policy::complete_for(config, assets, overlay) {
                Ok(())
            } else {
                Err(ActivationError::Invalid)
            }
        }
    }
    let root = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, NetworkValidator, "synthetic-secret".into());
    let manual = a.validate("home", &saved.revision).unwrap();
    let overlay = NetworkOverlay {
        lan_ifname: "br-lan".into(),
        lan_ipv4: "192.0.2.1".parse().unwrap(),
        selected_ipv4: "192.0.2.2".parse().unwrap(),
        tproxy_port: 7893,
        dns_port: 1053,
        nameservers: vec!["1.1.1.1".parse().unwrap()],
        bootstrap: vec!["1.1.1.1".parse().unwrap()],
        local_zones: vec!["+.lan".into()],
    };
    let network = a
        .validate_network("home", &saved.revision, &manual.candidate_id, overlay)
        .unwrap();
    assert_ne!(manual.candidate_id, network.candidate_id);
    assert_eq!(
        a.check_candidate("home", &saved.revision, &manual.candidate_id),
        Err(ActivationError::Conflict)
    );
    a.candidate_bundle("home", &saved.revision, &network.candidate_id)
        .unwrap();
    let mut core = Core::default();
    assert_eq!(
        a.apply(
            &root,
            &mut core,
            "home",
            &saved.revision,
            &network.candidate_id,
            "network-not-manual"
        ),
        Err(ActivationError::Conflict)
    );
    assert!(core.running.is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn emergency_stop_does_not_read_or_rewrite_corrupt_journal() {
    let root = std::env::temp_dir().join(format!("xkeen-emergency-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    std::fs::write(root.join("transaction.json"), b"corrupt").unwrap();
    let a = Activation::new(store, Accept, "synthetic-secret".into());
    let mut core = Core {
        running: Some("old".into()),
        reject: false,
    };
    a.emergency_stop(&mut core).unwrap();
    assert!(core.running.is_none());
    assert_eq!(std::fs::read(root.join("transaction.json")).unwrap(), b"corrupt");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn lifecycle_fence_after_core_change_prevents_success_and_retains_recovery() {
    struct FenceCore {
        running: Option<String>,
        fence: bool,
        trigger: bool,
    }
    impl xkeen_ui::configuration::ManualCore for FenceCore {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(self.running.is_some())
        }
        fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError> {
            self.running = config.map(str::to_owned);
            if self.trigger {
                self.fence = true;
                self.trigger = false;
            }
            Ok(())
        }
        fn check_fence(&self) -> Result<(), ActivationError> {
            if self.fence {
                Err(ActivationError::Conflict)
            } else {
                Ok(())
            }
        }
    }
    let base = std::env::temp_dir().join(format!("xkeen-fence-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, Accept, "synthetic-secret".into());
    let c = a.validate("home", &first.revision).unwrap();
    let mut core = FenceCore {
        running: None,
        fence: false,
        trigger: false,
    };
    a.apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "first")
        .unwrap();
    a.start(&base, &mut core).unwrap();
    let previous = core.running.clone();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    let c = a.validate("home", &second.revision).unwrap();
    core.trigger = true;
    assert_eq!(
        a.apply(&base, &mut core, "home", &second.revision, &c.candidate_id, "second"),
        Err(ActivationError::CommitUncertain)
    );
    core.fence = false;
    a.recover(&base, &mut core).unwrap();
    assert_eq!(core.running, previous);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn resource_admission_failure_precedes_journal_and_core_mutation() {
    struct Full;
    impl xkeen_ui::configuration::ManualCore for Full {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(false)
        }
        fn replace(&mut self, _: Option<&str>) -> Result<(), ActivationError> {
            panic!("must not touch core")
        }
        fn admit(&self, _: u64, _: u64, _: u64) -> Result<(), ActivationError> {
            Err(ActivationError::Unavailable)
        }
    }
    let base = std::env::temp_dir().join(format!("xkeen-capacity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    let candidate = activation.validate("home", &saved.revision).unwrap();
    assert_eq!(
        activation.apply(
            &base,
            &mut Full,
            "home",
            &saved.revision,
            &candidate.candidate_id,
            "capacity"
        ),
        Err(ActivationError::Unavailable)
    );
    assert!(!base.join("transaction.json").exists());
    assert!(!base.join("history").exists());
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn emergency_stop_does_not_depend_on_resource_admission() {
    struct LowMemory(bool);
    impl xkeen_ui::configuration::ManualCore for LowMemory {
        fn running(&self) -> Result<bool, ActivationError> {
            Ok(self.0)
        }
        fn replace(&mut self, config: Option<&str>) -> Result<(), ActivationError> {
            assert!(config.is_none());
            self.0 = false;
            Ok(())
        }
        fn admit(&self, _: u64, _: u64, _: u64) -> Result<(), ActivationError> {
            Err(ActivationError::Unavailable)
        }
    }
    let base = std::env::temp_dir().join(format!("xkeen-stop-low-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&base).unwrap();
    let activation = Activation::new(store, Accept, "synthetic-secret".into());
    let mut core = LowMemory(true);
    activation.emergency_stop(&mut core).unwrap();
    assert!(!core.0);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn later_manual_snapshot_keeps_existing_history() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("xkeen-history-retain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let mut profile = store.save("home", "mode: rule\n", None).unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    let mut core = Core::default();
    for (i, source) in ["mode: rule\n", "mode: direct\n", "mode: global\n"].iter().enumerate() {
        if i != 0 {
            profile = ConfigStore::new(base.join("profiles"))
                .unwrap()
                .save("home", source, Some(&profile.revision))
                .unwrap();
        }
        let candidate = activation.validate("home", &profile.revision).unwrap();
        activation
            .apply(
                &base,
                &mut core,
                "home",
                &profile.revision,
                &candidate.candidate_id,
                &format!("key-{i}"),
            )
            .unwrap();
        if i == 1 {
            let first = std::fs::read_dir(base.join("history"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let contents = std::fs::read(&first).unwrap();
            std::fs::write(base.join("first-path"), first.to_str().unwrap()).unwrap();
            std::fs::write(base.join("first-content"), contents).unwrap();
        }
    }
    let first = std::fs::read_to_string(base.join("first-path")).unwrap();
    assert_eq!(
        std::fs::read(first).unwrap(),
        std::fs::read(base.join("first-content")).unwrap()
    );
    assert_eq!(std::fs::read_dir(base.join("history")).unwrap().count(), 2);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn status_uses_small_payload_references_while_start_verifies_exact_payload() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("xkeen-payload-status-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let source = format!("# {}\nmode: rule\n", "synthetic".repeat(100_000));
    let profile = store.save("home", &source, None).unwrap();
    let mut activation = Activation::new(store, Accept, "synthetic-secret".into());
    let candidate = activation.validate("home", &profile.revision).unwrap();
    let mut core = Core::default();
    activation
        .apply(
            &base,
            &mut core,
            "home",
            &profile.revision,
            &candidate.candidate_id,
            "first",
        )
        .unwrap();
    let bytes = std::fs::read(base.join("transaction.json")).unwrap();
    assert!(bytes.len() < 16_384, "journal must contain metadata only");
    let journal: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(journal["version"], 2);
    assert!(journal["current"].get("config").is_none());
    let digest = journal["current"]["payload"]["digest"].as_str().unwrap();
    let payload = base.join("payloads").join(digest).join("config.yaml");
    std::fs::write(&payload, "damaged").unwrap();
    let status = activation.applied_status(&base).unwrap();
    assert_eq!(status.profile_id, "home");
    assert_eq!(status.revision, profile.revision);
    assert!(matches!(
        activation.verified_applied_status(&base),
        Err(ActivationError::Storage)
    ));
    assert!(
        activation.start(&base, &mut core).is_err(),
        "display is never mutation authority"
    );
    assert!(core.running.is_none());
    activation.emergency_stop(&mut core).unwrap();
    std::fs::remove_dir_all(base).unwrap();
}

/// A working router on 17.11: Apply reserved one history entry but its payload added more,
/// pushing history past the 512-entry limit. Apply now reserves its whole cost.
#[test]
fn apply_at_the_history_limit_reserves_its_whole_cost() {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let base = std::env::temp_dir().join(format!("xkeen-activation-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let history = base.join("history");
    std::fs::DirBuilder::new().mode(0o700).create(&history).unwrap();
    let dir = |path: &std::path::Path| std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    let file = |path: &std::path::Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
    };
    // 102 unattached five-entry snapshots plus one two-entry snapshot: 512.
    for index in 0..103u32 {
        let snapshot = history.join(uuid::Uuid::new_v4().to_string());
        dir(&snapshot);
        file(&snapshot.join("config.yaml"));
        if index < 102 {
            dir(&snapshot.join("assets"));
            dir(&snapshot.join("assets/providers"));
            dir(&snapshot.join("assets/providers/rules"));
        }
    }
    assert!(xkeenwrt_recovery::resources::history_size(&base).is_ok());
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    let mut a = Activation::new(store, Accept, "synthetic-secret".into());
    let c = a.validate("home", &first.revision).unwrap();
    let mut core = Core::default();
    a.apply(&base, &mut core, "home", &first.revision, &c.candidate_id, "one")
        .unwrap();
    let store = ConfigStore::new(base.join("profiles")).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    let c = a.validate("home", &second.revision).unwrap();
    a.apply(&base, &mut core, "home", &second.revision, &c.candidate_id, "two")
        .unwrap();
    assert!(
        xkeenwrt_recovery::resources::history_size(&base).is_ok(),
        "Apply must not leave history above its limit"
    );
    std::fs::remove_dir_all(base).unwrap();
}
