use xkeen_ui::runtime::networking::compatibility::{Application, Inputs, evaluate};
use xkeenwrt_recovery::topology::Severity;
#[test]
fn report_collects_independent_blockers_without_mutating_or_short_circuiting() {
    let input = Inputs::default();
    let application = Application {
        journal_readable: true,
        packages_verified: false,
        rescue_verified: false,
        accepted_profile: false,
        resources: xkeen_ui::runtime::networking::compatibility::Forecast {
            unavailable: true,
            ..Default::default()
        },
        lifecycle_clear: false,
    };
    let report = evaluate(
        &input,
        &application,
        "192.0.2.101".parse::<std::net::Ipv4Addr>().unwrap(),
        None,
    );
    assert!(!report.ready);
    let codes: Vec<_> = report.issues.iter().map(|i| i.code).collect();
    for expected in [
        "NETWORK_PACKAGES",
        "NETWORK_RECOVERY",
        "PROFILE_REQUIRED",
        "NETWORK_RESOURCES",
        "NETWORK_LAN",
        "NETWORK_MODULES_MISSING",
        "NETWORK_FIREWALL_UNAVAILABLE",
        "NETWORK_DNS_UNSUPPORTED",
        "NETWORK_RULES_UNAVAILABLE",
        "NETWORK_ROUTES_UNAVAILABLE",
        "NETWORK_LISTENERS_UNAVAILABLE",
        "FLOWTABLE_METADATA_UNAVAILABLE",
    ] {
        assert!(codes.contains(&expected), "missing independent {expected}: {codes:?}");
    }
    assert!(report.issues.iter().all(|i| i.severity == Severity::Blocker));
    assert_eq!(report.truncated, 0);
}

#[test]
fn corrupt_durable_journal_is_the_same_storage_prerequisite_for_check_and_start() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("xkeen-report-journal-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("recovery.json");
    std::fs::write(&path, b"corrupt").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let observed = xkeen_ui::runtime::networking::compatibility::network_journal(&root);
    assert!(observed.is_err());
    let app = Application {
        packages_verified: true,
        rescue_verified: true,
        accepted_profile: true,
        resources: Default::default(),
        lifecycle_clear: true,
        journal_readable: observed.is_ok(),
    };
    let report = evaluate(
        &Inputs::default(),
        &app,
        "192.0.2.101".parse::<std::net::Ipv4Addr>().unwrap(),
        None,
    );
    assert!(report.issues.iter().any(|i| i.code == "NETWORK_STORAGE"));
    assert!(!report.ready);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn report_and_start_use_the_same_exhausted_allocation_ranges() {
    use xkeen_ui::network::allocation_candidates;
    assert!(
        allocation_candidates(&(100..=252).collect::<Vec<_>>(), &[], &[])
            .0
            .is_none()
    );
    assert!(
        allocation_candidates(&[], &[], &(10000..=32000).collect::<Vec<_>>())
            .2
            .is_none()
    );
    assert!(allocation_candidates(&[], &[(u32::MAX, u32::MAX)], &[]).1.is_none());
    let mut raw = Inputs {
        rules4: serde_json::to_vec(
            &(100..=252)
                .map(|table| serde_json::json!({"priority":table,"src":"all","table":table}))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
        rules6: b"[]".to_vec(),
        routes4: b"[]".to_vec(),
        routes6: b"[]".to_vec(),
        nft: br#"{"nftables":[]}"#.to_vec(),
        ..Inputs::default()
    };
    let app = Application {
        packages_verified: true,
        rescue_verified: true,
        accepted_profile: true,
        resources: Default::default(),
        lifecycle_clear: true,
        journal_readable: true,
    };
    let report = evaluate(&raw, &app, "192.0.2.101".parse::<std::net::Ipv4Addr>().unwrap(), None);
    assert!(report.issues.iter().any(|i| i.code == "NETWORK_TABLE_CONFLICT"));
    raw.rules4 = serde_json::to_vec(
        &(10000..=32000)
            .map(|priority| serde_json::json!({"priority":priority,"src":"all","table":254}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    // The bounded kernel inventory limit is also a prerequisite; never promise
    // free resources after truncating a 21,001-rule table to a successful sample.
    let report = evaluate(&raw, &app, "192.0.2.101".parse::<std::net::Ipv4Addr>().unwrap(), None);
    assert!(
        report
            .issues
            .iter()
            .any(|i| ["NETWORK_PRIORITY_CONFLICT", "NETWORK_RULES_UNAVAILABLE"].contains(&i.code))
    );
}

#[test]
fn resource_shortages_name_their_resource_with_numbers_and_cleanup_only_warns() {
    use xkeen_ui::runtime::networking::compatibility::{Forecast, Shortage};
    let application = |resources: Forecast| Application {
        journal_readable: true,
        packages_verified: true,
        rescue_verified: true,
        accepted_profile: true,
        resources,
        lifecycle_clear: true,
    };
    let peer = "192.0.2.101".parse::<std::net::Ipv4Addr>().unwrap();
    let short = application(Forecast {
        shortages: vec![Shortage::Memory {
            available_mib: 243,
            reclaimable_mib: 0,
            required_mib: 256,
        }],
        ..Default::default()
    });
    let report = evaluate(&Inputs::default(), &short, peer, None);
    let memory = report
        .issues
        .iter()
        .find(|i| i.code == "NETWORK_MEMORY")
        .expect("memory blocker");
    assert_eq!(memory.severity, Severity::Blocker);
    let json = serde_json::to_value(memory).unwrap();
    assert_eq!(json["detail"]["available_mib"], 243);
    assert_eq!(json["detail"]["required_mib"], 256);
    assert!(!report.issues.iter().any(|i| i.code == "NETWORK_RESOURCES"));

    let cleanup = application(Forecast {
        cleanup_entries: 48,
        ..Default::default()
    });
    let report = evaluate(&Inputs::default(), &cleanup, peer, None);
    let warning = report
        .issues
        .iter()
        .find(|i| i.code == "NETWORK_HISTORY_CLEANUP")
        .expect("cleanup warning");
    assert_eq!(warning.severity, Severity::Warning);
    assert_eq!(serde_json::to_value(warning).unwrap()["detail"]["cleanup_entries"], 48);
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.check == "resources" && i.severity == Severity::Blocker)
    );
}

#[test]
fn tailscale_start_needs_the_current_overlay_boundary_and_a_peer_outside_the_lan() {
    use xkeen_ui::management::ManagementPeer;
    use xkeen_ui::runtime::networking::compatibility::management_allowed;
    let scope = Some("192.168.5.0/24");
    let router = "192.168.5.1".parse().unwrap();
    let boundary = Some("100.64.10.1".parse().unwrap());
    let overlay = ManagementPeer::Tailscale {
        peer: "100.64.20.2".parse().unwrap(),
        router: "100.64.10.1".parse().unwrap(),
    };
    assert!(management_allowed(scope, router, overlay, boundary));
    // The listener's address no longer matches tailscale0: refuse.
    assert!(!management_allowed(
        scope,
        router,
        overlay,
        Some("100.64.10.2".parse().unwrap())
    ));
    assert!(!management_allowed(scope, router, overlay, None));
    assert!(!management_allowed(None, router, overlay, boundary));
    // LAN peers keep the r26 rule and need no overlay.
    let lan = ManagementPeer::Lan {
        peer: "192.168.5.236".parse().unwrap(),
    };
    assert!(management_allowed(scope, router, lan, None));
    let lan_cgnat = ManagementPeer::Lan {
        peer: "100.64.20.2".parse().unwrap(),
    };
    assert!(!management_allowed(scope, router, lan_cgnat, boundary));
}

#[test]
fn over_tailscale_only_the_gateway_restarts_and_http_socks_stays_lan_only() {
    use xkeen_ui::management::ManagementPeer;
    use xkeen_ui::runtime::networking::compatibility::{explicit_allowed, restart_allowed};
    let scope = Some("192.168.5.0/24");
    let router = "192.168.5.1".parse().unwrap();
    let boundary = Some("100.64.10.1".parse().unwrap());
    let overlay = ManagementPeer::Tailscale {
        peer: "100.64.20.2".parse().unwrap(),
        router: "100.64.10.1".parse().unwrap(),
    };
    let lan = ManagementPeer::Lan {
        peer: "192.168.5.236".parse().unwrap(),
    };
    // Gateway only: allowed over Tailscale with a current boundary.
    assert!(restart_allowed(scope, router, overlay, boundary, false));
    assert!(!restart_allowed(scope, router, overlay, None, false), "stale boundary");
    // HTTP/SOCKS selected: refused over Tailscale before anything stops.
    assert!(!restart_allowed(scope, router, overlay, boundary, true));
    // The LAN keeps r26 behaviour for both selections.
    assert!(restart_allowed(scope, router, lan, None, true));
    assert!(restart_allowed(scope, router, lan, None, false));
    assert!(explicit_allowed(lan));
    assert!(!explicit_allowed(overlay));
}
