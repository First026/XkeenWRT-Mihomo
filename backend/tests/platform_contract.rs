use xkeen_ui::{
    platform::Platform,
    runtime::{RuntimeCommand, RuntimeReply},
};

#[test]
fn unsupported_host_has_no_xray_fallback() {
    let info = Platform::inspect();
    assert_eq!(info.core, "mihomo");
    if !std::path::Path::new("/etc/openwrt_release").exists() {
        assert_ne!(info.platform, "openwrt");
        assert!(!info.unsupported_reasons.is_empty());
    }
}

#[test]
fn unknown_runtime_command_is_rejected() {
    assert!(serde_json::from_str::<RuntimeCommand>(r#"{"command":"shell"}"#).is_err());
}

#[test]
fn enable_is_not_ready_until_managed_validation_exists() {
    let reply = RuntimeReply::for_command(RuntimeCommand::Enable);
    assert_eq!(reply.code, "NOT_READY");
}

#[test]
fn stopped_procd_service_is_not_reported_running() {
    use xkeen_ui::platform::{ServiceStatus, parse_service_status};
    assert_eq!(parse_service_status(r#"{}"#).unwrap(), ServiceStatus::Stopped);
    assert_eq!(
        parse_service_status(r#"{"xkeenwrt-core":{"instances":{"instance1":{"running":false}}}}"#).unwrap(),
        ServiceStatus::Stopped
    );
    assert_eq!(
        parse_service_status(r#"{"xkeenwrt-core":{"instances":{"instance1":{"running":true}}}}"#).unwrap(),
        ServiceStatus::Running
    );
    assert!(parse_service_status(r#"{"xkeenwrt-core":{}}"#).is_err());
}

#[test]
fn second_runtime_cannot_acquire_lock() {
    use xkeen_ui::runtime::ipc::RuntimeLock;
    let path = std::env::temp_dir().join(format!("xkeenwrt-lock-{}", uuid::Uuid::new_v4()));
    let first = RuntimeLock::acquire(&path).unwrap();
    assert!(RuntimeLock::acquire(&path).is_err());
    drop(first);
    assert!(RuntimeLock::acquire(&path).is_ok());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn preview_refuses_existing_state_directory() {
    use std::os::unix::process::CommandExt;
    let dir = std::env::temp_dir().join(format!("xkeenwrt-existing-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let preview = || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_xkeenwrt-ui"));
        command.args(["preview", "--state-dir", dir.to_str().unwrap(), "--port", "18080"]);
        command
    };
    let mut command = preview();
    // Preview refuses root before it looks at the directory. A root runner
    // (container, sudo) proves that refusal, then checks the unprivileged
    // path as `nobody`; std drops root's supplementary groups with the uid.
    if nix::unistd::geteuid().is_root() {
        let root = preview().output().unwrap();
        assert!(!root.status.success());
        assert!(String::from_utf8_lossy(&root.stderr).contains("preview must run unprivileged"));
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
        command.uid(65534).gid(65534);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("preview state directory already exists"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn runtime_lock_rejects_hard_links_and_non_private_files() {
    use std::os::unix::fs::PermissionsExt;
    use xkeen_ui::runtime::ipc::RuntimeLock;
    let path = std::env::temp_dir().join(format!("xkeenwrt-lock-{}", uuid::Uuid::new_v4()));
    let link = path.with_extension("link");
    std::fs::write(&path, b"keep").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&path, &link).unwrap();
    assert!(RuntimeLock::acquire(&path).is_err());
    std::fs::remove_file(link).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(RuntimeLock::acquire(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    std::fs::remove_file(path).unwrap();
}

#[cfg(not(feature = "lab-hooks"))]
#[test]
fn production_feature_set_has_no_marked_lab_deployment_bypass() {
    assert!(!xkeen_ui::runtime::core::marked_lab());
}

#[test]
fn runtime_lock_rejects_fifo_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    use xkeen_ui::runtime::ipc::RuntimeLock;
    let path = std::env::temp_dir().join(format!("xkeenwrt-fifo-{}", uuid::Uuid::new_v4()));
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { nix::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(RuntimeLock::acquire(&path).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn oversized_ubus_status_is_rejected() {
    use xkeen_ui::platform::parse_service_status;
    let oversized = format!("{{\"padding\":\"{}\"}}", "x".repeat(65_536));
    assert!(parse_service_status(&oversized).is_err());
}

#[test]
fn core_launcher_refuses_unmarked_host_before_touching_paths() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_xkeenwrt-ui"))
        .args(["core-run", "9d4dc08c-6e7c-4466-a07f-135271fae513"])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn activation_requires_known_matching_installed_package_versions() {
    use xkeen_ui::platform::package_pair_matches;
    let installed = "busybox-1.37-r1\nxkeenwrt-ui-0.1-r1\nxkeenwrt-core-0.1-r1\n";
    assert!(package_pair_matches(installed, "0.1-r1"));
    assert!(!package_pair_matches(installed, "0.1-r2"));
    assert!(!package_pair_matches(
        "xkeenwrt-ui-0.1-r2\nxkeenwrt-core-0.1-r1\n",
        "0.1-r1"
    ));
    assert!(!package_pair_matches(
        "xkeenwrt-ui-0.1-r1\nxkeenwrt-ui-0.1-r1\nxkeenwrt-core-0.1-r1\n",
        "0.1-r1"
    ));
    assert!(!package_pair_matches("xkeenwrt-ui-0.1-r1\n", "0.1-r1"));
}

#[test]
fn package_manifests_must_be_identical_complete_and_version_bound() {
    use xkeen_ui::platform::package_manifests_match;
    let hash = "a".repeat(64);
    let one = format!(
        r#"{{"version":1,"build_id":"{hash}","package_version":"0.1-r1","sha256":{{"ui":"{hash}","core":"{hash}","validator":"{hash}","recovery":"{hash}","init_runtime":"{hash}","init_ui":"{hash}","init_core":"{hash}","init_recovery":"{hash}"}}}}"#
    );
    assert!(package_manifests_match(one.as_bytes(), one.as_bytes(), "0.1-r1", &hash));
    assert!(!package_manifests_match(
        one.as_bytes(),
        one.as_bytes(),
        "0.1-r2",
        &hash
    ));
    assert!(!package_manifests_match(one.as_bytes(), b"{}", "0.1-r1", &hash));
    assert!(!package_manifests_match(b"{}", b"{}", "0.1-r1", &hash));
}
