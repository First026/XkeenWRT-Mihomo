use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use xkeenwrt_recovery::{LifecycleKind, LifecycleRequest, LifecycleState};

const OWNER: &str = "00000000-0000-4000-8000-000000000001";
const REQUEST: &str = "00000000-0000-4000-8000-000000000002";

struct Fixture(PathBuf);
impl Fixture {
    fn new(request: LifecycleRequest) -> Self {
        let stem = format!(
            "xkeen-remove-resume-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = (0..64)
            .find_map(|suffix| {
                let path = std::env::temp_dir().join(format!("{stem}-{suffix}"));
                match fs::create_dir(&path) {
                    Ok(()) => Some(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("unable to create lifecycle fixture: {error}"),
                }
            })
            .expect("unique lifecycle fixture path");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self::private_file(
            &dir.join("removal.json"),
            &serde_json::to_vec(&request).unwrap(),
        );
        Self::private_file(
            &dir.join("network-never-enabled"),
            b"xkeenwrt-no-network-v1\n",
        );
        Self(dir)
    }

    fn private_file(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn receipt(kind: LifecycleKind, state: LifecycleState) -> LifecycleRequest {
    LifecycleRequest {
        version: 1,
        owner_id: OWNER.into(),
        request_id: Some(REQUEST.into()),
        kind,
        state,
    }
}

#[test]
fn resume_receipt_requires_exact_completed_remove_and_consumes_only_that_request() {
    let fixture = Fixture::new(receipt(
        LifecycleKind::Remove,
        LifecycleState::CleanupComplete,
    ));

    assert!(
        xkeenwrt_recovery::verify_remove_after_integrity_check(&fixture.0, OWNER, REQUEST).is_ok()
    );
    assert!(
        xkeenwrt_recovery::verify_remove_after_integrity_check(
            &fixture.0,
            OWNER,
            "00000000-0000-4000-8000-000000000099"
        )
        .is_err()
    );
    assert!(fixture.0.join("removal.json").exists());

    let bytes_before = fs::read(fixture.0.join("removal.json")).unwrap();
    assert_eq!(
        xkeenwrt_recovery::completed_remove_request_id(&fixture.0, OWNER).unwrap(),
        Some(REQUEST.to_owned())
    );
    assert_eq!(
        fs::read(fixture.0.join("removal.json")).unwrap(),
        bytes_before
    );

    xkeenwrt_recovery::finish_remove_after_integrity_check(&fixture.0, OWNER, REQUEST).unwrap();
    assert!(!fixture.0.join("removal.json").exists());
    assert!(
        xkeenwrt_recovery::finish_remove_after_integrity_check(&fixture.0, OWNER, REQUEST).is_err()
    );
}

#[test]
fn upgrade_or_pending_receipt_is_never_consumed_as_remove_resume() {
    for value in [
        receipt(LifecycleKind::Upgrade, LifecycleState::CleanupComplete),
        receipt(LifecycleKind::Remove, LifecycleState::Requested),
    ] {
        let fixture = Fixture::new(value);
        assert!(
            xkeenwrt_recovery::verify_remove_after_integrity_check(&fixture.0, OWNER, REQUEST)
                .is_err()
        );
        assert!(
            xkeenwrt_recovery::finish_remove_after_integrity_check(&fixture.0, OWNER, REQUEST)
                .is_err()
        );
        assert!(fixture.0.join("removal.json").exists());
        assert_eq!(
            xkeenwrt_recovery::completed_remove_request_id(&fixture.0, OWNER).unwrap(),
            None
        );
    }
}

#[test]
fn absent_remove_receipt_does_not_advertise_resume() {
    let fixture = Fixture::new(receipt(
        LifecycleKind::Remove,
        LifecycleState::CleanupComplete,
    ));
    fs::remove_file(fixture.0.join("removal.json")).unwrap();
    assert_eq!(
        xkeenwrt_recovery::completed_remove_request_id(&fixture.0, OWNER).unwrap(),
        None
    );
}

#[test]
fn remove_ready_is_separate_and_bound_to_owner_request_boot_and_executable() {
    let ready = xkeenwrt_recovery::RemoveResumeReady {
        version: 1,
        request_id: REQUEST.into(),
        supervisor: xkeenwrt_recovery::SupervisorIdentity {
            version: 1,
            owner_id: OWNER.into(),
            nonce: "00000000-0000-4000-8000-000000000003".into(),
            pid: 123,
            starttime: 456,
            boot_id: "00000000-0000-4000-8000-000000000004".into(),
            exe_sha256: "a".repeat(64),
        },
    };
    let bytes = serde_json::to_vec(&ready).unwrap();
    assert_eq!(
        serde_json::from_slice::<xkeenwrt_recovery::RemoveResumeReady>(&bytes).unwrap(),
        ready
    );
    assert!(ready.valid_for(
        OWNER,
        REQUEST,
        "00000000-0000-4000-8000-000000000004",
        &"a".repeat(64)
    ));
    assert!(!ready.valid_for(
        OWNER,
        "00000000-0000-4000-8000-000000000099",
        "00000000-0000-4000-8000-000000000004",
        &"a".repeat(64)
    ));
    assert!(!ready.valid_for(
        OWNER,
        REQUEST,
        "00000000-0000-4000-8000-000000000099",
        &"a".repeat(64)
    ));
    assert!(!ready.valid_for(
        OWNER,
        REQUEST,
        "00000000-0000-4000-8000-000000000004",
        &"b".repeat(64)
    ));
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("command".into(), "shell".into());
    assert!(serde_json::from_value::<xkeenwrt_recovery::RemoveResumeReady>(unknown).is_err());
}
