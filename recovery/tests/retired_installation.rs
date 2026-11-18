use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use xkeenwrt_recovery::{LifecycleKind, LifecycleRequest, LifecycleState};
const OWNER: &str = "00000000-0000-4000-8000-000000000001";
const REQUEST: &str = "00000000-0000-4000-8000-000000000002";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        // Parallel tests share the pid and a coarse clock may repeat the
        // nanoseconds; the counter keeps every fixture directory distinct.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "xkeen-retire-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let data = root.join("xkeenwrt");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            ("owner-id", OWNER.as_bytes().to_vec()),
            (
                "network-never-enabled",
                b"xkeenwrt-no-network-v1\n".to_vec(),
            ),
            (
                "config.yaml",
                b"mode: rule\nrules: [MATCH,DIRECT]\n".to_vec(),
            ),
            (
                "removal.json",
                serde_json::to_vec(&LifecycleRequest {
                    version: 1,
                    owner_id: OWNER.into(),
                    request_id: Some(REQUEST.into()),
                    kind: LifecycleKind::Remove,
                    state: LifecycleState::CleanupComplete,
                })
                .unwrap(),
            ),
        ] {
            fs::write(data.join(name), bytes).unwrap();
            fs::set_permissions(data.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(root)
    }
    fn data(&self) -> PathBuf {
        self.0.join("xkeenwrt")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn finalized_remove_is_archived_whole_and_cannot_retire_a_new_installation() {
    let f = Fixture::new();
    let before = fs::read(f.data().join("removal.json")).unwrap();
    let archived =
        xkeenwrt_recovery::retirement::archive_finalized_remove(&f.data(), OWNER, REQUEST).unwrap();
    assert!(!f.data().exists());
    assert_eq!(archived, f.0.join(format!("xkeenwrt-retired-{REQUEST}")));
    assert_eq!(fs::read(archived.join("removal.json")).unwrap(), before);
    assert_eq!(
        fs::read(archived.join("config.yaml")).unwrap(),
        b"mode: rule\nrules: [MATCH,DIRECT]\n"
    );
    // Retrying after the persistent rename (including a lost response) is read-only.
    assert_eq!(
        xkeenwrt_recovery::retirement::archive_finalized_remove(&f.data(), OWNER, REQUEST).unwrap(),
        archived
    );
    assert_eq!(
        xkeenwrt_recovery::retirement::completed_archive(&f.data(), REQUEST).unwrap(),
        Some(archived.clone())
    );
    fs::create_dir(f.data()).unwrap();
    fs::set_permissions(f.data(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(f.data().join("new-installation"), b"untouched").unwrap();
    assert!(
        xkeenwrt_recovery::retirement::archive_finalized_remove(&f.data(), OWNER, REQUEST).is_err()
    );
    assert_eq!(
        fs::read(f.data().join("new-installation")).unwrap(),
        b"untouched"
    );
}

#[test]
fn archive_refuses_unfinished_rescue_wrong_request_or_existing_destination() {
    for blocker in [
        "rescue",
        "lifecycle.json",
        ".rescue-next",
        "rescue-previous-00000000-0000-4000-8000-000000000003",
    ] {
        let f = Fixture::new();
        fs::write(f.data().join(blocker), b"do not touch").unwrap();
        assert!(
            xkeenwrt_recovery::retirement::archive_finalized_remove(&f.data(), OWNER, REQUEST)
                .is_err()
        );
        assert!(f.data().join("removal.json").exists());
    }
    let f = Fixture::new();
    assert!(
        xkeenwrt_recovery::retirement::archive_finalized_remove(
            &f.data(),
            OWNER,
            "00000000-0000-4000-8000-000000000099"
        )
        .is_err()
    );
    let target = f.0.join(format!("xkeenwrt-retired-{REQUEST}"));
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"foreign").unwrap();
    assert!(
        xkeenwrt_recovery::retirement::archive_finalized_remove(&f.data(), OWNER, REQUEST).is_err()
    );
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"foreign");
    assert!(f.data().join("config.yaml").exists());
}
