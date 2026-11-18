use xkeen_ui::configuration::{ConfigError, ConfigStore};

fn store() -> (std::path::PathBuf, ConfigStore) {
    let root = std::env::temp_dir().join(format!("xkeen-config-test-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    (root, store)
}

#[test]
fn invalid_edit_and_stale_revision_preserve_source() {
    let (root, store) = store();
    let source = "# preserved comment\nproxies: []\n";
    let saved = store.save("home", source, None).unwrap();
    assert!(matches!(
        store.save("home", "proxies: [", Some(&saved.revision)),
        Err(ConfigError::InvalidYaml)
    ));
    assert!(matches!(
        store.save("home", "proxies: []\n", Some("stale")),
        Err(ConfigError::Conflict)
    ));
    let current = store.read("home").unwrap();
    assert_eq!(current.source, source);
    assert_eq!(current.revision, saved.revision);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn profile_lifecycle_and_preparation_gate() {
    let (root, store) = store();
    let first = store.save("home", "mode: rule\n", None).unwrap();
    assert_eq!(store.list().unwrap(), vec!["home"]);
    assert_eq!(store.delete("home", &first.revision), Err(ConfigError::InvalidId));
    store.save("config", "mode: rule\n", None).unwrap();
    let second = store.save("home", "mode: direct\n", Some(&first.revision)).unwrap();
    assert_ne!(first.revision, second.revision);
    assert_eq!(store.delete("home", &first.revision), Err(ConfigError::Conflict));
    assert_eq!(store.read("home").unwrap().source, "mode: direct\n");
    store.delete("home", &second.revision).unwrap();
    assert_eq!(store.list().unwrap(), vec!["config"]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsafe_names_symlinks_and_oversized_input() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (root, store) = store();
    assert_eq!(store.save("../outside", "a: b", None), Err(ConfigError::InvalidId));
    assert_eq!(
        store.save("big", &"x".repeat(xkeen_ui::configuration::MAX_PROFILE_BYTES + 1), None),
        Err(ConfigError::TooLarge)
    );
    let outside = root.with_extension("outside");
    std::fs::write(&outside, "unrelated").unwrap();
    symlink(&outside, root.join("link.yaml")).unwrap();
    assert_eq!(store.read("link"), Err(ConfigError::UnsafePath));
    assert_eq!(store.save("link", "a: b", None), Err(ConfigError::UnsafePath));
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "unrelated");
    std::fs::remove_file(root.join("link.yaml")).unwrap();
    store.save("private", "a: b\n", None).unwrap();
    assert_eq!(
        std::fs::metadata(root.join("private.yaml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    std::fs::remove_file(outside).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn renamed_store_cannot_follow_replacement_directory() {
    use std::os::unix::fs::symlink;
    let (root, store) = store();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let moved = root.with_extension("moved");
    let outside = root.with_extension("outside");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("home.yaml"), "external").unwrap();
    symlink(&outside, &root).unwrap();
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_file(root).unwrap();
    std::fs::remove_dir_all(moved).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}

#[test]
fn fifo_and_hard_link_are_rejected() {
    use std::os::unix::ffi::OsStrExt;
    let (root, store) = store();
    let path = root.join("pipe.yaml");
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { nix::libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert_eq!(store.read("pipe"), Err(ConfigError::UnsafePath));
    std::fs::remove_file(path).unwrap();
    store.save("one", "mode: rule\n", None).unwrap();
    std::fs::hard_link(root.join("one.yaml"), root.join("two.yaml")).unwrap();
    assert_eq!(store.read("one"), Err(ConfigError::UnsafePath));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn two_stores_reject_stale_writes_and_busy_locks() {
    use std::os::fd::AsRawFd;
    let (root, first) = store();
    let second = ConfigStore::new(&root).unwrap();
    let original = first.save("home", "mode: rule\n", None).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".lock"))
        .unwrap();
    assert_eq!(
        unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) },
        0
    );
    assert_eq!(second.read("home"), Err(ConfigError::Busy));
    assert_eq!(unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_UN) }, 0);
    first.save("home", "mode: direct\n", Some(&original.revision)).unwrap();
    assert_eq!(
        second.save("home", "mode: global\n", Some(&original.revision)),
        Err(ConfigError::Conflict)
    );
    assert_eq!(second.read("home").unwrap().source, "mode: direct\n");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn excessively_nested_yaml_is_rejected_without_losing_profile() {
    let (root, store) = store();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let nested = format!("a: {}0{}\n", "[".repeat(100), "]".repeat(100));
    assert_eq!(
        store.save("home", &nested, Some(&saved.revision)),
        Err(ConfigError::InvalidYaml)
    );
    assert_eq!(store.read("home").unwrap(), saved);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn total_quota_rejects_edit_without_changing_existing_profile() {
    let (root, store) = store();
    let large = format!("a: {}\n", "x".repeat(1_047_995));
    for id in ["one", "two", "three", "four"] {
        store.save(id, &large, None).unwrap();
    }
    let original = store.save("small", "mode: rule\n", None).unwrap();
    let larger = format!("a: {}\n", "x".repeat(5000));
    assert_eq!(
        store.save("small", &larger, Some(&original.revision)),
        Err(ConfigError::LimitReached)
    );
    assert_eq!(store.read("small").unwrap(), original);
    std::fs::remove_dir_all(root).unwrap();
}
