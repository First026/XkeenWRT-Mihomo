use std::os::unix::fs::{MetadataExt, PermissionsExt};
use xkeen_ui::private_file::publish_private;

#[test]
fn published_file_is_complete_private_and_never_overwrites() {
    let dir = std::env::temp_dir().join(format!("xkeenwrt-publish-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("secret");
    publish_private(&path, b"complete secret").unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.nlink(), 1);
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_eq!(std::fs::read(&path).unwrap(), b"complete secret");
    assert!(publish_private(&path, b"replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"complete secret");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn orphaned_staging_does_not_block_publication() {
    let dir = std::env::temp_dir().join(format!("xkeenwrt-publish-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join(".xkeenwrt-secret-interrupted"), b"partial").unwrap();
    let path = dir.join("secret");
    publish_private(&path, b"complete").unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"complete");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bootstrap_restart_reuses_complete_token_and_rejects_bad_final_file() {
    use xkeen_ui::private_file::load_or_create_bootstrap;
    let dir = std::env::temp_dir().join(format!("xkeenwrt-token-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join(".xkeenwrt-secret-interrupted"), b"partial").unwrap();
    let path = dir.join("bootstrap-token");
    let token = load_or_create_bootstrap(&path).unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(load_or_create_bootstrap(&path).unwrap(), token);
    assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
    std::fs::write(&path, b"partial").unwrap();
    assert!(load_or_create_bootstrap(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"partial");
    std::fs::remove_dir_all(dir).unwrap();
}
