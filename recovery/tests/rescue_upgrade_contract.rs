use xkeenwrt_recovery::rescue::{UpgradeIntent, UpgradePhase, UpgradeSpec};

fn spec() -> UpgradeSpec {
    UpgradeSpec {
        owner_id: "00000000-0000-4000-8000-000000000001".into(),
        request_id: "00000000-0000-4000-8000-000000000002".into(),
        old_sha256: "a".repeat(64),
        old_build_id: "b".repeat(64),
        new_sha256: "c".repeat(64),
        new_build_id: "d".repeat(64),
    }
}
#[test]
fn upgrade_identity_is_strict_and_distinguishes_builds() {
    let s = spec();
    assert!(s.valid());
    let mut same = s.clone();
    same.new_sha256 = s.old_sha256.clone();
    same.new_build_id = s.old_build_id.clone();
    assert!(!same.valid());
    let mut bad = s.clone();
    bad.request_id = "../../foreign".into();
    assert!(!bad.valid());
    let mut bad = s;
    bad.new_sha256 = "A".repeat(64);
    assert!(!bad.valid());
}
#[test]
fn durable_intent_is_typed_and_rejects_unknown_fields() {
    let i = UpgradeIntent {
        version: 1,
        spec: spec(),
        phase: UpgradePhase::Finalizing,
    };
    let bytes = serde_json::to_vec(&i).unwrap();
    assert_eq!(serde_json::from_slice::<UpgradeIntent>(&bytes).unwrap(), i);
    let mut value = serde_json::to_value(i).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("command".into(), "sh".into());
    assert!(serde_json::from_value::<UpgradeIntent>(value).is_err());
}
