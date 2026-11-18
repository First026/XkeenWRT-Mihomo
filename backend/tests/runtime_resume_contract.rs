use xkeen_ui::runtime::{RuntimeCommand, RuntimeReply};

const REQUEST: &str = "00000000-0000-4000-8000-000000000002";

#[test]
fn explicit_resume_ipc_carries_only_the_exact_request_id() {
    let command = RuntimeCommand::ResumeAfterReinstall {
        request_id: REQUEST.into(),
    };
    let value = serde_json::to_value(command).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "command": "resume_after_reinstall",
            "request_id": REQUEST,
        })
    );
    assert!(
        serde_json::from_value::<RuntimeCommand>(serde_json::json!({
            "command": "resume_after_reinstall",
            "request_id": REQUEST,
            "path": "/etc/xkeenwrt/removal.json",
        }))
        .is_err()
    );
}

#[test]
fn candidate_cancellation_is_bound_to_one_profile_revision_and_candidate() {
    let command = RuntimeCommand::CancelCandidate {
        profile_id: "home".into(),
        revision: "revision".into(),
        candidate_id: "candidate".into(),
    };
    assert_eq!(
        serde_json::to_value(command).unwrap(),
        serde_json::json!({
            "command": "cancel_candidate",
            "profile_id": "home",
            "revision": "revision",
            "candidate_id": "candidate",
        })
    );
}

#[test]
fn status_ipc_keeps_resume_request_separate_from_unknown_core_state() {
    let mut status = RuntimeReply::error("OK", "unknown");
    status.resume_request_id = Some(REQUEST.into());
    status.capabilities = Some(vec![xkeen_ui::runtime::RuntimeCapability::CoreControl]);
    status.running = None;
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        serde_json::json!({
            "code": "OK",
            "message": "unknown",
            "resume_request_id": REQUEST,
            "capabilities": ["core_control"],
        })
    );
}
