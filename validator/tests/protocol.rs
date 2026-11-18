use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn accepted_request_never_claims_validation_without_guardian() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xkeenwrt-validate"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"version":1,"config":"secret-value","assets":[]}"#)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(
        result.stdout,
        b"{\"status\":\"unavailable\",\"code\":\"SANDBOX_UNAVAILABLE\"}\n"
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("secret-value"));
}

fn run(input: &[u8]) -> Vec<u8> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xkeenwrt-validate"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap().stdout
}

#[test]
fn rejects_traversal_duplicate_assets_and_invalid_base64_without_echoing_secrets() {
    for input in [
        r#"{"version":1,"config":"secret-value","assets":[{"path":"../outside","content_base64":""}]}"#,
        r#"{"version":1,"config":"secret-value","assets":[{"path":"a","content_base64":""},{"path":"a","content_base64":""}]}"#,
        r#"{"version":1,"config":"secret-value","assets":[{"path":"a","content_base64":"***"}]}"#,
    ] {
        assert_eq!(
            run(input.as_bytes()),
            b"{\"status\":\"invalid\",\"code\":\"INVALID_REQUEST\"}\n"
        );
    }
}

#[test]
fn rejects_oversized_config_and_unknown_fields() {
    let oversized = format!(
        "{{\"version\":1,\"config\":\"{}\",\"assets\":[]}}",
        "x".repeat(1024 * 1024 + 1)
    );
    for input in [
        oversized.as_bytes(),
        br#"{"version":1,"config":"","assets":[],"core":"/tmp/evil"}"#,
    ] {
        assert_eq!(
            run(input),
            b"{\"status\":\"invalid\",\"code\":\"INVALID_REQUEST\"}\n"
        );
    }
}

#[test]
fn input_deadline_does_not_require_requester_to_close_pipe() {
    let child = Command::new(env!("CARGO_BIN_EXE_xkeenwrt-validate"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    // wait_with_output closes stdin itself; use explicit retained pipe below instead.
    assert_eq!(
        output.stdout,
        b"{\"status\":\"invalid\",\"code\":\"INVALID_REQUEST\"}\n"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_xkeenwrt-validate"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _open_pipe = child.stdin.take().unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.stdout,
        b"{\"status\":\"unavailable\",\"code\":\"INPUT_TIMEOUT\"}\n"
    );
}

#[test]
fn typed_overlay_accepts_manual_and_rejects_unknown_variants() {
    assert_eq!(
        run(br#"{"version":1,"config":"","assets":[],"overlay":{"mode":"manual"}}"#),
        b"{\"status\":\"unavailable\",\"code\":\"SANDBOX_UNAVAILABLE\"}\n"
    );
    assert_eq!(
        run(br#"{"version":1,"config":"","assets":[],"overlay":{"mode":"other"}}"#),
        b"{\"status\":\"invalid\",\"code\":\"INVALID_REQUEST\"}\n"
    );
}

#[test]
fn cleanup_command_refuses_unmarked_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_xkeenwrt-validate"))
        .arg("--cleanup")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        output.stdout,
        b"{\"status\":\"unavailable\",\"code\":\"SANDBOX_UNAVAILABLE\"}\n"
    );
}
