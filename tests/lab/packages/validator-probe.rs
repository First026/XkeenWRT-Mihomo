//! Bounded, fixed validator diagnostics in the marked disposable guest.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, process::{Command, Stdio}, thread, time::{Duration, Instant}};
fn run(cleanup: bool) -> std::io::Result<&'static str> {
    let path = format!("/tmp/xk-validator-probe-{}-{}", std::process::id(), u8::from(cleanup));
    let out = OpenOptions::new().write(true).read(true).create_new(true).open(&path)?;
    let request = if cleanup { Vec::new() } else { fs::read("/tmp/xkeenwrt-synthetic-validator-request.json")? };
    if request.len() > 1_048_576 { return Err(std::io::Error::other("request limit")); }
    let mut command = Command::new("/usr/libexec/xkeenwrt/xkeenwrt-validate");
    if cleanup { command.arg("--cleanup"); }
    command.stdin(if cleanup { Stdio::null() } else { Stdio::piped() }).stdout(Stdio::from(out)).stderr(Stdio::null());
    let mut child = command.spawn()?;
    if !cleanup {
        child.stdin.take().ok_or_else(|| std::io::Error::other("stdin"))?.write_all(&request)?;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait()? { break status; }
        if Instant::now() >= deadline {
            // Child remains unreaped, so its PID cannot have been reused.
            let _ = child.kill();
            let reap = Instant::now() + Duration::from_secs(3);
            while Instant::now() < reap { if child.try_wait()?.is_some() { break; } thread::sleep(Duration::from_millis(20)); }
            let _ = fs::remove_file(&path);
            return Ok("TIMEOUT");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut bytes = Vec::new();
    fs::File::open(&path)?.take(4097).read_to_end(&mut bytes)?;
    fs::remove_file(path)?;
    if !status.success() { return Ok("EXIT_NONZERO"); }
    if bytes.len() > 4096 { return Ok("OUTPUT_LIMIT"); }
    let text = String::from_utf8_lossy(&bytes);
    Ok(if text.contains("\"status\":\"clean\"") && text.contains("\"code\":\"CLEANUP_COMPLETE\"") { "CLEANUP_COMPLETE" }
       else if text.contains("\"status\":\"valid\"") && text.contains("\"code\":\"VALID\"") { "VALID" }
       else if text.contains("\"code\":\"SANDBOX_UNAVAILABLE\"") { "SANDBOX_UNAVAILABLE" }
       else if text.contains("\"code\":\"CORE_UNAVAILABLE\"") { "CORE_UNAVAILABLE" }
       else if text.contains("\"code\":\"WORKER_FAILED\"") { "WORKER_FAILED" }
       else if text.contains("\"code\":\"ASSETS_UNVERIFIED\"") { "ASSETS_UNVERIFIED" }
       else { "OTHER" })
}
fn main() {
    let lab = fs::read_to_string("/proc/cmdline").is_ok_and(|s| s.split_ascii_whitespace().any(|v| v == "xkeenwrt.isolation_lab=1"))
        && fs::read("/etc/xkeenwrt-isolation-lab").is_ok_and(|v| v == b"xkeenwrt-validator-lab-v1\n");
    if !lab { println!("DIAG_VALIDATOR_GUARD=DENIED"); return; }
    println!("DIAG_VALIDATOR_CLEANUP={}", run(true).unwrap_or("IO_ERROR"));
    println!("DIAG_VALIDATOR_PROTOCOL={}", run(false).unwrap_or("IO_ERROR"));
}
