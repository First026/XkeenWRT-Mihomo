//! Fixed diagnostic probe; only runs inside the no-NIC lab guest.
use std::{fs, io::{Read, Write}, net::Shutdown, os::unix::net::UnixStream, time::Duration};
fn main() {
    let outcome = (|| -> std::io::Result<(&'static str, &'static str)> {
        if !fs::read_to_string("/proc/cmdline")?.split_ascii_whitespace().any(|x| x == "xkeenwrt.isolation_lab=1")
            || fs::read("/etc/xkeenwrt-isolation-lab")? != b"xkeenwrt-validator-lab-v1\n" {
            return Err(std::io::Error::other("not a lab guest"));
        }
        let saved = fs::read_to_string("/tmp/xkeenwrt-synthetic-revision").unwrap_or_default();
        let value = saved.trim();
        let valid = value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
        let (kind, revision) = if valid { ("exact", value) } else { ("dummy", "00000000-0000-4000-8000-000000000000") };
        let request = format!(r#"{{"command":"validate","profile_id":"home","revision":"{revision}"}}"#);
        let mut stream = UnixStream::connect("/var/run/xkeenwrt/control.sock")?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;
        let mut data = Vec::new();
        stream.take(4097).read_to_end(&mut data)?;
        let reply = String::from_utf8_lossy(&data);
        Ok((kind, if reply.contains("Runtime deployment is not enabled") { "DEPLOYMENT_DISABLED" }
           else if reply.contains("Required validation or core service unavailable") { "VALIDATOR_UNAVAILABLE" }
           else if reply.contains("\"code\":\"CONFLICT\"") { "READY_CONFLICT" }
           else if reply.contains("\"code\":\"PACKAGE_MISMATCH\"") { "PACKAGE_MISMATCH" }
           else if reply.contains("\"code\":\"RESCUE_NOT_READY\"") { "RESCUE_NOT_READY" }
           else if reply.contains("\"code\":\"OK\"") { "OK" }
           else { "OTHER" }))
    })();
    let (kind, class) = outcome.unwrap_or(("unknown", "IO_ERROR"));
    println!("DIAG_IPC_REVISION={kind}");
    println!("DIAG_IPC_CLASS={class}");
}
