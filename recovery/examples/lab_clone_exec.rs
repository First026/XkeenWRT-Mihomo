//! Test-only child for no-NIC VM; install as lab-clone-probe only in fixture.
fn main() {
    use std::io::Write;
    let marker = std::fs::read_to_string("/etc/xkeenwrt-isolation-lab").unwrap_or_default();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    assert!(
        unsafe { libc::geteuid() } == 0
            && marker.trim() == "xkeenwrt-validator-lab-v1"
            && cmdline
                .split_whitespace()
                .any(|s| s == "xkeenwrt.isolation_lab=1")
    );
    if std::env::args().nth(1).as_deref() == Some("postexec") {
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/tmp/xkeenwrt-lab-clone-executed")
        .unwrap();
    f.write_all(b"executed\n").unwrap();
}
