//! Test-only VM fixture. Build with `--features lab-hooks`; never package.
#[cfg(not(feature = "lab-hooks"))]
fn main() {
    panic!("lab-hooks required");
}
#[cfg(feature = "lab-hooks")]
fn main() {
    use std::{
        fs::OpenOptions,
        io::Write,
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        time::Duration,
    };
    let marker = std::fs::read_to_string("/etc/xkeenwrt-isolation-lab").unwrap_or_default();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    assert!(
        unsafe { libc::geteuid() } == 0
            && marker.trim() == "xkeenwrt-validator-lab-v1"
            && cmdline
                .split_whitespace()
                .any(|s| s == "xkeenwrt.isolation_lab=1")
    );
    let mode = std::env::args().nth(1).unwrap_or_default();
    assert!(
        [
            "preclose",
            "postexec",
            "fail_enosys",
            "fail_einval",
            "fail_eperm"
        ]
        .contains(&mode.as_str())
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/var/run/xkeenwrt-lab-clone.lock")
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/sys/fs/cgroup/xkeenwrt-lab/clone3")
        .unwrap();
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    println!("PARENT_READY");
    std::io::stdout().flush().unwrap();
    let result = xkeenwrt_recovery::run_fixed_in_cgroup(
        xkeenwrt_recovery::FixedProgram::LabProbe,
        &[mode.clone()],
        dir.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        null.as_raw_fd(),
        Duration::from_secs(25),
    );
    match mode.as_str() {
        "fail_enosys" => assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSYS)),
        "fail_einval" => assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EINVAL)),
        "fail_eperm" => assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM)),
        _ => panic!("fault controller should terminate parent"),
    }
    println!("FAIL_CLOSED_OK");
}
