//! Deployment and lab identity checks before writes or privileged syscalls.
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub fn marked_guest() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    // The UI package provisions this root-only gate for isolated validation.
    let mut deployment = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/etc/xkeenwrt-validator-enabled")
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    let meta = match deployment.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 23
    {
        return false;
    }
    let mut contents = Vec::new();
    if deployment.read_to_end(&mut contents).is_err() || contents != b"xkeenwrt-validation-v1\n" {
        return false;
    }
    let release = match fs::read_to_string("/etc/openwrt_release") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !release
        .lines()
        .any(|line| line == "DISTRIB_RELEASE='25.12.6'")
    {
        return false;
    }
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }
    unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_bytes() == b"6.12.112"
}

#[cfg(feature = "lab-faults")]
pub fn marked_lab_guest() -> bool {
    let cmdline = match fs::read_to_string("/proc/cmdline") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !cmdline
        .split_ascii_whitespace()
        .any(|word| word == "xkeenwrt.isolation_lab=1")
    {
        return false;
    }
    let mut marker = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/etc/xkeenwrt-isolation-lab")
    {
        Ok(file) => file,
        Err(_) => return false,
    };
    let meta = match marker.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() != 26 {
        return false;
    }
    let mut contents = Vec::new();
    if marker.read_to_end(&mut contents).is_err() || contents != b"xkeenwrt-validator-lab-v1\n" {
        return false;
    }
    true
}
