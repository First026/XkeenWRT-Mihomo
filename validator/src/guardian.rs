//! Guardian owns admission and cleanup, outside the job cgroup.
use crate::{child, ChildFds, Request};
use std::fs::{self, OpenOptions};
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    io::AsRawFd,
};
use std::path::Path;
use std::time::{Duration, Instant};

const ROOT: &str = "/tmp/xkeenwrt-validation";
const CG: &str = "/sys/fs/cgroup/xkeenwrt-validation";
fn write(path: &str, data: &str) -> bool {
    fs::write(path, data).is_ok()
}
fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}
fn headroom() -> bool {
    let Some(info) = read("/proc/meminfo") else {
        return false;
    };
    let mut values = info
        .lines()
        .filter_map(|line| line.strip_prefix("MemAvailable:"))
        .filter_map(|s| {
            let mut parts = s.split_whitespace();
            let n = parts.next()?.parse::<u64>().ok()?;
            if parts.next()? != "kB" || parts.next().is_some() {
                return None;
            }
            Some(n)
        });
    matches!((values.next(), values.next()), (Some(n), None) if n >= 131_072)
}
fn dir(path: &str) -> bool {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return false,
    }
    let Ok(m) = fs::symlink_metadata(path) else {
        return false;
    };
    m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700
}
fn wait_empty(path: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if read(&format!("{path}/cgroup.events"))
            .is_some_and(|s| s.lines().any(|l| l == "populated 0"))
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn cleanup() -> bool {
    let job = format!("{CG}/job");
    if Path::new(&job).exists() && (!write(&format!("{job}/cgroup.kill"), "1") || !wait_empty(&job))
    {
        return false;
    }
    // Reap only descendants adopted by this subreaper; never trust PID files.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let n = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if n > 0 {
            continue;
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if Path::new(&job).exists() && fs::remove_dir(&job).is_err() {
        return false;
    }
    let root = format!("{ROOT}/job");
    if Path::new(&root).exists() && fs::remove_dir(&root).is_err() {
        return false;
    }
    true
}
fn pipe() -> Option<[i32; 2]> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0 {
        Some(fds)
    } else {
        None
    }
}
fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}
fn death() -> bool {
    let p = unsafe { libc::getppid() };
    p > 1
        && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
        && unsafe { libc::getppid() } == p
}

pub fn acquire() -> Result<std::fs::File, &'static str> {
    // Admission must remain possible under memory pressure so a stale job can
    // be killed before the headroom gate for the next execution.
    if !dir(ROOT) {
        return Err("SANDBOX_UNAVAILABLE");
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("{ROOT}/lock"))
        .map_err(|_| "SANDBOX_UNAVAILABLE")?;
    let m = lock.metadata().map_err(|_| "SANDBOX_UNAVAILABLE")?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err("SANDBOX_UNAVAILABLE");
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("BUSY");
    }
    Ok(lock)
}
pub fn cleanup_only() -> bool {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return false;
    }
    let Ok(m) = fs::symlink_metadata(CG) else {
        return false;
    };
    m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 && cleanup()
}
pub fn run(request: &Request, lock: &std::fs::File) -> (&'static str, &'static str) {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    }
    // This namespace must be explicitly provisioned with memory and pids controllers.
    let Ok(m) = fs::symlink_metadata(CG) else {
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    };
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 || !cleanup() {
        return ("unavailable", "CLEANUP_FAILED");
    }
    if !headroom() {
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    }
    // Keep the exact catalogue-verified inode open through the sandbox fork.
    // child::run bind-mounts this descriptor, never a path supplied by config.
    let core = match mihomo_release::open_active_core_for_validator() {
        Ok(core) => core,
        Err(_) => {
            eprintln!("xkeenwrt-validator: active core verification failed");
            return ("unavailable", "CORE_UNAVAILABLE");
        }
    };
    let cg = format!("{CG}/job");
    let root = format!("{ROOT}/job");
    if fs::create_dir(&cg).is_err() || !dir(&root) {
        let _ = cleanup();
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    }
    let setup = [
        ("memory.max", "67108864"),
        ("memory.swap.max", "0"),
        ("memory.oom.group", "1"),
        ("pids.max", "32"),
    ]
    .iter()
    .all(|(f, v)| {
        write(&format!("{cg}/{f}"), v) && read(&format!("{cg}/{f}")).is_some_and(|a| a.trim() == *v)
    });
    let before_memory = read(&format!("{cg}/memory.events"));
    let before_pids = read(&format!("{cg}/pids.events"));
    let mut result = if setup && before_memory.is_some() && before_pids.is_some() {
        supervise(request, &root, &cg, lock.as_raw_fd(), core.as_raw_fd())
    } else {
        ("unavailable", "SANDBOX_UNAVAILABLE")
    };
    // Freeze the job outcome before inspecting resource counters.
    if !write(&format!("{cg}/cgroup.kill"), "1") || !wait_empty(&cg) {
        let _ = cleanup();
        return ("unavailable", "CLEANUP_FAILED");
    }
    if read(&format!("{cg}/memory.events")) != before_memory
        || read(&format!("{cg}/pids.events")) != before_pids
    {
        result = ("unavailable", "RESOURCE_LIMIT");
    }
    if !cleanup() {
        ("unavailable", "CLEANUP_FAILED")
    } else if result.0 == "valid" && !known_complete(request) {
        ("unavailable", "ASSETS_UNVERIFIED")
    } else {
        result
    }
}
// A successful core exit cannot prove that lazy assets exist. The shared policy
// confirms supported profiles and the exact staged assets after job cleanup.
fn known_complete(request: &Request) -> bool {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let assets = request
        .assets
        .iter()
        .map(|asset| {
            Some(profile_policy::Asset {
                path: asset.path.clone(),
                content: STANDARD.decode(&asset.content_base64).ok()?,
            })
        })
        .collect::<Option<Vec<_>>>();
    assets.is_some_and(|assets| {
        profile_policy::complete_for(&request.config, &assets, &request.overlay)
    })
}
fn supervise(
    request: &Request,
    root: &str,
    cg: &str,
    lock_fd: i32,
    core_fd: i32,
) -> (&'static str, &'static str) {
    let Some(result) = pipe() else {
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        close(result[0]);
        // Only the guardian owns admission: descendants must never inherit it.
        close(lock_fd);
        if !death() {
            unsafe { libc::_exit(127) }
        }
        let byte = worker(request, root, cg, result[1], core_fd);
        unsafe {
            libc::write(result[1], (&byte as *const u8).cast(), 1);
            libc::_exit(0);
        }
    }
    close(result[1]);
    if pid < 0 {
        close(result[0]);
        return ("unavailable", "SANDBOX_UNAVAILABLE");
    }
    let mut pfd = libc::pollfd {
        fd: result[0],
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, 20000) };
    let mut b = 0u8;
    let got = if n > 0 {
        unsafe { libc::read(result[0], (&mut b as *mut u8).cast(), 1) }
    } else {
        0
    };
    close(result[0]);
    // Fault injection is compiled only into explicitly marked lab builds.
    if got == 1
        && b == 3
        && matches!(
            lab_fault().as_str(),
            "guardian-crash-detached" | "guardian-crash-after-exec"
        )
    {
        unsafe { libc::_exit(117) }
    }
    // kill only our still-unreaped direct child; cleanup kills job descendants.
    let mut status = 0;
    let deadline = Instant::now() + Duration::from_secs(1);
    let waited = loop {
        let n = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if n != 0 {
            break n;
        }
        if Instant::now() >= deadline {
            if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                return ("unavailable", "CLEANUP_FAILED");
            }
            let reap_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let n = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if n == pid {
                    break;
                }
                if n < 0 || Instant::now() >= reap_deadline {
                    return ("unavailable", "CLEANUP_FAILED");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            break -1;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if got != 1 || waited != pid || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return ("unavailable", "WORKER_FAILED");
    }
    match b {
        1 => ("valid", "VALID"),
        2 => ("invalid", "INVALID_CONFIG"),
        _ => ("unavailable", "CORE_UNAVAILABLE"),
    }
}
fn lab_fault() -> String {
    #[cfg(feature = "lab-faults")]
    {
        if crate::preflight::marked_lab_guest() {
            std::env::var("XKEENWRT_VALIDATOR_LAB_FAULT").unwrap_or_default()
        } else {
            String::new()
        }
    }
    #[cfg(not(feature = "lab-faults"))]
    {
        String::new()
    }
}
fn worker(request: &Request, root: &str, cg: &str, result_fd: i32, core_fd: i32) -> u8 {
    let fault = lab_fault();
    let Some(gate) = pipe() else { return 0 };
    let Some(ready) = pipe() else { return 0 };
    let Some(error) = pipe() else { return 0 };
    let Some(status) = pipe() else { return 0 };
    let Some(output) = pipe() else { return 0 };
    let Some(fault_pipe) = pipe() else { return 0 };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        close(result_fd);
        close(fault_pipe[0]);
        for fd in [gate[1], ready[0], error[0], status[0], output[0]] {
            close(fd);
        }
        if !death() {
            unsafe { libc::_exit(127) }
        }
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if null < 0
            || unsafe { libc::dup2(null, 0) } < 0
            || unsafe { libc::dup2(output[1], 1) } < 0
            || unsafe { libc::dup2(output[1], 2) } < 0
        {
            unsafe { libc::_exit(127) }
        }
        close(null);
        close(output[1]);
        let mut b = 0u8;
        if unsafe { libc::read(gate[0], (&mut b as *mut u8).cast(), 1) } != 1 || b != 1 {
            unsafe { libc::_exit(127) }
        }
        close(gate[0]);
        if fault == "after-detached" || fault == "guardian-crash-detached" {
            let detached = unsafe { libc::fork() };
            if detached == 0 {
                unsafe {
                    libc::setsid();
                    loop {
                        libc::pause();
                    }
                }
            }
            if detached < 0 {
                unsafe { libc::_exit(127) }
            }
            unsafe {
                libc::write(fault_pipe[1], [1u8].as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        close(fault_pipe[1]);
        child::run(
            Path::new(root),
            ChildFds {
                ready: ready[1],
                exec_error: error[1],
                status: status[1],
                core: core_fd,
            },
            request,
        );
    }
    close(fault_pipe[1]);
    for fd in [gate[0], ready[1], error[1], status[1], output[1]] {
        close(fd);
    }
    if fault == "before-admission" {
        unsafe { libc::_exit(117) }
    }
    if pid < 0 {
        return 0;
    }
    let admitted = write(&format!("{cg}/cgroup.procs"), &pid.to_string())
        && read(&format!("{cg}/cgroup.procs"))
            .is_some_and(|s| s.split_whitespace().any(|x| x == pid.to_string()))
        && read(&format!("/proc/{pid}/cgroup"))
            .is_some_and(|s| s.lines().any(|line| line == "0::/xkeenwrt-validation/job"));
    if admitted && fault == "after-admission" {
        unsafe { libc::_exit(117) }
    }
    if admitted {
        unsafe {
            libc::write(gate[1], [1u8].as_ptr().cast(), 1);
        }
    }
    close(gate[1]);
    if admitted && fault == "after-release" {
        unsafe { libc::_exit(117) }
    }
    if admitted && (fault == "after-detached" || fault == "guardian-crash-detached") {
        let mut p = libc::pollfd {
            fd: fault_pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, 2000) } > 0 {
            if fault == "guardian-crash-detached" {
                unsafe {
                    libc::write(result_fd, [3u8].as_ptr().cast(), 1);
                    loop {
                        libc::pause();
                    }
                }
            }
            unsafe { libc::_exit(117) }
        }
    }
    close(fault_pipe[0]);
    let outcome = monitor(
        [ready[0], error[0], status[0], output[0]],
        pid,
        result_fd,
        &fault,
    );
    for fd in [ready[0], error[0], status[0], output[0]] {
        close(fd);
    }
    outcome
}
fn monitor(fds: [i32; 4], pid: i32, result_fd: i32, fault: &str) -> u8 {
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return 0;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut open = [true; 4];
    let mut data: [Vec<u8>; 4] = Default::default();
    while open.iter().any(|x| *x) {
        if fault == "guardian-crash-after-exec"
            && !open[0]
            && data[0] == [1]
            && !open[1]
            && data[1].is_empty()
        {
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == 0 {
                unsafe {
                    libc::write(result_fd, [3u8].as_ptr().cast(), 1);
                    loop {
                        libc::pause();
                    }
                }
            }
            return 0;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return 0;
        }
        let mut pollfds: Vec<_> = fds
            .iter()
            .enumerate()
            .map(|(i, &fd)| libc::pollfd {
                fd: if open[i] { fd } else { -1 },
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            })
            .collect();
        let n = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                4,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return 0;
        }
        for i in 0..4 {
            if !open[i] || pollfds[i].revents == 0 {
                continue;
            }
            if pollfds[i].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return 0;
            }
            loop {
                let mut buf = [0u8; 4096];
                let n = unsafe { libc::read(fds[i], buf.as_mut_ptr().cast(), buf.len()) };
                if n == 0 {
                    open[i] = false;
                    break;
                }
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return 0;
                }
                data[i].extend_from_slice(&buf[..n as usize]);
                if data[i].len() > if i == 3 { 65536 } else { 4 } {
                    return 0;
                }
            }
        }
    }
    let mut wrapper = 0;
    loop {
        let n = unsafe { libc::waitpid(pid, &mut wrapper, libc::WNOHANG) };
        if n == pid {
            break;
        }
        if n < 0 || Instant::now() >= deadline {
            return 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if data[0] != [1]
        || !data[1].is_empty()
        || data[2].len() != 4
        || !libc::WIFEXITED(wrapper)
        || libc::WEXITSTATUS(wrapper) != 0
    {
        // Emit only fixed protocol metadata, never the core's output: it may
        // contain profile names, endpoints or credentials.
        let setup = <[u8; 4]>::try_from(data[1].as_slice())
            .ok()
            .map(i32::from_ne_bytes);
        eprintln!("xkeenwrt-validator: sandbox setup failed; ready={} phase={:?} errno={:?} status_bytes={} wrapper={wrapper}", data[0] == [1], setup.map(|value| value >> 16), setup.map(|value| value & 0xffff), data[2].len());
        return 0;
    }
    let status = i32::from_ne_bytes(data[2][..4].try_into().unwrap());
    if !libc::WIFEXITED(status) {
        eprintln!("xkeenwrt-validator: core terminated; wait_status={status}");
        return 0;
    }
    match classify_core_exit(status) {
        1 => return 1,
        2 => return 2,
        _ => (),
    }
    eprintln!(
        "xkeenwrt-validator: core rejected configuration; exit={}",
        libc::WEXITSTATUS(status)
    );
    0
}

// Setup, readiness, wrapper status and resource counters are checked separately.
// Mihomo -t uses exit 1 for all rejected configurations, not just one YAML error.
fn classify_core_exit(status: i32) -> u8 {
    if !libc::WIFEXITED(status) {
        return 0;
    }
    match libc::WEXITSTATUS(status) {
        0 => 1,
        1 => 2,
        _ => 0,
    }
}
#[cfg(test)]
mod outcome_tests {
    #[test]
    fn semantic_core_rejection_is_distinct_from_process_failure() {
        assert_eq!(super::classify_core_exit(0), 1);
        assert_eq!(super::classify_core_exit(1 << 8), 2);
        assert_eq!(super::classify_core_exit(2 << 8), 0);
        assert_eq!(super::classify_core_exit(libc::SIGKILL), 0);
    }
}
