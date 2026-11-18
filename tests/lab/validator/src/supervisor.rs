//! One job at a time; all mutations are confined to our fresh directories.
use crate::{
    child,
    protocol::{ChildFds, Scenario},
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CG: &str = "/sys/fs/cgroup";
const LIMIT: usize = 65536;

fn write(path: &Path, value: &str) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(value.as_bytes())
}
fn read(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path)
}
fn words(s: &str, word: &str) -> bool {
    s.split_ascii_whitespace().any(|w| w == word)
}
fn event(path: &Path, key: &str) -> Option<u64> {
    let data = read(path).ok()?;
    let mut matching = data.lines().filter_map(|line| {
        let mut parts = line.split_ascii_whitespace();
        if parts.next()? != key {
            return None;
        }
        let value = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(value)
    });
    let value = matching.next()?;
    if matching.next().is_some() {
        None
    } else {
        Some(value)
    }
}
fn pipe() -> std::io::Result<[RawFd; 2]> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fds)
}
fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}
fn nonblock(fd: RawFd) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
}

struct Job {
    root: PathBuf,
    cg: PathBuf,
    root_created: bool,
    cg_created: bool,
    added: Vec<&'static str>,
    pid: libc::pid_t,
}
impl Job {
    fn new() -> Self {
        let pid = unsafe { libc::getpid() };
        Self {
            root: PathBuf::from(format!("/tmp/xkeenwrt-lab-{pid}")),
            cg: PathBuf::from(format!("{CG}/xkeenwrt-lab-{pid}")),
            root_created: false,
            cg_created: false,
            added: Vec::new(),
            pid: -1,
        }
    }
    fn setup(&mut self, scenario: Scenario) -> std::io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(&self.root)?;
        self.root_created = true;
        let base = Path::new(CG);
        let controllers = read(&base.join("cgroup.controllers"))?;
        let before = read(&base.join("cgroup.subtree_control"))?;
        for c in ["memory", "pids"] {
            if !words(&controllers, c) {
                return Err(std::io::Error::other("controller"));
            }
            if !words(&before, c) {
                write(&base.join("cgroup.subtree_control"), &format!("+{c}"))?;
                self.added.push(c);
            }
        }
        let after = read(&base.join("cgroup.subtree_control"))?;
        if !words(&after, "memory") || !words(&after, "pids") {
            return Err(std::io::Error::other("controllers"));
        }
        fs::create_dir(&self.cg)?;
        self.cg_created = true;
        let memory_limit = if matches!(scenario, Scenario::Memory) {
            "16777216"
        } else {
            "67108864"
        };
        for (file, val) in [
            ("memory.max", memory_limit),
            ("memory.oom.group", "1"),
            ("memory.swap.max", "0"),
            ("pids.max", "32"),
        ] {
            write(&self.cg.join(file), val)?;
            if read(&self.cg.join(file))?.trim() != val {
                return Err(std::io::Error::other("limit"));
            }
        }
        Ok(())
    }
    fn cleanup(&mut self) -> bool {
        let mut ok = true;
        if self.cg_created && write(&self.cg.join("cgroup.kill"), "1").is_err() {
            ok = false;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        // Admission can fail while our direct child is still outside the job
        // cgroup. Only signal it after waitpid confirms it remains our child.
        if self.pid > 0 {
            loop {
                let n = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG) };
                if n == 0 {
                    if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        ok = false;
                    }
                    break;
                }
                if n == self.pid {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted && Instant::now() < deadline {
                    continue;
                }
                if e.raw_os_error() != Some(libc::ECHILD) {
                    ok = false;
                }
                break;
            }
        }
        loop {
            let no_children = loop {
                let n = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
                if n > 0 {
                    continue;
                }
                if n == 0 {
                    break false;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() != Some(libc::ECHILD) {
                    ok = false;
                }
                break error.raw_os_error() == Some(libc::ECHILD);
            };
            let empty = if self.cg_created {
                match read(&self.cg.join("cgroup.events")) {
                    Ok(s) => s.lines().any(|l| l == "populated 0"),
                    Err(_) => false,
                }
            } else {
                true
            };
            if empty && no_children {
                break;
            }
            if Instant::now() >= deadline {
                ok = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.cg_created && fs::remove_dir(&self.cg).is_err() {
            ok = false;
        }
        for c in self.added.iter().rev() {
            if write(
                &Path::new(CG).join("cgroup.subtree_control"),
                &format!("-{c}"),
            )
            .is_err()
            {
                ok = false;
            }
            match read(&Path::new(CG).join("cgroup.subtree_control")) {
                Ok(s) if !words(&s, c) => (),
                _ => ok = false,
            }
        }
        if self.root_created && fs::remove_dir(&self.root).is_err() {
            ok = false;
        }
        ok
    }
}

pub fn run(scenario: Scenario) -> Result<Option<u64>, &'static str> {
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/tmp/xkeenwrt-lab.lock")
    {
        Ok(f) => f,
        Err(_) => return Err("setup"),
    };
    let meta = match lock.metadata() {
        Ok(m) => m,
        Err(_) => return Err("setup"),
    };
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("setup");
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err("setup");
    }
    let mut job = Job::new();
    let result = match job.setup(scenario) {
        Ok(()) => {
            let before = match scenario {
                Scenario::Pids => event(&job.cg.join("pids.events"), "max"),
                Scenario::Memory
                | Scenario::MihomoValid
                | Scenario::MihomoInvalid
                | Scenario::MihomoInvalidUnreadable
                | Scenario::MihomoMissingAsset
                | Scenario::MihomoFileContained
                | Scenario::MihomoFileEscape
                | Scenario::MihomoAwgV3
                | Scenario::MihomoAwgLegacy => event(&job.cg.join("memory.events"), "oom_kill"),
                _ => Some(0),
            };
            let before_oom = if scenario.is_core() {
                event(&job.cg.join("memory.events"), "oom")
            } else {
                Some(0)
            };
            let before_pids = if scenario.is_core() {
                event(&job.cg.join("pids.events"), "max")
            } else {
                Some(0)
            };
            if let (Some(before), Some(before_oom), Some(before_pids)) =
                (before, before_oom, before_pids)
            {
                let outcome = execute(&mut job, scenario);
                let core_pids_ok = !scenario.is_core()
                    || event(&job.cg.join("pids.events"), "max") == Some(before_pids);
                let matched = match (scenario, outcome) {
                    (Scenario::Probe | Scenario::Tmpfs, Outcome::Exit(0)) => true,
                    (Scenario::Pids, Outcome::Exit(0)) => event(&job.cg.join("pids.events"), "max")
                        .is_some_and(|after| after > before),
                    (Scenario::Timeout, Outcome::Timeout) | (Scenario::Output, Outcome::Output) => {
                        true
                    }
                    (Scenario::SetupDenied, Outcome::Denied) => true,
                    (
                        Scenario::MihomoValid
                        | Scenario::MihomoFileContained
                        | Scenario::MihomoAwgV3
                        | Scenario::MihomoAwgLegacy,
                        Outcome::Exit(0),
                    )
                    | (Scenario::MihomoInvalid, Outcome::InvalidYaml)
                    | (Scenario::MihomoMissingAsset, Outcome::MissingAsset)
                    | (Scenario::MihomoFileEscape, Outcome::FileContained) => {
                        event(&job.cg.join("memory.events"), "oom_kill") == Some(before)
                            && event(&job.cg.join("memory.events"), "oom") == Some(before_oom)
                            && core_pids_ok
                    }
                    (Scenario::Memory, Outcome::MemoryKilled) => {
                        event(&job.cg.join("memory.events"), "oom_kill")
                            .is_some_and(|after| after > before)
                    }
                    _ => false,
                };
                if matched {
                    if matches!(
                        scenario,
                        Scenario::Memory
                            | Scenario::MihomoValid
                            | Scenario::MihomoInvalid
                            | Scenario::MihomoInvalidUnreadable
                            | Scenario::MihomoMissingAsset
                            | Scenario::MihomoFileContained
                            | Scenario::MihomoFileEscape
                            | Scenario::MihomoAwgV3
                            | Scenario::MihomoAwgLegacy
                    ) {
                        match read(&job.cg.join("memory.peak"))
                            .ok()
                            .and_then(|s| s.trim().parse::<u64>().ok())
                        {
                            Some(n) if n > 0 => Ok(Some(n)),
                            _ => Err("execute"),
                        }
                    } else {
                        Ok(None)
                    }
                } else if scenario.is_core() {
                    Err(if !core_pids_ok {
                        "core-pids"
                    } else {
                        match outcome {
                            Outcome::Exit(0)
                                if !matches!(
                                    scenario,
                                    Scenario::MihomoValid
                                        | Scenario::MihomoFileContained
                                        | Scenario::MihomoAwgV3
                                        | Scenario::MihomoAwgLegacy
                                ) =>
                            {
                                "core-exit-0"
                            }
                            Outcome::Exit(0) => "core-oom",
                            Outcome::CoreFailure(reason) => reason,
                            Outcome::Exit(1) => "core-exit-1",
                            Outcome::Exit(_) => "core-exit-other",
                            Outcome::Timeout => "core-timeout",
                            Outcome::Output => "core-output",
                            Outcome::InvalidYaml => "core-unexpected-parse",
                            _ => "core-handshake",
                        }
                    })
                } else {
                    Err("execute")
                }
            } else {
                Err("setup")
            }
        }
        Err(_) => Err("setup"),
    };
    if !job.cleanup() {
        Err("cleanup")
    } else {
        result
    }
}

#[derive(Debug, Clone, Copy)]
enum Outcome {
    Exit(i32),
    CoreFailure(&'static str),
    MissingAsset,
    InvalidYaml,
    FileContained,
    Timeout,
    Output,
    MemoryKilled,
    Denied,
    Error,
}

fn execute(job: &mut Job, scenario: Scenario) -> Outcome {
    let mut all = Vec::new();
    for _ in 0..5 {
        match pipe() {
            Ok(p) => all.push(p),
            Err(_) => {
                for p in all {
                    close(p[0]);
                    close(p[1]);
                }
                return Outcome::Error;
            }
        }
    }
    let [gate, ready, exec_error, status, output] = [all[0], all[1], all[2], all[3], all[4]];
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        close(gate[1]);
        close(ready[0]);
        close(exec_error[0]);
        close(status[0]);
        close(output[0]);
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if null < 0
            || unsafe { libc::dup2(null, 0) } < 0
            || unsafe { libc::dup2(output[1], 1) } < 0
            || unsafe { libc::dup2(output[1], 2) } < 0
        {
            unsafe { libc::_exit(126) }
        }
        close(null);
        close(output[1]);
        let mut b = 0u8;
        let n = unsafe { libc::read(gate[0], &mut b as *mut u8 as *mut _, 1) };
        close(gate[0]);
        if n != 1 || b != 1 {
            unsafe { libc::_exit(126) }
        }
        // Plant an inert high descriptor to exercise the child's FD closure.
        let injected = unsafe { libc::fcntl(0, libc::F_DUPFD, 200) };
        if injected < 0 {
            unsafe { libc::_exit(126) }
        }
        child::run(
            &job.root,
            ChildFds {
                ready: ready[1],
                exec_error: exec_error[1],
                status: status[1],
            },
            scenario,
        );
    }
    close(gate[0]);
    close(ready[1]);
    close(exec_error[1]);
    close(status[1]);
    close(output[1]);
    if pid < 0 {
        close(gate[1]);
        for fd in [ready[0], exec_error[0], status[0], output[0]] {
            close(fd);
        }
        return Outcome::Error;
    }
    job.pid = pid;
    let admitted = write(&job.cg.join("cgroup.procs"), &pid.to_string()).is_ok()
        && read(&job.cg.join("cgroup.procs"))
            .map(|s| words(&s, &pid.to_string()))
            .unwrap_or(false)
        && read(Path::new(&format!("/proc/{pid}/cgroup")))
            .map(|s| {
                s.lines()
                    .any(|l| l == format!("0::/xkeenwrt-lab-{}", unsafe { libc::getpid() }))
            })
            .unwrap_or(false);
    let denied = admitted && matches!(scenario, Scenario::SetupDenied);
    let released =
        admitted && !denied && unsafe { libc::write(gate[1], [1u8].as_ptr() as *const _, 1) } == 1;
    close(gate[1]);
    let fds = [ready[0], exec_error[0], status[0], output[0]];
    let result = if denied {
        monitor_denied(fds, pid)
    } else if released {
        monitor(fds, pid, scenario)
    } else {
        Outcome::Error
    };
    for fd in fds {
        close(fd);
    }
    result
}

fn monitor(fds: [RawFd; 4], pid: libc::pid_t, scenario: Scenario) -> Outcome {
    if !fds.iter().all(|&fd| nonblock(fd)) {
        return Outcome::Error;
    }
    let duration = match scenario {
        Scenario::Timeout => Duration::from_secs(1),
        _ => Duration::from_secs(15),
    };
    let deadline = Instant::now() + duration;
    let mut data: [Vec<u8>; 3] = Default::default();
    let mut total = 0usize;
    let mut timeout_evidence = Vec::new();
    let mut core_output = Vec::new();
    let mut open = [true; 4];
    let mut overflow = false;
    loop {
        let established = !open[0] && data[0] == [1] && !open[1] && data[1].is_empty();
        if overflow && established {
            return Outcome::Output;
        }
        if open.iter().all(|x| !*x) {
            if !established {
                return Outcome::Error;
            }
            let mut wrapper_status = 0;
            loop {
                let n = unsafe { libc::waitpid(pid, &mut wrapper_status, libc::WNOHANG) };
                if n == pid {
                    break;
                }
                if n < 0 || Instant::now() >= deadline {
                    return Outcome::Error;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(scenario, Scenario::Memory) {
                return if timeout_evidence == b"M"
                    && libc::WIFSIGNALED(wrapper_status)
                    && libc::WTERMSIG(wrapper_status) == libc::SIGKILL
                {
                    Outcome::MemoryKilled
                } else {
                    Outcome::Error
                };
            }
            if data[2].len() != 4
                || !libc::WIFEXITED(wrapper_status)
                || libc::WEXITSTATUS(wrapper_status) != 0
            {
                return Outcome::Error;
            }
            let raw = i32::from_ne_bytes(data[2][..4].try_into().unwrap());
            return if libc::WIFEXITED(raw) {
                let code = libc::WEXITSTATUS(raw);
                if matches!(
                    scenario,
                    Scenario::MihomoInvalid | Scenario::MihomoInvalidUnreadable
                ) && code == 1
                {
                    let lower = core_output.to_ascii_lowercase();
                    let contains = |s: &[u8]| lower.windows(s.len()).any(|w| w == s);
                    if contains(b"yaml:") && contains(b"did not find expected node content") {
                        Outcome::InvalidYaml
                    } else {
                        Outcome::CoreFailure("core-invalid-evidence")
                    }
                } else if matches!(scenario, Scenario::MihomoFileEscape) && code == 1 {
                    let lower = core_output.to_ascii_lowercase();
                    if lower
                        .windows(b"open /data/key.pem: no such file or directory".len())
                        .any(|w| w == b"open /data/key.pem: no such file or directory")
                    {
                        Outcome::FileContained
                    } else {
                        Outcome::CoreFailure("core-file-evidence")
                    }
                } else if matches!(scenario, Scenario::MihomoMissingAsset) && code == 1 {
                    let lower = core_output.to_ascii_lowercase();
                    let contains = |s: &[u8]| lower.windows(s.len()).any(|w| w == s);
                    if contains(b"can't download mmdb") || contains(b"can't find mmdb") {
                        Outcome::MissingAsset
                    } else {
                        Outcome::CoreFailure("core-missing-evidence")
                    }
                } else if matches!(scenario, Scenario::MihomoValid) && code == 1 {
                    let lower = core_output.to_ascii_lowercase();
                    let contains = |s: &[u8]| lower.windows(s.len()).any(|w| w == s);
                    Outcome::CoreFailure(
                        if contains(b"amd64")
                            || contains(b"microarchitecture")
                            || contains(b"processor")
                            || contains(b"instruction")
                        {
                            "core-cpu"
                        } else {
                            "core-exit-1"
                        },
                    )
                } else {
                    Outcome::Exit(code)
                }
            } else {
                Outcome::Error
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let mut status = 0;
            let alive = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == 0;
            return if established
                && !overflow
                && data[2].is_empty()
                && alive
                && ((matches!(scenario, Scenario::Timeout) && timeout_evidence == b"D")
                    || scenario.is_core())
            {
                Outcome::Timeout
            } else {
                Outcome::Error
            };
        }
        let mut polls: Vec<libc::pollfd> = fds
            .iter()
            .enumerate()
            .map(|(i, &fd)| libc::pollfd {
                fd: if open[i] && !(i == 3 && overflow) {
                    fd
                } else {
                    -1
                },
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            })
            .collect();
        let n = unsafe {
            libc::poll(
                polls.as_mut_ptr(),
                4,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Outcome::Error;
        }
        if n == 0 {
            continue;
        }
        for i in 0..4 {
            if !open[i] || polls[i].revents == 0 {
                continue;
            }
            if polls[i].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Outcome::Error;
            }
            let mut buf = [0u8; 4096];
            loop {
                let got = unsafe { libc::read(fds[i], buf.as_mut_ptr() as *mut _, buf.len()) };
                if got == 0 {
                    open[i] = false;
                    break;
                }
                if got < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Outcome::Error;
                }
                let n = got as usize;
                if i == 3 {
                    if scenario.is_core() {
                        if core_output.len() + n > LIMIT {
                            return Outcome::Output;
                        }
                        core_output.extend_from_slice(&buf[..n]);
                    }
                    if matches!(scenario, Scenario::Timeout | Scenario::Memory) {
                        timeout_evidence.extend_from_slice(&buf[..n]);
                        if timeout_evidence.len() > 1 {
                            return Outcome::Error;
                        }
                    }
                    total += n;
                    if total > LIMIT {
                        overflow = true;
                        break;
                    }
                } else {
                    data[i].extend_from_slice(&buf[..n]);
                    if data[i].len() > 4 {
                        return Outcome::Error;
                    }
                }
            }
        }
    }
}

// A closed gate must produce no setup, exec, status, or payload output.
fn monitor_denied(fds: [RawFd; 4], pid: libc::pid_t) -> Outcome {
    if !fds.iter().all(|&fd| nonblock(fd)) {
        return Outcome::Error;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut open = [true; 4];
    while open.iter().any(|v| *v) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Outcome::Error;
        }
        let mut polls: Vec<libc::pollfd> = fds
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
                polls.as_mut_ptr(),
                4,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Outcome::Error;
        }
        if n == 0 {
            continue;
        }
        for i in 0..4 {
            if !open[i] || polls[i].revents == 0 {
                continue;
            }
            if polls[i].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Outcome::Error;
            }
            let mut byte = 0u8;
            let n = unsafe { libc::read(fds[i], &mut byte as *mut u8 as *mut _, 1) };
            if n == 0 {
                open[i] = false;
            } else if n > 0 {
                return Outcome::Error;
            } else {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::Interrupted
                {
                    return Outcome::Error;
                }
            }
        }
    }
    let mut status = 0;
    loop {
        let n = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if n == pid {
            break;
        }
        if n < 0 || Instant::now() >= deadline {
            return Outcome::Error;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 126 {
        Outcome::Denied
    } else {
        Outcome::Error
    }
}
