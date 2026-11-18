//! Fixed, root-only local transport. Neither HTTP nor command payloads choose a
//! socket, executable, service name or shell command.
use super::{RuntimeCommand, RuntimeReply};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{FromRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    time::{Duration, Instant},
};

pub const SOCKET: &str = "/var/run/xkeenwrt/control.sock";
const DIR: &str = "/var/run/xkeenwrt";
const LIMIT: u64 = 2 * 1024 * 1024 + 64 * 1024;

struct StopPriority {
    _file: std::fs::File,
}
impl StopPriority {
    fn open(path: &Path) -> io::Result<std::fs::File> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { nix::libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe stop priority lock",
            ));
        }
        Ok(file)
    }
    fn path_for(lock_path: &Path) -> std::path::PathBuf {
        let mut name = lock_path.file_name().unwrap_or_default().to_os_string();
        name.push(".stop-priority");
        lock_path.with_file_name(name)
    }
    fn shared(path: &Path) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = Self::open(path)?;
        if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_SH | nix::libc::LOCK_NB) } == 0 {
            return Ok(Self { _file: file });
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Err(io::Error::new(io::ErrorKind::Interrupted, "emergency Stop is pending"))
        } else {
            Err(error)
        }
    }
    fn exclusive_bounded(path: &Path, wait: Duration) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = Self::open(path)?;
        let deadline = Instant::now() + wait;
        loop {
            if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Stop priority is busy"));
            }
            std::thread::sleep(Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

/// Holds the single-runtime lock until dropped. Emergency Stop also holds an
/// exclusive priority fence so new mutation waiters leave room for it.
pub struct RuntimeLock {
    file: std::fs::File,
    _priority: Option<StopPriority>,
}
impl RuntimeLock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        Self::acquire_bounded(path, Duration::from_secs(3))
    }
    pub fn acquire_emergency(path: &Path) -> io::Result<Self> {
        let priority_path = StopPriority::path_for(path);
        let priority = StopPriority::exclusive_bounded(&priority_path, Duration::from_secs(12))?;
        let file = Self::open_mutation_lock(path)?;
        Self::lock_until(&file, Duration::from_secs(12))?;
        Ok(Self {
            file,
            _priority: Some(priority),
        })
    }
    fn acquire_bounded(path: &Path, wait: Duration) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let priority_path = StopPriority::path_for(path);
        let priority_lock = Self::open_mutation_lock(path)?;
        let deadline = Instant::now() + wait;
        loop {
            let priority = StopPriority::shared(&priority_path)?;
            if unsafe { nix::libc::flock(priority_lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } == 0 {
                return Ok(Self {
                    file: priority_lock,
                    _priority: None,
                });
            }
            let error = io::Error::last_os_error();
            drop(priority);
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "runtime mutation lock is busy"));
            }
            std::thread::sleep(Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())));
        }
    }
    fn open_mutation_lock(path: &Path) -> io::Result<std::fs::File> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { nix::libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe runtime lock"));
        }
        Ok(file)
    }
    fn lock_until(file: &std::fs::File, wait: Duration) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let deadline = Instant::now() + wait;
        loop {
            if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "runtime mutation lock is busy"));
            }
            std::thread::sleep(Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}
impl Drop for RuntimeLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            nix::libc::flock(self.file.as_raw_fd(), nix::libc::LOCK_UN);
        }
    }
}

pub fn serve() -> io::Result<()> {
    if crate::platform::Platform::inspect().platform != "openwrt" {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "runtime requires OpenWrt"));
    }
    if unsafe { nix::libc::geteuid() } != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "runtime requires root"));
    }
    match fs::DirBuilder::new().mode(0o700).create(DIR) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let meta = fs::symlink_metadata(DIR)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe runtime directory",
        ));
    }
    let incarnation = super::networking::incarnation::RuntimeIncarnation::acquire()?;
    let mut coordinator = super::Coordinator::open(&incarnation)?;
    match fs::symlink_metadata(SOCKET) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => fs::remove_file(SOCKET)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe runtime socket path",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut last_maintenance = Instant::now() - Duration::from_secs(1);
    loop {
        if last_maintenance.elapsed() >= Duration::from_secs(1) {
            coordinator.maintain_storage();
            last_maintenance = Instant::now();
        }
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut fd = nix::libc::pollfd {
                    fd: std::os::fd::AsRawFd::as_raw_fd(&listener),
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                if unsafe { nix::libc::poll(&mut fd, 1, 1000) } < 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    return Err(io::Error::last_os_error());
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes = Vec::new();
        let complete = (&mut stream).take(LIMIT + 1).read_to_end(&mut bytes).is_ok();
        let reply = if !complete || bytes.len() as u64 > LIMIT {
            RuntimeReply::error("INVALID_COMMAND", "Command too large")
        } else {
            match serde_json::from_slice::<RuntimeCommand>(&bytes) {
                Ok(cmd) => coordinator.command(cmd),
                Err(_) => RuntimeReply::error("INVALID_COMMAND", "Unknown or malformed command"),
            }
        };
        let _ = stream.write_all(&serde_json::to_vec(&reply)?);
    }
}

#[cfg(test)]
mod lock_tests {
    use super::RuntimeLock;
    use std::time::{Duration, Instant};

    #[test]
    fn runtime_lock_waits_boundedly_for_recovery_to_release() {
        let path = std::env::temp_dir().join(format!("xkeenwrt-lock-wait-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let held = RuntimeLock::acquire_bounded(&path, Duration::from_millis(100)).unwrap();
        let waiting_path = path.clone();
        let waiting =
            std::thread::spawn(move || RuntimeLock::acquire_bounded(&waiting_path, Duration::from_secs(1)).is_ok());
        std::thread::sleep(Duration::from_millis(150));
        drop(held);
        assert!(waiting.join().unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn runtime_lock_contention_stops_at_its_deadline() {
        let path = std::env::temp_dir().join(format!("xkeenwrt-lock-timeout-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let held = RuntimeLock::acquire_bounded(&path, Duration::from_millis(100)).unwrap();
        let started = Instant::now();
        let error = match RuntimeLock::acquire_bounded(&path, Duration::from_millis(120)) {
            Ok(_) => panic!("contention should time out"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(held);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn emergency_stop_fences_new_mutation_waiters() {
        use super::StopPriority;
        use std::{sync::mpsc, thread};
        let path = std::env::temp_dir().join(format!("xkeenwrt-lock-priority-{}", std::process::id()));
        let priority_path = StopPriority::path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&priority_path);
        let held = RuntimeLock::acquire(&path).unwrap();
        let waiting_path = path.clone();
        let (sender, receiver) = mpsc::channel();
        let stop = thread::spawn(move || {
            let acquired = RuntimeLock::acquire_emergency(&waiting_path);
            sender.send(acquired.is_ok()).unwrap();
            drop(acquired);
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match StopPriority::shared(&priority_path) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => break,
                Ok(priority) => drop(priority),
                Err(error) => panic!("priority probe failed: {error}"),
            }
            assert!(Instant::now() < deadline, "emergency Stop did not publish priority");
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = Instant::now();
        let error = match RuntimeLock::acquire_bounded(&path, Duration::from_secs(1)) {
            Ok(_) => panic!("new mutation should yield to emergency Stop"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(held);
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        stop.join().unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(priority_path).unwrap();
    }
}

pub struct RuntimeClient;
impl RuntimeClient {
    pub fn command(command: RuntimeCommand) -> io::Result<RuntimeReply> {
        Self::command_with_timeout(command, Duration::from_secs(200))
    }
    pub fn status() -> io::Result<RuntimeReply> {
        let stream = connect_bounded(Path::new(SOCKET), Duration::from_millis(250))?;
        exchange_bounded(stream, RuntimeCommand::Status, Duration::from_secs(8))
    }
    fn command_with_timeout(command: RuntimeCommand, read_timeout: Duration) -> io::Result<RuntimeReply> {
        let stream = UnixStream::connect(SOCKET)?;
        Self::exchange(stream, command, read_timeout, Duration::from_secs(2))
    }
    fn exchange(
        mut stream: UnixStream, command: RuntimeCommand, read_timeout: Duration, write_timeout: Duration,
    ) -> io::Result<RuntimeReply> {
        stream.set_read_timeout(Some(read_timeout))?;
        stream.set_write_timeout(Some(write_timeout))?;
        stream.write_all(&serde_json::to_vec(&command)?)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = Vec::new();
        stream.take(LIMIT + 1).read_to_end(&mut response)?;
        if response.len() as u64 > LIMIT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
        }
        serde_json::from_slice(&response).map_err(io::Error::other)
    }
}

struct SocketFd(RawFd);
impl Drop for SocketFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { nix::libc::close(self.0) };
        }
    }
}

fn connect_bounded(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::{
        mem::{size_of, zeroed},
        time::Instant,
    };

    let path_bytes = path.as_os_str().as_bytes();
    let mut address: nix::libc::sockaddr_un = unsafe { zeroed() };
    if path_bytes.is_empty() || path_bytes.len() >= address.sun_path.len() || path_bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Unix socket path"));
    }
    address.sun_family = nix::libc::AF_UNIX as nix::libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *target = *source as nix::libc::c_char;
    }

    let fd = unsafe {
        nix::libc::socket(
            nix::libc::AF_UNIX,
            nix::libc::SOCK_STREAM | nix::libc::SOCK_NONBLOCK | nix::libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut owned = SocketFd(fd);
    let connected = unsafe {
        nix::libc::connect(
            fd,
            (&address as *const nix::libc::sockaddr_un).cast(),
            size_of::<nix::libc::sockaddr_un>() as nix::libc::socklen_t,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::EAGAIN) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "runtime socket backlog is busy",
            ));
        }
        if !matches!(
            error.raw_os_error(),
            Some(nix::libc::EINPROGRESS) | Some(nix::libc::EALREADY) | Some(nix::libc::EINTR)
        ) {
            return Err(error);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "runtime socket connect timed out",
                ));
            }
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = nix::libc::pollfd {
                fd,
                events: nix::libc::POLLOUT,
                revents: 0,
            };
            let ready = unsafe { nix::libc::poll(&mut descriptor, 1, millis) };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "runtime socket connect timed out",
                ));
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut socket_error: nix::libc::c_int = 0;
            let mut socket_error_len = size_of::<nix::libc::c_int>() as nix::libc::socklen_t;
            if unsafe {
                nix::libc::getsockopt(
                    fd,
                    nix::libc::SOL_SOCKET,
                    nix::libc::SO_ERROR,
                    (&mut socket_error as *mut nix::libc::c_int).cast(),
                    &mut socket_error_len,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
            break;
        }
    }
    let fd = owned.0;
    owned.0 = -1;
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn wait_ready(fd: RawFd, events: i16, deadline: std::time::Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "runtime status I/O timed out"));
        }
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = nix::libc::pollfd { fd, events, revents: 0 };
        let ready = unsafe { nix::libc::poll(&mut descriptor, 1, millis) };
        if ready == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "runtime status I/O timed out"));
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptor.revents & nix::libc::POLLNVAL != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid runtime socket"));
        }
        if descriptor.revents & (events | nix::libc::POLLERR | nix::libc::POLLHUP) != 0 {
            return Ok(());
        }
    }
}

fn exchange_bounded(mut stream: UnixStream, command: RuntimeCommand, timeout: Duration) -> io::Result<RuntimeReply> {
    use std::os::fd::AsRawFd;

    stream.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    let request = serde_json::to_vec(&command)?;
    let mut written = 0;
    while written < request.len() {
        match stream.write(&request[written..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "runtime socket closed")),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(stream.as_raw_fd(), nix::libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&buffer[..count]);
                if response.len() as u64 > LIMIT {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(stream.as_raw_fd(), nix::libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    serde_json::from_slice(&response).map_err(io::Error::other)
}

#[cfg(test)]
mod bounded_status_connect_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn status_connect_fails_fast_when_runtime_socket_backlog_is_full() {
        let path = std::env::temp_dir().join(format!("xkeen-status-busy-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { nix::libc::socket(nix::libc::AF_UNIX, nix::libc::SOCK_STREAM | nix::libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let mut address: nix::libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = nix::libc::AF_UNIX as nix::libc::sa_family_t;
        for (target, source) in address.sun_path.iter_mut().zip(path_c.as_bytes()) {
            *target = *source as nix::libc::c_char;
        }
        assert_eq!(
            unsafe {
                nix::libc::bind(
                    fd,
                    (&address as *const nix::libc::sockaddr_un).cast(),
                    std::mem::size_of::<nix::libc::sockaddr_un>() as nix::libc::socklen_t,
                )
            },
            0
        );
        assert_eq!(unsafe { nix::libc::listen(fd, 1) }, 0);
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        let mut clients = Vec::new();
        let started = Instant::now();
        let mut busy = false;
        for _ in 0..8 {
            match connect_bounded(&path, Duration::from_millis(100)) {
                Ok(stream) => clients.push(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    busy = true;
                    break;
                }
                Err(error) => panic!("unexpected bounded connect result: {error}"),
            }
        }
        assert!(busy, "full AF_UNIX listener backlog must fail fast");
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(clients);
        drop(listener);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn status_exchange_enforces_total_deadline_for_trickled_reply() {
        let path = std::env::temp_dir().join(format!("xkeen-status-trickle-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            for byte in br#"{"code":"OK"}"# {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        });
        let stream = UnixStream::connect(&path).unwrap();
        let started = Instant::now();
        let result = exchange_bounded(stream, RuntimeCommand::Status, Duration::from_millis(150));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }
}
