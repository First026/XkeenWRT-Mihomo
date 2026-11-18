//! Fixed probe: runs only inside the disposable VM supervisor.
#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("validator lab supports only little-endian 64-bit Linux x86_64 and aarch64");

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::ptr;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn boundary_probe() -> Result<(), i32> {
    if fs::read("/data/probe-marker").ok().as_deref() != Some(b"probe-v1\n") {
        return Err(10);
    }
    for path in [
        "/tmp/xkeenwrt-isolation-sentinel",
        "/../../tmp/xkeenwrt-isolation-sentinel",
        "/proc",
        "/sys",
        "/dev",
    ] {
        match fs::metadata(path) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
            _ => return Err(11),
        }
    }
    unsafe {
        let (mut r, mut e, mut s) = (0, 0, 0);
        if libc::getresuid(&mut r, &mut e, &mut s) != 0 || (r, e, s) != (65534, 65534, 65534) {
            return Err(12);
        }
        if libc::getresgid(&mut r, &mut e, &mut s) != 0
            || (r, e, s) != (65534, 65534, 65534)
            || libc::getgroups(0, ptr::null_mut()) != 0
        {
            return Err(13);
        }
        let mut header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) != 0
            || data
                .iter()
                .any(|c| c.effective | c.permitted | c.inheritable != 0)
        {
            return Err(14);
        }
        for cap in 0..64 {
            let b = libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0);
            if b < 0 && *libc::__errno_location() == libc::EINVAL {
                break;
            }
            if b != 0
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0
            {
                return Err(15);
            }
        }
        if libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
            || libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) != 2
            || libc::getppid() != 1
        {
            return Err(16);
        }
        for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
            let fd = libc::socket(domain, libc::SOCK_STREAM, 0);
            if fd != -1 || *libc::__errno_location() != libc::EPERM {
                if fd >= 0 {
                    libc::close(fd);
                }
                return Err(17);
            }
        }
        let mut pair = [-1; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(18);
        }
        if libc::unshare(libc::CLONE_NEWUSER) != -1 || *libc::__errno_location() != libc::EPERM {
            return Err(19);
        }
        if libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
        ) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(20);
        }
        if libc::syscall(
            libc::SYS_process_vm_readv,
            libc::getpid(),
            ptr::null::<libc::iovec>(),
            0,
            ptr::null::<libc::iovec>(),
            0,
            0,
        ) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(21);
        }
        // Probe architecture-sensitive pre-exec filter decisions at the same
        // fixed VM seam as the rest of the boundary checks.
        if libc::syscall(libc::SYS_clone3, ptr::null::<libc::c_void>(), 0) != -1
            || *libc::__errno_location() != libc::ENOSYS
        {
            return Err(27);
        }
        let clone = libc::syscall(
            libc::SYS_clone,
            libc::CLONE_NEWUSER | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        );
        if clone == 0 {
            libc::_exit(44);
        }
        if clone != -1 || *libc::__errno_location() != libc::EPERM {
            if clone > 0 {
                libc::waitpid(clone as libc::pid_t, ptr::null_mut(), 0);
            }
            return Err(28);
        }
        if libc::syscall(
            libc::SYS_mount,
            ptr::null::<libc::c_void>(),
            ptr::null::<libc::c_void>(),
            ptr::null::<libc::c_void>(),
            0,
            ptr::null::<libc::c_void>(),
        ) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(29);
        }
        if libc::syscall(libc::SYS_io_uring_setup, 1, ptr::null::<libc::c_void>()) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(30);
        }
        let root = CString::new("/").unwrap();
        if libc::chroot(root.as_ptr()) != -1
            || *libc::__errno_location() != libc::EPERM
            || libc::setuid(0) != -1
            || *libc::__errno_location() != libc::EPERM
        {
            return Err(22);
        }
        for fd in 3..256 {
            if libc::fcntl(fd, libc::F_GETFD) != -1 || *libc::__errno_location() != libc::EBADF {
                return Err(23);
            }
        }
        for (resource, value) in [
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_NOFILE, 64),
            (libc::RLIMIT_FSIZE, 16 * 1024 * 1024),
            (libc::RLIMIT_CPU, 5),
        ] {
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(resource, &mut limit) != 0
                || limit.rlim_cur != value
                || limit.rlim_max != value
            {
                return Err(24);
            }
        }
    }
    if std::env::vars_os().next().is_some() {
        return Err(25);
    }
    if fs::OpenOptions::new()
        .write(true)
        .open("/bin/probe")
        .is_ok()
    {
        return Err(26);
    }
    Ok(())
}

fn main() {
    let mode = std::env::args_os().nth(1);
    let mode = mode.as_deref().and_then(|s| s.to_str());
    if matches!(
        mode,
        Some("probe" | "timeout" | "output" | "tmpfs" | "pids" | "memory")
    ) {
        if let Err(code) = boundary_probe() {
            std::process::exit(code);
        }
    }
    match mode {
        Some("probe") => {}
        Some("timeout") => unsafe {
            // Descendant remains in the cgroup even after detaching its session.
            let pid = libc::fork();
            if pid < 0 {
                std::process::exit(30);
            }
            if pid == 0 {
                if libc::setsid() < 0 {
                    libc::_exit(31);
                }
                let byte = b"D";
                loop {
                    let n = libc::write(1, byte.as_ptr().cast(), 1);
                    if n == 1 {
                        break;
                    }
                    if n < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(31);
                }
            }
            loop {
                libc::pause();
            }
        },
        Some("tmpfs") => {
            let mut file = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("/data/quota-test")
            {
                Ok(file) => file,
                Err(_) => std::process::exit(34),
            };
            let bytes = [0x5a; 4096];
            let mut exhausted = false;
            for _ in 0..4096 {
                match file.write_all(&bytes) {
                    Ok(()) => (),
                    Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                        exhausted = true;
                        break;
                    }
                    Err(_) => std::process::exit(35),
                }
            }
            if !exhausted {
                std::process::exit(36);
            }
            drop(file);
            if fs::remove_file("/data/quota-test").is_err() {
                std::process::exit(37);
            }
            let mut inode_exhausted = false;
            for i in 0..256 {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(format!("/data/inode-{i}"))
                {
                    Ok(_) => (),
                    Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                        inode_exhausted = true;
                        break;
                    }
                    Err(_) => std::process::exit(38),
                }
            }
            if !inode_exhausted {
                std::process::exit(39);
            }
        }
        Some("pids") => unsafe {
            let mut children = Vec::new();
            let mut exhausted = false;
            for _ in 0..64 {
                let pid = libc::fork();
                if pid == 0 {
                    loop {
                        libc::pause();
                    }
                }
                if pid < 0 {
                    if *libc::__errno_location() == libc::EAGAIN {
                        exhausted = true;
                    }
                    break;
                }
                children.push(pid);
            }
            let mut clean = true;
            for &pid in &children {
                if libc::kill(pid, libc::SIGKILL) != 0 {
                    clean = false;
                }
            }
            for pid in children {
                loop {
                    let mut status = 0;
                    let result = libc::waitpid(pid, &mut status, 0);
                    if result == pid {
                        if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
                            clean = false;
                        }
                        break;
                    }
                    if result < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    clean = false;
                    break;
                }
            }
            if !exhausted || !clean {
                std::process::exit(40);
            }
        },
        Some("memory") => unsafe {
            let marker = b"M";
            loop {
                let n = libc::write(1, marker.as_ptr().cast(), 1);
                if n == 1 {
                    break;
                }
                if n < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(41);
            }
            const SIZE: usize = 64 * 1024 * 1024;
            let memory = libc::mmap(
                ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if memory == libc::MAP_FAILED {
                libc::_exit(42);
            }
            for offset in (0..SIZE).step_by(4096) {
                ptr::write_volatile((memory as *mut u8).add(offset), 1);
            }
            // Reaching the end means the expected cgroup OOM did not occur.
            libc::_exit(43);
        },
        Some("output") => {
            let bytes = [b'x'; 4096];
            let mut out = std::io::stdout().lock();
            loop {
                if out.write_all(&bytes).is_err() {
                    std::process::exit(32);
                }
            }
        }
        _ => std::process::exit(33),
    }
}
