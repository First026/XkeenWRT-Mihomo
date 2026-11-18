//! Privileged setup for the fixed disposable-VM probe. Never call from a
//! multithreaded process. The caller has already gated this process in a cgroup.
//! The job has private mount, network, PID, IPC, and UTS namespaces.
#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("validator lab supports only little-endian 64-bit Linux x86_64 and aarch64");

use crate::{ChildFds, Request};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

const UID: libc::uid_t = 65534;
const GID: libc::gid_t = 65534;
// Fixed setup phase plus errno, never a path or configuration value.
static SETUP_STAGE: AtomicI32 = AtomicI32::new(1);

unsafe fn fail(fd: libc::c_int, errno: i32) -> ! {
    let bytes = (errno | (SETUP_STAGE.load(Ordering::Relaxed) << 16)).to_ne_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let n = libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset);
        if n > 0 {
            offset += n as usize;
        } else if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
    libc::_exit(127)
}
unsafe fn check(result: libc::c_int, fd: libc::c_int) {
    if result < 0 {
        fail(fd, *libc::__errno_location());
    }
}
unsafe fn close_checked(fd: libc::c_int, err: libc::c_int) {
    check(libc::close(fd), err);
}
unsafe fn mkdir(path: &CStr, mode: libc::mode_t, err: libc::c_int) {
    check(libc::mkdir(path.as_ptr(), mode), err);
}
fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

// Close every inherited descriptor except the explicitly named pipe ends.
unsafe fn close_others(keep: &[libc::c_int], err: libc::c_int) {
    // close_range covers descriptors even above a lowered RLIMIT_NOFILE.
    let mut sorted = keep.to_vec();
    sorted.sort_unstable();
    let mut start = 3u32;
    for end in sorted
        .into_iter()
        .map(|x| x as u32)
        .chain(std::iter::once(u32::MAX))
    {
        if start < end && libc::syscall(libc::SYS_close_range, start, end - 1, 0u32) < 0 {
            // A lowered rlimit does not prove that higher FDs do not
            // already exist. Reject kernels without close_range.
            fail(err, *libc::__errno_location());
        }
        start = end.saturating_add(1);
    }
}

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
unsafe fn parent_death(err: libc::c_int) {
    let parent = libc::getppid();
    check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL), err);
    if libc::getppid() != parent {
        fail(err, libc::ECHILD);
    }
}
unsafe fn drop_privileges(err: libc::c_int) {
    SETUP_STAGE.store(8, Ordering::Relaxed);
    // Drop bounding capabilities while CAP_SETPCAP is still effective.
    for cap in 0..64 {
        if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 {
            if *libc::__errno_location() == libc::EINVAL {
                break;
            }
            fail(err, *libc::__errno_location());
        }
    }
    check(libc::setgroups(0, ptr::null()), err);
    check(libc::setresgid(GID, GID, GID), err);
    check(libc::setresuid(UID, UID, UID), err);
    parent_death(err);
    let mut hdr = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    check(
        libc::syscall(libc::SYS_capset, &mut hdr, caps.as_ptr()) as i32,
        err,
    );
    check(
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ),
        err,
    );
    check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), err);
    let (mut r, mut e, mut s) = (0, 0, 0);
    check(libc::getresuid(&mut r, &mut e, &mut s), err);
    if (r, e, s) != (UID, UID, UID) {
        fail(err, libc::EPERM);
    }
    check(libc::getresgid(&mut r, &mut e, &mut s), err);
    if (r, e, s) != (GID, GID, GID) || libc::getgroups(0, ptr::null_mut()) != 0 {
        fail(err, libc::EPERM);
    }
    check(
        libc::syscall(libc::SYS_capget, &mut hdr, caps.as_mut_ptr()) as i32,
        err,
    );
    if caps
        .iter()
        .any(|x| x.effective | x.permitted | x.inheritable != 0)
        || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
    {
        fail(err, libc::EPERM);
    }
    for cap in 0..64 {
        let b = libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0);
        if b < 0 && *libc::__errno_location() == libc::EINVAL {
            break;
        }
        if b != 0 {
            fail(err, libc::EPERM);
        }
        let a = libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
        if a != 0 {
            fail(err, libc::EPERM);
        }
    }
}

// Enforce the native audit architecture; this rejects compat ABIs. The x86-64
// filter additionally rejects x32 syscall numbers. clone is allowed only
// without namespace flags; clone3 returns ENOSYS for runtime fallback.
unsafe fn seccomp(err: libc::c_int) {
    SETUP_STAGE.store(9, Ordering::Relaxed);
    const LD: u16 = 0x20;
    const JEQ: u16 = 0x15;
    #[cfg(target_arch = "x86_64")]
    const JGE: u16 = 0x35;
    const JSET: u16 = 0x45;
    const RET: u16 = 0x06;
    const KILL: u32 = 0x80000000;
    const ALLOW: u32 = 0x7fff0000;
    const ERRNO: u32 = 0x00050000;
    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "x86_64")]
    const KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;
    // https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h
    // __NR_kexec_file_load is 294 on AArch64.
    // libc 0.2.191 omits this AArch64 number even though the ABI defines it.
    #[cfg(target_arch = "aarch64")]
    const KEXEC_FILE_LOAD: libc::c_long = 294;
    let mut f = vec![
        ins(LD, 0, 0, 4),
        ins(JEQ, 1, 0, AUDIT_ARCH),
        ins(RET, 0, 0, KILL),
        ins(LD, 0, 0, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    f.extend([ins(JGE, 0, 1, 0x40000000), ins(RET, 0, 0, KILL)]);
    let denied: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_mount_setattr,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        KEXEC_FILE_LOAD,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
    ];
    for &nr in denied {
        f.push(ins(JEQ, 0, 1, nr as u32));
        f.push(ins(RET, 0, 0, ERRNO | libc::EPERM as u32));
    }
    f.push(ins(JEQ, 0, 1, libc::SYS_clone3 as u32));
    f.push(ins(RET, 0, 0, ERRNO | libc::ENOSYS as u32));
    f.push(ins(JEQ, 0, 3, libc::SYS_clone as u32));
    f.push(ins(LD, 0, 0, 16));
    f.push(ins(
        JSET,
        0,
        1,
        (libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWUTS
            | 0x80) as u32,
    ));
    f.push(ins(RET, 0, 0, ERRNO | libc::EPERM as u32));
    f.push(ins(RET, 0, 0, ALLOW));
    let prog = libc::sock_fprog {
        len: f.len() as u16,
        filter: f.as_mut_ptr(),
    };
    check(
        libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog),
        err,
    );
    if libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) != libc::SECCOMP_MODE_FILTER as i32 {
        fail(err, libc::EPERM);
    }
}

unsafe fn stage(request: &Request, err: libc::c_int) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut entries = vec![(
        "config.yaml".to_string(),
        request.config.as_bytes().to_vec(),
    )];
    for asset in &request.assets {
        let data = match STANDARD.decode(&asset.content_base64) {
            Ok(d) => d,
            Err(_) => fail(err, libc::EINVAL),
        };
        entries.push((asset.path.clone(), data));
    }
    for (path, data) in entries {
        let path = Path::new("data").join(path);
        if let Some(parent) = path.parent() {
            if std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)
                .is_err()
            {
                fail(err, libc::EIO);
            }
        }
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            Err(_) => fail(err, libc::EIO),
        };
        if f.write_all(&data).is_err() {
            fail(err, libc::EIO);
        }
    }
}

pub fn run(root: &Path, fds: ChildFds, request: &Request) -> ! {
    unsafe {
        let err = fds.exec_error;
        let root = match CString::new(root.as_os_str().as_bytes()) {
            Ok(v) => v,
            Err(_) => fail(err, libc::EINVAL),
        };
        for fd in [fds.ready, err, fds.status, fds.core] {
            if fd < 3 {
                fail(err, libc::EINVAL);
            }
        }
        if fds.ready == err
            || fds.ready == fds.status
            || err == fds.status
            || [fds.ready, err, fds.status].contains(&fds.core)
        {
            fail(err, libc::EINVAL);
        }
        close_others(&[fds.ready, err, fds.status, fds.core], err);
        SETUP_STAGE.store(2, Ordering::Relaxed);
        for (resource, value) in [
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_NOFILE, 64),
            (libc::RLIMIT_FSIZE, 16 * 1024 * 1024),
            (libc::RLIMIT_CPU, 5),
        ] {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            check(libc::setrlimit(resource, &limit), err);
            let mut actual: libc::rlimit = std::mem::zeroed();
            check(libc::getrlimit(resource, &mut actual), err);
            if actual.rlim_cur != value || actual.rlim_max != value {
                fail(err, libc::EPERM);
            }
        }
        check(libc::fcntl(err, libc::F_SETFD, libc::FD_CLOEXEC), err);
        check(libc::fcntl(fds.ready, libc::F_SETFD, libc::FD_CLOEXEC), err);
        SETUP_STAGE.store(3, Ordering::Relaxed);
        check(
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWPID
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS,
            ),
            err,
        );
        check(
            libc::mount(
                ptr::null(),
                c("/").as_ptr(),
                ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as _,
                ptr::null(),
            ),
            err,
        );
        SETUP_STAGE.store(4, Ordering::Relaxed);
        check(
            libc::mount(
                c("tmpfs").as_ptr(),
                root.as_ptr(),
                c("tmpfs").as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV) as _,
                c("size=16m,nr_inodes=256,mode=755").as_ptr().cast(),
            ),
            err,
        );
        check(libc::chdir(root.as_ptr()), err);
        mkdir(&c("data"), 0o755, err);
        mkdir(&c("bin"), 0o755, err);
        check(libc::chown(c("data").as_ptr(), UID, GID), err);
        stage(request, err);
        let target_name = "bin/mihomo";
        let target = libc::open(
            c(target_name).as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o755,
        );
        check(target, err);
        close_checked(target, err);
        SETUP_STAGE.store(5, Ordering::Relaxed);
        // unshare(CLONE_NEWNS) clones the mount tree. An inherited fd still
        // points at the old tree, so bind-mounting its proc link fails EINVAL.
        // Reopen the exact catalogue path in this namespace, then prove that
        // it is the same verified inode before using the new descriptor.
        let core_path = match mihomo_release::active_release() {
            Ok(Some(release)) => mihomo_release::version_path(release),
            _ => fail(err, libc::EINVAL),
        };
        SETUP_STAGE.store(12, Ordering::Relaxed);
        let namespace_core = libc::open(
            CString::new(core_path.as_os_str().as_bytes())
                .unwrap()
                .as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        );
        check(namespace_core, err);
        let mut pinned: libc::stat = std::mem::zeroed();
        let mut reopened: libc::stat = std::mem::zeroed();
        check(libc::fstat(fds.core, &mut pinned), err);
        check(libc::fstat(namespace_core, &mut reopened), err);
        if pinned.st_dev != reopened.st_dev
            || pinned.st_ino != reopened.st_ino
            || pinned.st_size != reopened.st_size
            || pinned.st_mode != reopened.st_mode
            || pinned.st_uid != reopened.st_uid
            || pinned.st_nlink != reopened.st_nlink
        {
            fail(err, libc::ESTALE);
        }
        let core_source = c(&format!("/proc/self/fd/{namespace_core}"));
        SETUP_STAGE.store(13, Ordering::Relaxed);
        check(
            libc::mount(
                core_source.as_ptr(),
                c(target_name).as_ptr(),
                ptr::null(),
                libc::MS_BIND as _,
                ptr::null(),
            ),
            err,
        );
        SETUP_STAGE.store(11, Ordering::Relaxed);
        check(
            libc::mount(
                ptr::null(),
                c(target_name).as_ptr(),
                ptr::null(),
                (libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV) as _,
                ptr::null(),
            ),
            err,
        );
        close_checked(namespace_core, err);
        close_checked(fds.core, err);
        SETUP_STAGE.store(6, Ordering::Relaxed);
        check(libc::chroot(c(".").as_ptr()), err);
        check(libc::chdir(c("/").as_ptr()), err);
        // The namespace init cannot see its outside parent, so a private pipe
        // proves that parent survived the PDEATHSIG setup race.
        let mut lifeline = [-1; 2];
        SETUP_STAGE.store(7, Ordering::Relaxed);
        check(libc::pipe2(lifeline.as_mut_ptr(), libc::O_CLOEXEC), err);
        let pid = libc::fork();
        check(pid, err);
        if pid > 0 {
            close_checked(lifeline[0], err);
            // The direct child of the supervisor remains in the job cgroup,
            // waits for namespace init, and holds no control-pipe writes.
            close_checked(fds.ready, err);
            close_checked(fds.status, err);
            drop_privileges(err);
            if libc::getppid() == 1 {
                fail(err, libc::ECHILD);
            }
            close_checked(err, 2);
            let mut init_status = 0;
            loop {
                let w = libc::waitpid(pid, &mut init_status, 0);
                if w == pid {
                    break;
                }
                if w < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(127);
            }
            libc::_exit(if libc::WIFEXITED(init_status) {
                libc::WEXITSTATUS(init_status)
            } else {
                127
            });
        }
        close_checked(lifeline[1], err);
        parent_death(err);
        let mut life = libc::pollfd {
            fd: lifeline[0],
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&mut life, 1, 0) != 0 {
            fail(err, libc::ECHILD);
        }
        let mut init_gate = [-1; 2];
        check(libc::pipe2(init_gate.as_mut_ptr(), libc::O_CLOEXEC), err);
        let pid = libc::fork();
        check(pid, err);
        if pid == 0 {
            close_checked(init_gate[1], err);
            let mut gate_byte = 0u8;
            if libc::read(init_gate[0], (&mut gate_byte as *mut u8).cast(), 1) != 1
                || gate_byte != 1
            {
                fail(err, libc::ECHILD);
            }
            close_checked(init_gate[0], err);
            close_checked(lifeline[0], err);
            parent_death(err);
            close_checked(fds.status, err);
            drop_privileges(err);
            seccomp(err);
            let byte = [1u8];
            if libc::write(fds.ready, byte.as_ptr().cast(), 1) != 1 {
                fail(err, libc::EIO);
            }
            close_checked(fds.ready, err);
            let env = [ptr::null()];
            SETUP_STAGE.store(10, Ordering::Relaxed);
            let args = [
                c("/bin/mihomo"),
                c("-t"),
                c("-d"),
                c("/data"),
                c("-f"),
                c("/data/config.yaml"),
            ];
            let mut argv: Vec<_> = args.iter().map(|arg| arg.as_ptr()).collect();
            argv.push(ptr::null());
            libc::execve(args[0].as_ptr(), argv.as_ptr(), env.as_ptr());
            fail(err, *libc::__errno_location());
        }
        close_checked(init_gate[0], err);
        close_checked(fds.ready, err);
        // Retain exec_error until setup succeeds so failures remain observable.
        drop_privileges(err);
        if libc::poll(&mut life, 1, 0) != 0 {
            fail(err, libc::ECHILD);
        }
        close_checked(lifeline[0], err);
        if libc::write(init_gate[1], [1u8].as_ptr().cast(), 1) != 1 {
            fail(err, libc::EIO);
        }
        close_checked(init_gate[1], err);
        if libc::close(err) < 0 {
            libc::_exit(127);
        }
        let mut status = 0;
        loop {
            let w = libc::waitpid(pid, &mut status, 0);
            if w == pid {
                break;
            }
            if w < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(127);
        }
        let b = status.to_ne_bytes();
        let mut off = 0;
        while off < b.len() {
            let n = libc::write(fds.status, b[off..].as_ptr().cast(), b.len() - off);
            if n > 0 {
                off += n as usize;
            } else if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            } else {
                libc::_exit(127);
            }
        }
        libc::_exit(0)
    }
}
