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

use crate::protocol::{ChildFds, Scenario};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

const UID: libc::uid_t = 65534;
const GID: libc::gid_t = 65534;
const SOURCE: &[u8] = b"/usr/libexec/xkeenwrt-lab/isolation-probe\0";
const MIHOMO_SOURCE: &[u8] = b"/usr/libexec/xkeenwrt-lab/mihomo\0";
const VALID_CONFIG: &[u8] = include_bytes!("../fixtures/mihomo-valid.yaml");
const INVALID_CONFIG: &[u8] = include_bytes!("../fixtures/mihomo-invalid.yaml");
const MISSING_ASSET_CONFIG: &[u8] = include_bytes!("../fixtures/mihomo-missing-asset.yaml");
const FILE_CONFIG: &[u8] = include_bytes!("../fixtures/mihomo-file.yaml");
// Existing synthetic lab fixture, shared with the earlier parser experiment.
const AWG_V3_CONFIG: &[u8] = include_bytes!("../../amnezia-v3.yaml");
const AWG_LEGACY_CONFIG: &[u8] = include_bytes!("../../amnezia-legacy.yaml");
// RFC 8032 test-vector seed, exclusively for this synthetic lab fixture.
const FIXTURE_KEY: &[u8] = include_bytes!("../fixtures/synthetic-ed25519-key.pem");

unsafe fn fail(fd: libc::c_int, errno: i32) -> ! {
    let bytes = errno.to_ne_bytes();
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
unsafe fn drop_privileges(err: libc::c_int) {
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

pub fn run(root: &Path, fds: ChildFds, scenario: Scenario) -> ! {
    unsafe {
        let err = fds.exec_error;
        if matches!(scenario, Scenario::SetupDenied) {
            fail(err, libc::EPERM);
        }
        let root = match CString::new(root.as_os_str().as_bytes()) {
            Ok(v) => v,
            Err(_) => fail(err, libc::EINVAL),
        };
        for fd in [fds.ready, err, fds.status] {
            if fd < 3 {
                fail(err, libc::EINVAL);
            }
        }
        if fds.ready == err || fds.ready == fds.status || err == fds.status {
            fail(err, libc::EINVAL);
        }
        close_others(&[fds.ready, err, fds.status], err);
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
        check(
            libc::mount(
                c("tmpfs").as_ptr(),
                root.as_ptr(),
                c("tmpfs").as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV) as _,
                c("size=8m,nr_inodes=128,mode=755").as_ptr().cast(),
            ),
            err,
        );
        check(libc::chdir(root.as_ptr()), err);
        mkdir(&c("data"), 0o755, err);
        mkdir(&c("bin"), 0o755, err);
        check(libc::chown(c("data").as_ptr(), UID, GID), err);
        let marker = libc::open(
            c("data/probe-marker").as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o644,
        );
        check(marker, err);
        let b = b"probe-v1\n";
        if libc::write(marker, b.as_ptr().cast(), b.len()) != b.len() as isize {
            fail(err, libc::EIO);
        }
        close_checked(marker, err);
        let mihomo = matches!(
            scenario,
            Scenario::MihomoValid
                | Scenario::MihomoInvalid
                | Scenario::MihomoInvalidUnreadable
                | Scenario::MihomoMissingAsset
                | Scenario::MihomoFileContained
                | Scenario::MihomoFileEscape
                | Scenario::MihomoAwgV3
                | Scenario::MihomoAwgLegacy
        );
        if mihomo {
            let config = libc::open(
                c("data/config.yaml").as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o644,
            );
            check(config, err);
            let fixture = if matches!(
                scenario,
                Scenario::MihomoInvalid | Scenario::MihomoInvalidUnreadable
            ) {
                INVALID_CONFIG
            } else if matches!(scenario, Scenario::MihomoMissingAsset) {
                MISSING_ASSET_CONFIG
            } else if matches!(
                scenario,
                Scenario::MihomoFileContained | Scenario::MihomoFileEscape
            ) {
                FILE_CONFIG
            } else if matches!(scenario, Scenario::MihomoAwgV3) {
                AWG_V3_CONFIG
            } else if matches!(scenario, Scenario::MihomoAwgLegacy) {
                AWG_LEGACY_CONFIG
            } else {
                VALID_CONFIG
            };
            if libc::write(config, fixture.as_ptr().cast(), fixture.len()) != fixture.len() as isize
            {
                fail(err, libc::EIO);
            }
            if matches!(scenario, Scenario::MihomoInvalidUnreadable) {
                check(libc::fchmod(config, 0), err);
            }
            close_checked(config, err);
            if matches!(scenario, Scenario::MihomoFileContained) {
                let key = libc::open(
                    c("data/key.pem").as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                    0o644,
                );
                check(key, err);
                if libc::write(key, FIXTURE_KEY.as_ptr().cast(), FIXTURE_KEY.len())
                    != FIXTURE_KEY.len() as isize
                {
                    fail(err, libc::EIO);
                }
                close_checked(key, err);
            } else if matches!(scenario, Scenario::MihomoFileEscape) {
                check(
                    libc::symlink(
                        c("/tmp/xkeenwrt-isolation-key.pem").as_ptr(),
                        c("data/key.pem").as_ptr(),
                    ),
                    err,
                );
            }
        }
        let target_name = if mihomo { "bin/mihomo" } else { "bin/probe" };
        let target = libc::open(
            c(target_name).as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o755,
        );
        check(target, err);
        close_checked(target, err);
        check(
            libc::mount(
                if mihomo { MIHOMO_SOURCE } else { SOURCE }.as_ptr().cast(),
                c(target_name).as_ptr(),
                ptr::null(),
                libc::MS_BIND as _,
                ptr::null(),
            ),
            err,
        );
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
        check(libc::chroot(c(".").as_ptr()), err);
        check(libc::chdir(c("/").as_ptr()), err);
        let pid = libc::fork();
        check(pid, err);
        if pid > 0 {
            // The direct child of the supervisor remains in the job cgroup,
            // waits for namespace init, and holds no control-pipe writes.
            close_checked(fds.ready, err);
            close_checked(fds.status, err);
            drop_privileges(err);
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
        // This process is PID 1 inside the new namespace and reaps the payload.
        let pid = libc::fork();
        check(pid, err);
        if pid == 0 {
            close_checked(fds.status, err);
            drop_privileges(err);
            seccomp(err);
            let byte = [1u8];
            if libc::write(fds.ready, byte.as_ptr().cast(), 1) != 1 {
                fail(err, libc::EIO);
            }
            close_checked(fds.ready, err);
            let env = [ptr::null()];
            if mihomo {
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
            } else {
                let path = c("/bin/probe");
                let mode = c(match scenario {
                    Scenario::Probe => "probe",
                    Scenario::Timeout => "timeout",
                    Scenario::Output => "output",
                    Scenario::Tmpfs => "tmpfs",
                    Scenario::Pids => "pids",
                    Scenario::Memory => "memory",
                    Scenario::SetupDenied
                    | Scenario::MihomoValid
                    | Scenario::MihomoInvalid
                    | Scenario::MihomoInvalidUnreadable
                    | Scenario::MihomoMissingAsset
                    | Scenario::MihomoFileContained
                    | Scenario::MihomoFileEscape
                    | Scenario::MihomoAwgV3
                    | Scenario::MihomoAwgLegacy => fail(err, libc::EPERM),
                });
                let argv = [path.as_ptr(), mode.as_ptr(), ptr::null()];
                libc::execve(path.as_ptr(), argv.as_ptr(), env.as_ptr());
            }
            fail(err, *libc::__errno_location());
        }
        close_checked(fds.ready, err);
        // Retain exec_error until setup succeeds so failures remain observable.
        drop_privileges(err);
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
