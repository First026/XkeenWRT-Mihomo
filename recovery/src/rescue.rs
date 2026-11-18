//! Durable rescue provisioning; all destinations and payloads are fixed.
//!
//! The caller must authenticate the source against the package integrity
//! manifest before calling this module. Existing resources are never replaced.
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const INIT: &[u8] = include_bytes!("../assets/xkeenwrt-rescue.init");
const MAX_EXEC: u64 = 64 * 1024 * 1024;
const META: &str = "identity";
const BINARY: &str = "xkeenwrt-recovery";
const INIT_NAME: &str = "xkeenwrt-rescue";

fn error() -> io::Error {
    io::Error::other("rescue integrity unavailable")
}
fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| error())
}
fn open_at(dir: &File, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c(name)?.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn directory(dir: &File, name: &str, exact: Option<u32>) -> io::Result<File> {
    let f = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let m = f.metadata()?;
    if !m.is_dir()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || exact.is_some_and(|v| m.mode() & 0o777 != v)
    {
        return Err(error());
    }
    Ok(f)
}
fn validate_file(file: &File, mode: u32, limit: u64) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != mode
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > limit
    {
        return Err(error());
    }
    Ok(())
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hash(file: &File) -> io::Result<String> {
    let size = file.metadata()?.len();
    if size == 0 || size > MAX_EXEC {
        return Err(error());
    }
    let mut h = Sha256::new();
    let mut offset = 0;
    let mut b = [0; 32768];
    while offset < size {
        let n = file.read_at(&mut b, offset)?;
        if n == 0 {
            return Err(error());
        }
        h.update(&b[..n]);
        offset += n as u64;
    }
    if file.metadata()?.len() != size {
        return Err(error());
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
// ELF64 little-endian native static binary, with bounded program-header table.
fn static_elf(f: &File) -> io::Result<()> {
    let len = f.metadata()?.len();
    let mut h = [0u8; 64];
    if f.read_at(&mut h, 0)? != h.len()
        || &h[..4] != b"\x7fELF"
        || h[4] != 2
        || h[5] != 1
        || h[6] != 1
    {
        return Err(error());
    }
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = 62;
    #[cfg(target_arch = "aarch64")]
    const MACHINE: u16 = 183;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("unsupported rescue architecture");
    if u16::from_le_bytes([h[18], h[19]]) != MACHINE
        || !matches!(u16::from_le_bytes([h[16], h[17]]), 2 | 3)
    {
        return Err(error());
    }
    let off = u64::from_le_bytes(h[32..40].try_into().unwrap());
    let entsize = u16::from_le_bytes([h[54], h[55]]) as u64;
    let count = u16::from_le_bytes([h[56], h[57]]) as u64;
    if entsize != 56
        || count == 0
        || count > 128
        || off.checked_add(entsize * count).is_none_or(|end| end > len)
    {
        return Err(error());
    }
    for i in 0..count {
        let mut p = [0u8; 4];
        if f.read_at(&mut p, off + i * entsize)? != 4 || u32::from_le_bytes(p) == 3 {
            return Err(error());
        }
    }
    Ok(())
}
fn read_exact_bounded(mut f: &File, limit: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(error());
    }
    Ok(out)
}
fn identity(hash: &str, build_id: &str) -> io::Result<Vec<u8>> {
    if !valid_digest(hash) || !valid_digest(build_id) {
        return Err(error());
    }
    Ok(format!("xkeenwrt-rescue-v1\nbuild_id={build_id}\nsha256={hash}\n").into_bytes())
}
fn entry_exists(dir: &File, name: &str) -> io::Result<bool> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c(name)?.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(e)
    }
}
fn ensure_not_removing(config: &File) -> io::Result<()> {
    if entry_exists(config, "removal.json")? {
        Err(error())
    } else {
        Ok(())
    }
}
fn lifecycle_exists(config: &File) -> io::Result<bool> {
    Ok(entry_exists(config, "recovery.json")?
        || entry_exists(config, "removal.json")?
        || entry_exists(config, "lifecycle.json")?)
}
struct Dirs {
    root: File,
    rescue: File,
    init: File,
    rc: File,
}
fn dirs(create: bool, strict_release: bool) -> io::Result<Dirs> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(error());
    }
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let root = unsafe { File::from_raw_fd(root_fd) };
    let etc = directory(&root, "etc", None)?;
    let release = open_at(
        &etc,
        "openwrt_release",
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    let m = release.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 || m.len() > 4096 {
        return Err(error());
    }
    let release = read_exact_bounded(&release, 4096)?;
    let release = std::str::from_utf8(&release).map_err(|_| error())?;
    if !release.lines().any(|l| l == "DISTRIB_ID='OpenWrt'") {
        return Err(error());
    }
    if strict_release {
        if !release.lines().any(|l| l == "DISTRIB_RELEASE='25.12.6'") {
            return Err(error());
        }
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0
            || unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_bytes() != b"6.12.112"
        {
            return Err(error());
        }
    }
    let config = directory(&etc, "xkeenwrt", Some(0o700))?;
    if !check_existing(
        &config,
        "recovery-enabled",
        0o600,
        b"xkeenwrt-recovery-v1\n",
    )? {
        return Err(error());
    }
    let init = directory(&etc, "init.d", None)?;
    let rc = directory(&etc, "rc.d", None)?;
    if create {
        // Never establish a fresh rescue installation over existing lifecycle
        // state: the older helper may be the only compatible cleanup path.
        if lifecycle_exists(&config)? && !entry_exists(&config, "rescue")? {
            return Err(error());
        }
        let n = unsafe { libc::mkdirat(config.as_raw_fd(), c"rescue".as_ptr(), 0o700) };
        if n == 0 {
            config.sync_all()?;
        } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
            return Err(io::Error::last_os_error());
        }
    }
    let rescue = directory(&config, "rescue", Some(0o700))?;
    Ok(Dirs {
        root: config,
        rescue,
        init,
        rc,
    })
}
fn check_existing(dir: &File, name: &str, mode: u32, expected: &[u8]) -> io::Result<bool> {
    let file = match open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    validate_file(&file, mode, expected.len() as u64)?;
    if read_exact_bounded(&file, expected.len() as u64)? != expected {
        return Err(error());
    }
    Ok(true)
}
fn check_binary(dir: &File, digest: &str) -> io::Result<Option<File>> {
    let f = match open_at(dir, BINARY, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    validate_file(&f, 0o700, MAX_EXEC)?;
    static_elf(&f)?;
    if hash(&f)? != digest {
        return Err(error());
    }
    Ok(Some(f))
}
const BOOT_TARGET: &str = "/etc/init.d/xkeenwrt-rescue";
const BOOT_LINKS: [&str; 2] = ["S09xkeenwrt-rescue", "K91xkeenwrt-rescue"];
fn check_link(dir: &File, name: &str) -> io::Result<bool> {
    let name = c(name)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(e);
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFLNK || stat.st_uid != 0 || stat.st_nlink != 1 {
        return Err(error());
    }
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 || &buf[..n as usize] != BOOT_TARGET.as_bytes() {
        return Err(error());
    }
    Ok(true)
}
fn create_link(dir: &File, name: &str) -> io::Result<()> {
    let n =
        unsafe { libc::symlinkat(c(BOOT_TARGET)?.as_ptr(), dir.as_raw_fd(), c(name)?.as_ptr()) };
    if n != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.sync_all()
}
// A same-directory rename with NOREPLACE atomically publishes exactly one
// inode, with no point where a durable hard-link count can be two.
fn publish(
    dir: &File,
    dest: &str,
    mode: u32,
    mut fill: impl FnMut(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let name = format!(".xkeenwrt-rescue-{}-{}", std::process::id(), dest);
    let mut f = open_at(
        dir,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let result = (|| {
        fill(&mut f)?;
        if unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        f.sync_all()?;
        let n = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                c(&name)?.as_ptr(),
                dir.as_raw_fd(),
                c(dest)?.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if n != 0 {
            return Err(io::Error::last_os_error());
        }
        dir.sync_all()
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), c(&name)?.as_ptr(), 0);
        }
    }
    result
}
/// Provision a root-private immutable rescue and return its validated descriptor.
pub fn provision(pinned_exe: &File, expected_sha256: &str, build_id: &str) -> io::Result<File> {
    let id = identity(expected_sha256, build_id)?;
    validate_file(pinned_exe, 0o755, MAX_EXEC)?;
    static_elf(pinned_exe)?;
    if hash(pinned_exe)? != expected_sha256 {
        return Err(error());
    }
    let d = dirs(true, true)?;
    ensure_not_removing(&d.root)?;
    let binary = check_binary(&d.rescue, expected_sha256)?;
    let have_id = check_existing(&d.rescue, META, 0o600, &id)?;
    let have_init = check_existing(&d.init, INIT_NAME, 0o755, INIT)?;
    let mut boot_links = [false; 2];
    for (i, name) in BOOT_LINKS.iter().enumerate() {
        boot_links[i] = check_link(&d.rc, name)?;
    }
    if lifecycle_exists(&d.root)?
        && (binary.is_none() || !have_id || !have_init || boot_links.iter().any(|present| !present))
    {
        return Err(error());
    }
    if binary.is_none() {
        ensure_not_removing(&d.root)?;
        publish(&d.rescue, BINARY, 0o700, |out| {
            let mut pos = 0;
            let len = pinned_exe.metadata()?.len();
            let mut buf = [0u8; 32768];
            while pos < len {
                let n = pinned_exe.read_at(&mut buf, pos)?;
                if n == 0 {
                    return Err(error());
                }
                out.write_all(&buf[..n])?;
                pos += n as u64;
            }
            if hash(out)? != expected_sha256 {
                return Err(error());
            }
            Ok(())
        })?;
    }
    if !have_id {
        ensure_not_removing(&d.root)?;
        publish(&d.rescue, META, 0o600, |f| f.write_all(&id))?;
    }
    if !have_init {
        ensure_not_removing(&d.root)?;
        publish(&d.init, INIT_NAME, 0o755, |f| f.write_all(INIT))?;
    }
    for (name, present) in BOOT_LINKS.iter().zip(boot_links) {
        if !present {
            ensure_not_removing(&d.root)?;
            create_link(&d.rc, name)?;
        }
    }
    d.root.sync_all()?;
    ensure_not_removing(&d.root)?;
    let verified = verify(expected_sha256, build_id)?;
    ensure_not_removing(&d.root)?;
    Ok(verified)
}
/// Verify all persistent rescue assets and return an authenticated executable FD.
pub fn verify(expected_sha256: &str, build_id: &str) -> io::Result<File> {
    let id = identity(expected_sha256, build_id)?;
    let d = dirs(false, true)?;
    if !check_existing(&d.rescue, META, 0o600, &id)?
        || !check_existing(&d.init, INIT_NAME, 0o755, INIT)?
    {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if !check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    check_binary(&d.rescue, expected_sha256)?.ok_or_else(error)
}

/// Verify only the init program and boot links against this executable's
/// compiled template. This remains usable after a package upgrade/removal.
pub fn verify_init_template() -> io::Result<()> {
    let d = dirs(false, false)?;
    if !check_existing(&d.init, INIT_NAME, 0o755, INIT)? {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if !check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    Ok(())
}

/// Authenticate this running persistent rescue against its own root-private
/// installation metadata, including the inode actually executing. This cleanup
/// path does not rely on files belonging to a currently installed package.
pub fn verify_self() -> io::Result<File> {
    let d = dirs(false, false)?;
    let id_file = open_at(&d.rescue, META, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    validate_file(&id_file, 0o600, 256)?;
    let contents = read_exact_bounded(&id_file, 256)?;
    let text = std::str::from_utf8(&contents).map_err(|_| error())?;
    let mut lines = text.lines();
    if lines.next() != Some("xkeenwrt-rescue-v1") {
        return Err(error());
    }
    let build_id = lines
        .next()
        .and_then(|v| v.strip_prefix("build_id="))
        .ok_or_else(error)?;
    let digest = lines
        .next()
        .and_then(|v| v.strip_prefix("sha256="))
        .ok_or_else(error)?;
    if lines.next().is_some() || contents != identity(digest, build_id)? {
        return Err(error());
    }
    if !check_existing(&d.init, INIT_NAME, 0o755, INIT)? {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if !check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    let executable = check_binary(&d.rescue, digest)?.ok_or_else(error)?;
    let running = File::open("/proc/self/exe")?;
    let a = executable.metadata()?;
    let b = running.metadata()?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(error());
    }
    Ok(executable)
}

/// Replacement describes one already-approved upgrade receipt and two exact
/// builds. The caller never supplies paths or commands.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeSpec {
    pub owner_id: String,
    pub request_id: String,
    pub old_sha256: String,
    pub old_build_id: String,
    pub new_sha256: String,
    pub new_build_id: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePhase {
    Prepared,
    Exchanged,
    Finalizing,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeIntent {
    pub version: u32,
    pub spec: UpgradeSpec,
    pub phase: UpgradePhase,
}
const INTENT: &str = "rescue-replacement.json";
const NEXT: &str = ".rescue-next";

/// Fixed, bounded platform operations supplied by runtime. No arbitrary
/// commands or caller-selected filesystem paths may cross this interface.
pub trait UpgradeAdapter {
    fn verify_quiescent(&mut self, spec: &UpgradeSpec) -> io::Result<()>;
    fn stop_old(&mut self, old: &File, spec: &UpgradeSpec) -> io::Result<()>;
    fn start_new_ready(&mut self, new: &File, spec: &UpgradeSpec) -> io::Result<()>;
    fn verify_new_ready(&mut self, new: &File, spec: &UpgradeSpec) -> io::Result<()>;
}
impl UpgradeSpec {
    pub fn valid(&self) -> bool {
        crate::valid_owner(&self.owner_id)
            && crate::valid_owner(&self.request_id)
            && valid_digest(&self.old_sha256)
            && valid_digest(&self.old_build_id)
            && valid_digest(&self.new_sha256)
            && valid_digest(&self.new_build_id)
            && (self.old_sha256 != self.new_sha256 || self.old_build_id != self.new_build_id)
    }
}
fn load_intent(root: &File) -> io::Result<Option<UpgradeIntent>> {
    let f = match open_at(root, INTENT, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    validate_file(&f, 0o600, 4096)?;
    let b = read_exact_bounded(&f, 4096)?;
    let intent: UpgradeIntent = serde_json::from_slice(&b).map_err(|_| error())?;
    if intent.version != 1 || !intent.spec.valid() {
        return Err(error());
    }
    Ok(Some(intent))
}
/// Read the validated durable fence to resume an interrupted replacement.
/// This performs no mutation; all callers must treat Some as a global fence.
pub fn upgrade_status() -> io::Result<Option<UpgradeIntent>> {
    let d = dirs(false, true)?;
    load_intent(&d.root)
}
/// Read-only fence lookup for the persistent cleanup supervisor, including
/// after an OS release change. Publication still requires strict release.
pub fn upgrade_status_for_supervisor() -> io::Result<Option<UpgradeIntent>> {
    let d = dirs(false, false)?;
    load_intent(&d.root)
}
fn store_intent(
    root: &File,
    intent: &UpgradeIntent,
    previous: Option<&UpgradeIntent>,
) -> io::Result<()> {
    if load_intent(root)?.as_ref() != previous {
        return Err(error());
    }
    let bytes = serde_json::to_vec(intent).map_err(io::Error::other)?;
    if bytes.len() > 4096 {
        return Err(error());
    }
    if previous.is_none() {
        return publish(root, INTENT, 0o600, |f| f.write_all(&bytes));
    }
    let temp = format!(".rescue-replacement-{}", std::process::id());
    let mut f = open_at(
        root,
        &temp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let result = (|| {
        f.write_all(&bytes)?;
        if unsafe { libc::fchmod(f.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        f.sync_all()?;
        if load_intent(root)?.as_ref() != previous {
            return Err(error());
        }
        let n = unsafe {
            libc::renameat(
                root.as_raw_fd(),
                c(&temp)?.as_ptr(),
                root.as_raw_fd(),
                c(INTENT)?.as_ptr(),
            )
        };
        if n != 0 {
            return Err(io::Error::last_os_error());
        }
        root.sync_all()
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(root.as_raw_fd(), c(&temp)?.as_ptr(), 0);
        }
    }
    result
}
fn bundle(dir: &File, sha: &str, build: &str) -> io::Result<Option<File>> {
    let id = identity(sha, build)?;
    let file = match open_at(dir, META, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    validate_file(&file, 0o600, 256)?;
    if read_exact_bounded(&file, 256)? != id {
        return Ok(None);
    }
    check_binary(dir, sha)
}
fn dir_if_exists(root: &File, name: &str) -> io::Result<Option<File>> {
    match directory(root, name, Some(0o700)) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn check_init(d: &Dirs) -> io::Result<()> {
    if !check_existing(&d.init, INIT_NAME, 0o755, INIT)? {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if !check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    Ok(())
}
fn entries(dir: &File) -> io::Result<std::collections::BTreeSet<String>> {
    let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name().into_string().map_err(|_| error())?;
        if !names.insert(name) {
            return Err(error());
        }
    }
    Ok(names)
}
fn exact_entries(dir: &File, expected: &[&str]) -> io::Result<()> {
    let actual = entries(dir)?;
    let expected = expected.iter().map(|v| (*v).to_owned()).collect();
    if actual != expected {
        return Err(error());
    }
    Ok(())
}
fn bundle_identity(dir: &File) -> io::Result<(String, String)> {
    let file = open_at(dir, META, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    validate_file(&file, 0o600, 256)?;
    let bytes = read_exact_bounded(&file, 256)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| error())?;
    let mut lines = text.lines();
    if lines.next() != Some("xkeenwrt-rescue-v1") {
        return Err(error());
    }
    let build = lines
        .next()
        .and_then(|v| v.strip_prefix("build_id="))
        .filter(|v| valid_digest(v))
        .ok_or_else(error)?;
    let digest = lines
        .next()
        .and_then(|v| v.strip_prefix("sha256="))
        .filter(|v| valid_digest(v))
        .ok_or_else(error)?;
    if lines.next().is_some() || bytes != identity(digest, build)? {
        return Err(error());
    }
    if check_binary(dir, digest)?.is_none() {
        return Err(error());
    }
    exact_entries(dir, &[BINARY, META])?;
    Ok((digest.to_owned(), build.to_owned()))
}
fn remove_bundle(root: &File, name: &str, dir: File) -> io::Result<()> {
    exact_entries(&dir, &[BINARY, META])?;
    for file in [BINARY, META] {
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c(file)?.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    dir.sync_all()?;
    drop(dir);
    if unsafe { libc::unlinkat(root.as_raw_fd(), c(name)?.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    root.sync_all()
}

/// Remove the persistent rescue only after the caller has authenticated and
/// stopped its supervisor and held the shared lifecycle locks. The exact
/// completed Remove receipt and disabled/never-enabled network state are
/// checked again here before any rescue asset is unlinked.
pub fn finalize_remove_assets(owner: &str, request_id: &str) -> io::Result<()> {
    if !crate::valid_owner(owner) || !crate::valid_owner(request_id) {
        return Err(error());
    }
    let _ = verify_self()?;
    let root_path = std::path::Path::new("/etc/xkeenwrt");
    crate::verify_remove_after_integrity_check(root_path, owner, request_id)?;
    let receipt = crate::read_lifecycle_request(root_path)?.ok_or_else(error)?;
    if receipt.owner_id != owner
        || receipt.request_id.as_deref() != Some(request_id)
        || receipt.kind != crate::LifecycleKind::Remove
        || receipt.state != crate::LifecycleState::CleanupComplete
    {
        return Err(error());
    }
    let d = dirs(false, false)?;
    if load_intent(&d.root)?.is_some() || entry_exists(&d.root, NEXT)? {
        return Err(error());
    }
    exact_entries(&d.rescue, &[BINARY, META])?;
    let (digest, build_id) = bundle_identity(&d.rescue)?;
    if bundle(&d.rescue, &digest, &build_id)?.is_none() {
        return Err(error());
    }
    check_init(&d)?;

    let mut archives = Vec::new();
    let root_names = entries(&d.root)?;
    for name in &root_names {
        if name.starts_with(".rescue") || name.starts_with(".xkeenwrt-rescue") {
            return Err(error());
        }
        if let Some(request) = name.strip_prefix("rescue-previous-") {
            if !crate::valid_owner(request) {
                return Err(error());
            }
            let archive = dir_if_exists(&d.root, name)?.ok_or_else(error)?;
            let (sha, build) = bundle_identity(&archive)?;
            if bundle(&archive, &sha, &build)?.is_none() {
                return Err(error());
            }
            archives.push((name.clone(), archive));
        }
    }

    // Recheck the public service links before removing any of them.
    for name in BOOT_LINKS {
        if !check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    if !check_existing(&d.init, INIT_NAME, 0o755, INIT)? {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if unsafe { libc::unlinkat(d.rc.as_raw_fd(), c(name)?.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    d.rc.sync_all()?;
    if unsafe { libc::unlinkat(d.init.as_raw_fd(), c(INIT_NAME)?.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    d.init.sync_all()?;

    let active = dir_if_exists(&d.root, "rescue")?.ok_or_else(error)?;
    remove_bundle(&d.root, "rescue", active)?;
    for (name, dir) in archives {
        remove_bundle(&d.root, &name, dir)?;
    }
    if entry_exists(&d.root, "rescue")? {
        return Err(error());
    }
    for name in BOOT_LINKS {
        if check_link(&d.rc, name)? {
            return Err(error());
        }
    }
    Ok(())
}
fn stage_new(root: &File, exe: &File, spec: &UpgradeSpec) -> io::Result<File> {
    let stage = match dir_if_exists(root, NEXT)? {
        Some(f) => f,
        None => {
            let n = unsafe { libc::mkdirat(root.as_raw_fd(), c(NEXT)?.as_ptr(), 0o700) };
            if n != 0 {
                return Err(io::Error::last_os_error());
            }
            root.sync_all()?;
            directory(root, NEXT, Some(0o700))?
        }
    };
    let current = check_binary(&stage, &spec.new_sha256)?;
    let id = identity(&spec.new_sha256, &spec.new_build_id)?;
    let have_id = check_existing(&stage, META, 0o600, &id)?;
    if current.is_none() {
        publish(&stage, BINARY, 0o700, |out| {
            let len = exe.metadata()?.len();
            let mut pos = 0;
            let mut buf = [0; 32768];
            while pos < len {
                let n = exe.read_at(&mut buf, pos)?;
                if n == 0 {
                    return Err(error());
                }
                out.write_all(&buf[..n])?;
                pos += n as u64;
            }
            if hash(out)? != spec.new_sha256 {
                return Err(error());
            }
            Ok(())
        })?;
    }
    if !have_id {
        publish(&stage, META, 0o600, |f| f.write_all(&id))?;
    }
    bundle(&stage, &spec.new_sha256, &spec.new_build_id)?.ok_or_else(error)?;
    Ok(stage)
}
fn archive_capacity(root: &File) -> io::Result<()> {
    let path = format!("/proc/self/fd/{}", root.as_raw_fd());
    let mut count = 0usize;
    for item in std::fs::read_dir(path)? {
        let name = item?.file_name();
        let Some(name) = name.to_str() else {
            return Err(error());
        };
        if name.starts_with("rescue-previous-") {
            count += 1;
            if count >= 8 {
                return Err(error());
            }
        }
    }
    Ok(())
}
fn receipt(spec: &UpgradeSpec) -> io::Result<()> {
    crate::verify_upgrade_after_integrity_check(
        std::path::Path::new("/etc/xkeenwrt"),
        &spec.owner_id,
        &spec.request_id,
    )
}
fn layout(d: &Dirs, spec: &UpgradeSpec) -> io::Result<(File, File, bool)> {
    let archived = format!("rescue-previous-{}", spec.request_id);
    let next_live = dir_if_exists(&d.root, NEXT)?;
    let old_archive = dir_if_exists(&d.root, &archived)?;
    let next = match (next_live, old_archive) {
        (Some(f), None) | (None, Some(f)) => f,
        _ => return Err(error()),
    };
    let old_active = bundle(&d.rescue, &spec.old_sha256, &spec.old_build_id)?;
    let new_active = bundle(&d.rescue, &spec.new_sha256, &spec.new_build_id)?;
    let old_next = bundle(&next, &spec.old_sha256, &spec.old_build_id)?;
    let new_next = bundle(&next, &spec.new_sha256, &spec.new_build_id)?;
    match (old_active, new_active, old_next, new_next) {
        (Some(old), None, None, Some(new)) => Ok((old, new, false)),
        (None, Some(new), Some(old), None) => Ok((old, new, true)),
        _ => Err(error()),
    }
}

/// Phase A: call under mutation.lock. The caller must already have verified the
/// package pair and passed an authenticated FD for the new recovery executable.
/// A durable intent fences new mutations before any replacement begins.
pub fn prepare_upgrade(
    spec: &UpgradeSpec,
    pinned_new: &File,
    adapter: &mut impl UpgradeAdapter,
) -> io::Result<()> {
    if !spec.valid() {
        return Err(error());
    }
    validate_file(pinned_new, 0o755, MAX_EXEC)?;
    static_elf(pinned_new)?;
    if hash(pinned_new)? != spec.new_sha256 {
        return Err(error());
    }
    let d = dirs(false, true)?;
    check_init(&d)?;
    receipt(spec)?;
    adapter.verify_quiescent(spec)?;
    let mut intent = match load_intent(&d.root)? {
        Some(v) if v.spec == *spec => v,
        Some(_) => return Err(error()),
        None => {
            archive_capacity(&d.root)?;
            if dir_if_exists(&d.root, NEXT)?.is_some() {
                return Err(error());
            }
            bundle(&d.rescue, &spec.old_sha256, &spec.old_build_id)?.ok_or_else(error)?;
            let v = UpgradeIntent {
                version: 1,
                spec: spec.clone(),
                phase: UpgradePhase::Prepared,
            };
            store_intent(&d.root, &v, None)?;
            v
        }
    };
    if intent.phase == UpgradePhase::Finalizing {
        return Err(error());
    }
    let active_old = bundle(&d.rescue, &spec.old_sha256, &spec.old_build_id)?;
    if active_old.is_some() {
        stage_new(&d.root, pinned_new, spec)?;
    }
    let (old, _, exchanged) = layout(&d, spec)?;
    receipt(spec)?;
    adapter.stop_old(&old, spec)?;
    adapter.verify_quiescent(spec)?;
    receipt(spec)?;
    if !exchanged {
        let n = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                d.root.as_raw_fd(),
                c"rescue".as_ptr(),
                d.root.as_raw_fd(),
                c(NEXT)?.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if n != 0 {
            return Err(io::Error::last_os_error());
        }
        d.root.sync_all()?;
    }
    // Reopen after exchange: d.rescue remains pinned to the old directory.
    let refreshed = dirs(false, true)?;
    let (_, _, done) = layout(&refreshed, spec)?;
    if !done {
        return Err(error());
    }
    if intent.phase != UpgradePhase::Exchanged {
        let previous = intent.clone();
        intent.phase = UpgradePhase::Exchanged;
        store_intent(&refreshed.root, &intent, Some(&previous))?;
    }
    Ok(())
}
/// Phase B: no mutation.lock is held while procd starts the new supervisor and
/// it publishes READY. A concurrent lifecycle change makes this return error.
pub fn start_upgrade(spec: &UpgradeSpec, adapter: &mut impl UpgradeAdapter) -> io::Result<()> {
    if !spec.valid() {
        return Err(error());
    }
    let d = dirs(false, true)?;
    check_init(&d)?;
    receipt(spec)?;
    let intent = load_intent(&d.root)?.ok_or_else(error)?;
    if intent.spec != *spec || intent.phase != UpgradePhase::Exchanged {
        return Err(error());
    }
    let (_, new, done) = layout(&d, spec)?;
    if !done {
        return Err(error());
    }
    adapter.start_new_ready(&new, spec)?;
    receipt(spec)?;
    if load_intent(&d.root)?.as_ref() != Some(&intent) {
        return Err(error());
    }
    let refreshed = dirs(false, true)?;
    let (_, _, done) = layout(&refreshed, spec)?;
    if !done {
        return Err(error());
    }
    Ok(())
}
/// Phase C begins under mutation.lock. It does not consume the upgrade receipt;
/// the caller may do that only after this finalizing state is durable.
pub fn finish_upgrade(spec: &UpgradeSpec, adapter: &mut impl UpgradeAdapter) -> io::Result<()> {
    if !spec.valid() {
        return Err(error());
    }
    let d = dirs(false, true)?;
    check_init(&d)?;
    receipt(spec)?;
    let mut intent = load_intent(&d.root)?.ok_or_else(error)?;
    if intent.spec != *spec
        || !matches!(
            intent.phase,
            UpgradePhase::Exchanged | UpgradePhase::Finalizing
        )
    {
        return Err(error());
    }
    let (_, new, done) = layout(&d, spec)?;
    if !done {
        return Err(error());
    }
    adapter.verify_quiescent(spec)?;
    adapter.verify_new_ready(&new, spec)?;
    receipt(spec)?;
    if intent.phase != UpgradePhase::Finalizing {
        let previous = intent.clone();
        intent.phase = UpgradePhase::Finalizing;
        store_intent(&d.root, &intent, Some(&previous))?;
    }
    Ok(())
}
/// Clear the fence only after the matching receipt was durably consumed. A
/// crash between receipt consumption and this operation leaves Finalizing and
/// can be resumed after verifying package integrity, quiescence and READY.
pub fn clear_upgrade_fence(
    spec: &UpgradeSpec,
    adapter: &mut impl UpgradeAdapter,
) -> io::Result<()> {
    if !spec.valid() {
        return Err(error());
    }
    let d = dirs(false, true)?;
    check_init(&d)?;
    let intent = load_intent(&d.root)?.ok_or_else(error)?;
    if intent.spec != *spec
        || intent.phase != UpgradePhase::Finalizing
        || entry_exists(&d.root, "removal.json")?
    {
        return Err(error());
    }
    let (_, new, done) = layout(&d, spec)?;
    if !done {
        return Err(error());
    }
    adapter.verify_quiescent(spec)?;
    adapter.verify_new_ready(&new, spec)?;
    if load_intent(&d.root)?.as_ref() != Some(&intent) || entry_exists(&d.root, "removal.json")? {
        return Err(error());
    }
    // Retain the previous verified bundle outside the active name; no old
    // executable is deleted or overwritten. A crash after this rename can
    // resume via layout() using the receipt-bound archive name.
    let archive = format!("rescue-previous-{}", spec.request_id);
    if dir_if_exists(&d.root, NEXT)?.is_some() {
        if entry_exists(&d.root, &archive)? {
            return Err(error());
        }
        let n = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                d.root.as_raw_fd(),
                c(NEXT)?.as_ptr(),
                d.root.as_raw_fd(),
                c(&archive)?.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if n != 0 {
            return Err(io::Error::last_os_error());
        }
        d.root.sync_all()?;
    }
    if unsafe { libc::unlinkat(d.root.as_raw_fd(), c(INTENT)?.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    d.root.sync_all()
}

#[cfg(test)]
mod finalize_tests {
    use super::{BINARY, META, exact_entries};
    use std::{fs, fs::File};

    #[test]
    fn finalizer_refuses_unknown_rescue_assets() {
        let dir =
            std::env::temp_dir().join(format!("xkeen-rescue-finalize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join(BINARY), b"synthetic rescue").unwrap();
        fs::write(dir.join(META), b"synthetic identity").unwrap();
        let handle = File::open(&dir).unwrap();
        exact_entries(&handle, &[BINARY, META]).unwrap();
        fs::write(dir.join("foreign-sentinel"), b"preserve").unwrap();
        assert!(exact_entries(&handle, &[BINARY, META]).is_err());
        assert_eq!(fs::read(dir.join("foreign-sentinel")).unwrap(), b"preserve");
        drop(handle);
        fs::remove_dir_all(dir).unwrap();
    }
}
