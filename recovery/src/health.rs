//! Identity proof for the fixed procd-managed core.
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{Mutex, OnceLock},
};
use xkeenwrt_recovery::{
    CoreSnapshot, LaunchGrant,
    active::{Code, CoreHealth},
};

fn bad() -> io::Error {
    io::Error::other("core identity unavailable")
}
fn read(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut v = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut v)?;
    if v.len() > max {
        return Err(bad());
    }
    Ok(v)
}
fn text(path: &Path, max: usize) -> io::Result<String> {
    String::from_utf8(read(path, max)?).map_err(|_| bad())
}
fn grant(snapshot: &CoreSnapshot, desired: bool) -> io::Result<LaunchGrant> {
    let path = Path::new("/var/run/xkeenwrt/launch.json");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > 16384
    {
        return Err(bad());
    }
    let mut b = Vec::new();
    f.take(16385).read_to_end(&mut b)?;
    if b.len() > 16384 {
        return Err(bad());
    }
    let g: LaunchGrant = serde_json::from_slice(&b).map_err(|_| bad())?;
    let expected = LaunchGrant::from_snapshot(snapshot, g.nonce.clone(), desired)?;
    if !g.valid()
        || serde_json::to_value(&g).map_err(|_| bad())?
            != serde_json::to_value(expected).map_err(|_| bad())?
    {
        return Err(bad());
    }
    Ok(g)
}
fn parse_instances(
    instances: Option<&serde_json::Map<String, serde_json::Value>>,
    nonce: &str,
) -> io::Result<Option<u32>> {
    let Some(instances) = instances else {
        return Ok(None);
    };
    if instances.len() > 1 {
        return Err(bad());
    }
    let Some(value) = instances.values().next() else {
        return Ok(None);
    };
    match value.get("running").and_then(|v| v.as_bool()) {
        Some(false) => Ok(None),
        Some(true) => {
            let command = value
                .get("command")
                .and_then(|v| v.as_array())
                .ok_or_else(bad)?;
            if command.len() != 3
                || command[0].as_str() != Some("/usr/bin/xkeenwrt-ui")
                || command[1].as_str() != Some("core-run")
                || command[2].as_str() != Some(nonce)
            {
                return Err(bad());
            }
            let pid = value
                .get("pid")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .filter(|p| *p > 1)
                .ok_or_else(bad)?;
            Ok(Some(pid))
        }
        _ => Err(bad()),
    }
}
fn parse_starttime(stat: &str, pid: u32) -> io::Result<u64> {
    let (left, right) = stat.rsplit_once(')').ok_or_else(bad)?;
    let id = left
        .split_once(' ')
        .ok_or_else(bad)?
        .0
        .parse::<u32>()
        .map_err(|_| bad())?;
    let fields: Vec<_> = right.split_whitespace().collect();
    if id != pid || fields.first().is_none_or(|s| matches!(*s, "Z" | "X")) {
        return Err(bad());
    }
    fields.get(19).ok_or_else(bad)?.parse().map_err(|_| bad())
}
fn starttime(pid: u32) -> io::Result<u64> {
    let stat = text(Path::new(&format!("/proc/{pid}/stat")), 4096)?;
    parse_starttime(&stat, pid)
}
fn limits_match(memory: &str, swap: &str, pids: &str, oom: &str) -> bool {
    let expected = xkeenwrt_recovery::CORE_CGROUP_LIMITS;
    [
        ("memory.max", memory),
        ("memory.swap.max", swap),
        ("pids.max", pids),
        ("memory.oom.group", oom),
    ]
    .iter()
    .all(|(name, value)| {
        expected
            .iter()
            .any(|(key, want)| key == name && *want == value.trim())
    })
}
fn open_dir_at(parent: &File, name: &std::ffi::CStr) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(bad());
    }
    Ok(f)
}
fn read_cg_file(dir: &File, name: &std::ffi::CStr, max: usize) -> io::Result<String> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let mut data = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut data)?;
    if data.len() > max {
        return Err(bad());
    }
    String::from_utf8(data).map_err(|_| bad())
}
fn core_group() -> io::Result<(String, String)> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup")?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x6367_7270
    {
        return Err(bad());
    }
    let parent = open_dir_at(&root, c"xkeenwrt")?;
    let core = open_dir_at(&parent, c"core")?;
    let memory = read_cg_file(&core, c"memory.max", 128)?;
    let swap = read_cg_file(&core, c"memory.swap.max", 128)?;
    let pids = read_cg_file(&core, c"pids.max", 128)?;
    let oom = read_cg_file(&core, c"memory.oom.group", 128)?;
    if !limits_match(&memory, &swap, &pids, &oom) {
        return Err(bad());
    }
    Ok((
        read_cg_file(&core, c"cgroup.procs", 65536)?,
        read_cg_file(&core, c"cgroup.events", 4096)?,
    ))
}
fn populated(events: &str) -> io::Result<bool> {
    let mut found = None;
    for line in events.lines() {
        let mut p = line.split_whitespace();
        if p.next() == Some("populated") {
            let v = p.next().ok_or_else(bad)?;
            if p.next().is_some() || found.is_some() {
                return Err(bad());
            }
            found = Some(match v {
                "0" => false,
                "1" => true,
                _ => return Err(bad()),
            });
        }
    }
    found.ok_or_else(bad)
}
fn membership(pid: u32) -> io::Result<()> {
    let (procs, events) = core_group()?;
    let ids: Vec<_> = procs.split_whitespace().collect();
    if !populated(&events)? || ids.len() != 1 || ids[0] != pid.to_string() {
        return Err(bad());
    }
    let proc = text(Path::new(&format!("/proc/{pid}/cgroup")), 4096)?;
    if !proc.lines().any(|v| v == "0::/xkeenwrt/core") {
        return Err(bad());
    }
    Ok(())
}
fn empty_group() -> io::Result<()> {
    let (procs, events) = core_group()?;
    if populated(&events)? || !procs.trim().is_empty() {
        return Err(bad());
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    uid: u32,
    mode: u32,
    nlink: u64,
}
impl FileIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        if !m.is_file() || m.len() == 0 || m.len() > 100 * 1024 * 1024 {
            return Err(bad());
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
        })
    }
}
struct CacheEntry {
    fd: File,
    identity: FileIdentity,
    digest: String,
}
#[derive(Default)]
struct IdentityCache {
    entry: Option<CacheEntry>,
}
#[derive(Debug, PartialEq, Eq)]
enum CacheResult {
    Hit,
    Verified,
}
impl IdentityCache {
    fn verify(&mut self, file: File, expected: &str) -> io::Result<CacheResult> {
        let before = match FileIdentity::from_file(&file) {
            Ok(v) => v,
            Err(e) => {
                self.entry = None;
                return Err(e);
            }
        };
        if let Some(entry) = self.entry.as_ref()
            && entry.digest == expected
            && entry.identity == before
            && FileIdentity::from_file(&entry.fd).ok().as_ref() == Some(&before)
            && FileIdentity::from_file(&file).ok().as_ref() == Some(&before)
        {
            return Ok(CacheResult::Hit);
        }
        self.entry = None;
        let mut h = Sha256::new();
        let mut b = [0u8; 32768];
        let mut off = 0u64;
        while off < before.len {
            let n = file.read_at(&mut b, off)?;
            if n == 0 {
                return Err(bad());
            }
            h.update(&b[..n]);
            off += n as u64;
        }
        let digest: String = h.finalize().iter().map(|v| format!("{v:02x}")).collect();
        if digest != expected || FileIdentity::from_file(&file)? != before {
            return Err(bad());
        }
        self.entry = Some(CacheEntry {
            fd: file,
            identity: before,
            digest,
        });
        Ok(CacheResult::Verified)
    }
}
static CORE_CACHE: OnceLock<Mutex<IdentityCache>> = OnceLock::new();
#[cfg(test)]
fn trusted_exe_path(path: &Path) -> bool {
    mihomo_release::release_for_exe_path(path).is_some()
}
fn exe_digest(pid: u32) -> io::Result<()> {
    let cache = CORE_CACHE.get_or_init(|| Mutex::new(IdentityCache::default()));
    let mut cache = cache.lock().map_err(|_| bad())?;
    let result = (|| {
        let (f, release) = mihomo_release::verify_process_exe(pid).map_err(|_| bad())?;
        let identity = FileIdentity::from_file(&f)?;
        if identity.uid != 0
            || identity.mode & 0o7777 != 0o755
            || identity.nlink != 1
            || identity.len != release.elf_size
        {
            return Err(bad());
        }
        cache.verify(f, release.elf_sha256)?;
        let (again, again_release) = mihomo_release::verify_process_exe(pid).map_err(|_| bad())?;
        if again_release.version != release.version || FileIdentity::from_file(&again)? != identity
        {
            return Err(bad());
        }
        Ok(())
    })();
    if result.is_err() {
        cache.entry = None;
    }
    result
}
fn sockets(pid: u32) -> io::Result<Vec<u64>> {
    let mut result = Vec::new();
    for (count, e) in fs::read_dir(format!("/proc/{pid}/fd"))?.enumerate() {
        if count >= 4096 {
            return Err(bad());
        }
        let v = fs::read_link(e?.path())?;
        let Some(v) = v.to_str() else {
            return Err(bad());
        };
        if let Some(n) = v.strip_prefix("socket:[").and_then(|v| v.strip_suffix(']')) {
            let n = n.parse::<u64>().map_err(|_| bad())?;
            if n == 0 {
                return Err(bad());
            }
            result.push(n);
        }
    }
    Ok(result)
}
fn tables() -> io::Result<[Vec<u8>; 4]> {
    Ok([
        read(Path::new("/proc/net/tcp"), 1048576)?,
        read(Path::new("/proc/net/udp"), 1048576)?,
        read(Path::new("/proc/net/tcp6"), 1048576)?,
        read(Path::new("/proc/net/udp6"), 1048576)?,
    ])
}
fn listeners_owned(tables: [&[u8]; 4], lan: Option<Ipv4Addr>, owned: &[u64]) -> io::Result<()> {
    let own: HashSet<_> = owned.iter().copied().collect();
    let mut counts = [0u8; 5];
    let lan = lan.map(|ip| {
        let o = ip.octets();
        format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
    });
    for (kind, data) in tables.iter().enumerate() {
        if data.len() > 1048576 {
            return Err(bad());
        }
        let data = std::str::from_utf8(data).map_err(|_| bad())?;
        let mut lines = data.lines();
        if !lines
            .next()
            .is_some_and(|h| h.split_whitespace().any(|v| v == "local_address"))
        {
            return Err(bad());
        }
        for line in lines {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 10 {
                return Err(bad());
            }
            let (address, port) = f[1].split_once(':').ok_or_else(bad)?;
            if !matches!(address.len(), 8 | 32)
                || port.len() != 4
                || !address.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(bad());
            }
            let port = u16::from_str_radix(port, 16).map_err(|_| bad())?;
            if !matches!(port, 9090 | 7893 | 1053) {
                continue;
            }
            if kind % 2 == 0 && f[3] != "0A" {
                continue;
            }
            if kind % 2 == 1 && f[3] != "07" {
                return Err(bad());
            }
            if kind >= 2 {
                return Err(bad());
            }
            let index = match (kind, port) {
                (0, 9090) if address.eq_ignore_ascii_case("0100007F") => 0,
                (0, 7893)
                    if lan
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(address)) =>
                {
                    1
                }
                (0, 1053)
                    if lan
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(address)) =>
                {
                    2
                }
                (1, 7893)
                    if lan
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(address)) =>
                {
                    3
                }
                (1, 1053)
                    if lan
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(address)) =>
                {
                    4
                }
                _ => return Err(bad()),
            };
            let inode = f[9].parse::<u64>().map_err(|_| bad())?;
            if inode == 0 || !own.contains(&inode) {
                return Err(bad());
            }
            counts[index] = counts[index].checked_add(1).ok_or_else(bad)?;
        }
    }
    let expected = if lan.is_some() {
        [1, 1, 1, 1, 1]
    } else {
        [1, 0, 0, 0, 0]
    };
    if counts != expected {
        return Err(bad());
    }
    Ok(())
}
fn no_reserved_listeners() -> io::Result<()> {
    let data = tables()?;
    reserved_clear([&data[0], &data[1], &data[2], &data[3]])
}
fn reserved_clear(tables: [&[u8]; 4]) -> io::Result<()> {
    for (kind, data) in tables.iter().enumerate() {
        let text = std::str::from_utf8(data).map_err(|_| bad())?;
        let mut lines = text.lines();
        if !lines
            .next()
            .is_some_and(|h| h.split_whitespace().any(|v| v == "local_address"))
        {
            return Err(bad());
        }
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return Err(bad());
            }
            let (address, port) = fields[1].split_once(':').ok_or_else(bad)?;
            if !matches!(address.len(), 8 | 32)
                || port.len() != 4
                || !address.bytes().all(|v| v.is_ascii_hexdigit())
            {
                return Err(bad());
            }
            let port = u16::from_str_radix(port, 16).map_err(|_| bad())?;
            if matches!(port, 9090 | 7893 | 1053)
                && ((kind % 2 == 0 && fields[3] == "0A") || kind % 2 == 1)
            {
                return Err(bad());
            }
        }
    }
    Ok(())
}
fn process_identity(
    snapshot: &CoreSnapshot,
    expected: &LaunchGrant,
) -> io::Result<Option<(u32, u64)>> {
    let instances = crate::commands::core_instances()?;
    let Some(pid) = parse_instances(instances.as_ref(), &expected.nonce)? else {
        empty_group()?;
        no_reserved_listeners()?;
        return Ok(None);
    };
    let start = starttime(pid)?;
    exe_digest(pid)?;
    membership(pid)?;
    let inodes = sockets(pid)?;
    let t = tables()?;
    let lan = snapshot.overlay.gateway().map(|n| n.lan_ipv4);
    listeners_owned([&t[0], &t[1], &t[2], &t[3]], lan, &inodes)?;
    if let Some(e) = snapshot.overlay.explicit() {
        xkeenwrt_recovery::explicit::verify(
            e,
            &crate::commands::inventory(crate::commands::InventoryQuery::NftRuleset)?,
        )?;
        if !xkeenwrt_recovery::explicit::socket_proof(
            [&t[0], &t[1], &t[2], &t[3]],
            Some(e),
            &inodes,
            true,
        )? {
            return Err(bad());
        }
    }
    if starttime(pid)? != start {
        return Err(bad());
    }
    Ok(Some((pid, start)))
}
/// Independent helper-owned observation. Unknown/ambiguous evidence is never
/// downgraded to a failure signal that can change network policy.
pub(crate) fn observe(snapshot: &CoreSnapshot) -> Result<CoreHealth, Code> {
    if !snapshot.running {
        return Err(Code::Unavailable);
    }
    let result = (|| -> io::Result<CoreHealth> {
        crate::core::verify_active_home(snapshot)?;
        let g = grant(snapshot, true)?;
        let first = process_identity(snapshot, &g)?;
        let Some(identity) = first else {
            crate::core::verify_active_home(snapshot)?;
            let after = grant(snapshot, true)?;
            if serde_json::to_value(&g).map_err(|_| bad())?
                != serde_json::to_value(&after).map_err(|_| bad())?
                || process_identity(snapshot, &after)?.is_some()
            {
                return Err(bad());
            }
            return Ok(CoreHealth::Failed);
        };
        let secret = crate::core::secret(snapshot)?;
        let status = crate::core::health(snapshot.controller_port, &secret);
        crate::core::verify_active_home(snapshot)?;
        let after = grant(snapshot, true)?;
        if serde_json::to_value(&g).map_err(|_| bad())?
            != serde_json::to_value(&after).map_err(|_| bad())?
            || process_identity(snapshot, &after)? != Some(identity)
        {
            return Err(bad());
        }
        match status {
            Ok(()) => Ok(CoreHealth::Healthy),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(CoreHealth::Failed),
            Err(e) => Err(e),
        }
    })();
    result.map_err(|_| Code::Unavailable)
}
/// Read-only proof that an expected stopped baseline is actually absent.
pub(crate) fn stopped(snapshot: &CoreSnapshot) -> Result<bool, Code> {
    if snapshot.running {
        return Err(Code::Unavailable);
    }
    let result = (|| -> io::Result<bool> {
        crate::core::verify_active_home(snapshot)?;
        let g = grant(snapshot, false)?;
        if process_identity(snapshot, &g)?.is_some() {
            return Ok(false);
        }
        crate::core::verify_active_home(snapshot)?;
        let after = grant(snapshot, false)?;
        if serde_json::to_value(&g).map_err(|_| bad())?
            != serde_json::to_value(&after).map_err(|_| bad())?
            || process_identity(snapshot, &after)?.is_some()
        {
            return Err(bad());
        }
        Ok(true)
    })();
    result.map_err(|_| Code::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn procd_command_must_bind_exact_nonce_and_single_pid() {
        let good = serde_json::json!({"i":{"running":true,"pid":123,"command":["/usr/bin/xkeenwrt-ui","core-run","00000000-0000-4000-8000-000000000001"]}}).as_object().unwrap().clone();
        assert_eq!(
            parse_instances(Some(&good), "00000000-0000-4000-8000-000000000001").unwrap(),
            Some(123)
        );
        assert!(parse_instances(Some(&good), "00000000-0000-4000-8000-000000000002").is_err());
    }
    #[test]
    fn foreign_and_wildcard_listener_never_passes() {
        let header =
            b"sl local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n";
        let foreign=b"sl local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n0: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 777\n";
        assert!(
            listeners_owned(
                [&foreign[..], &header[..], &header[..], &header[..]],
                None,
                &[777]
            )
            .is_err()
        );
    }
    fn rows(values: &[(&str, &str, u64)]) -> Vec<u8> {
        let mut v = String::from(
            "sl local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        for (local, state, inode) in values {
            v.push_str(&format!("0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 {inode}\n"));
        }
        v.into_bytes()
    }
    #[test]
    fn exact_network_listeners_must_belong_to_core() {
        let tcp = rows(&[
            ("0100007F:2382", "0A", 101),
            ("0102A8C0:1ED5", "0A", 102),
            ("0102A8C0:041D", "0A", 103),
        ]);
        let udp = rows(&[("0102A8C0:1ED5", "07", 104), ("0102A8C0:041D", "07", 105)]);
        let empty = rows(&[]);
        let lan = Some("192.168.2.1".parse().unwrap());
        assert!(
            listeners_owned(
                [&tcp, &udp, &empty, &empty],
                lan,
                &[101, 102, 103, 104, 105]
            )
            .is_ok()
        );
        assert!(listeners_owned([&tcp, &udp, &empty, &empty], lan, &[101, 102, 103, 104]).is_err());
        let ipv6 = rows(&[("00000000000000000000000000000000:041D", "0A", 106)]);
        assert!(
            listeners_owned(
                [&tcp, &udp, &ipv6, &empty],
                lan,
                &[101, 102, 103, 104, 105, 106]
            )
            .is_err()
        );
    }
    #[test]
    fn manual_controller_rejects_duplicate_or_unowned_socket() {
        let tcp = rows(&[("0100007F:2382", "0A", 101)]);
        let empty = rows(&[]);
        assert!(listeners_owned([&tcp, &empty, &empty, &empty], None, &[101]).is_ok());
        assert!(listeners_owned([&tcp, &empty, &empty, &empty], None, &[202]).is_err());
        let duplicate = rows(&[("0100007F:2382", "0A", 101), ("0100007F:2382", "0A", 102)]);
        assert!(listeners_owned([&duplicate, &empty, &empty, &empty], None, &[101, 102]).is_err());
    }
    #[test]
    fn rejects_zombie_wrong_pid_and_incomplete_stat() {
        let s = "123 (core ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242";
        assert_eq!(parse_starttime(s, 123).unwrap(), 4242);
        assert!(parse_starttime(s, 124).is_err());
        assert!(parse_starttime(&s.replace(") S ", ") Z "), 123).is_err());
        assert!(parse_starttime("123 (core) S 1", 123).is_err());
    }
    #[test]
    fn rejects_multiple_procd_instances() {
        let value = serde_json::json!({"a":{"running":false},"b":{"running":false}});
        assert!(
            parse_instances(value.as_object(), "00000000-0000-4000-8000-000000000001").is_err()
        );
    }
    #[test]
    fn stopped_proof_rejects_foreign_reserved_listener() {
        let empty = rows(&[]);
        assert!(reserved_clear([&empty, &empty, &empty, &empty]).is_ok());
        let foreign = rows(&[("0100007F:2382", "0A", 99)]);
        assert!(reserved_clear([&foreign, &empty, &empty, &empty]).is_err());
    }
    #[test]
    fn cache_hits_unchanged_and_rejects_mutated_or_replaced_file() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("xkeenwrt-health-cache-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("core");
        std::fs::write(&path, b"synthetic-core").unwrap();
        let expected: String = Sha256::digest(b"synthetic-core")
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        let mut cache = IdentityCache::default();
        assert_eq!(
            cache.verify(File::open(&path).unwrap(), &expected).unwrap(),
            CacheResult::Verified
        );
        assert_eq!(
            cache.verify(File::open(&path).unwrap(), &expected).unwrap(),
            CacheResult::Hit
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            cache.verify(File::open(&path).unwrap(), &expected).unwrap(),
            CacheResult::Verified
        );
        // The cached descriptor pins the old inode, so a same-content replacement
        // cannot be mistaken for a cache hit.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"synthetic-core").unwrap();
        assert_eq!(
            cache.verify(File::open(&path).unwrap(), &expected).unwrap(),
            CacheResult::Verified
        );
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"x").unwrap();
        drop(file);
        assert!(cache.verify(File::open(&path).unwrap(), &expected).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"synthetic-core").unwrap();
        assert_eq!(
            cache.verify(File::open(&path).unwrap(), &expected).unwrap(),
            CacheResult::Verified
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn core_executable_path_must_match_catalogue_location() {
        assert!(trusted_exe_path(Path::new(
            "/usr/libexec/xkeenwrt/cores/1.19.33/mihomo"
        )));
        assert!(trusted_exe_path(Path::new(
            "/usr/libexec/xkeenwrt/cores/1.19.34/mihomo"
        )));
        assert!(!trusted_exe_path(Path::new("/usr/libexec/xkeenwrt/mihomo")));
        assert!(!trusted_exe_path(Path::new("/tmp/mihomo")));
        assert!(!trusted_exe_path(Path::new(
            "/usr/libexec/xkeenwrt/cores/1.19.34/mihomo (deleted)"
        )));
    }
    #[test]
    fn core_limits_must_be_exact_and_enforced() {
        assert!(limits_match("201326592\n", "0\n", "64\n", "1\n"));
        assert!(!limits_match("max\n", "0\n", "64\n", "1\n"));
        assert!(!limits_match("201326592\n", "1\n", "64\n", "1\n"));
        assert!(!limits_match("201326592\n", "0\n", "65\n", "1\n"));
        assert!(!limits_match("201326592\n", "0\n", "64\n", "0\n"));
    }
}
