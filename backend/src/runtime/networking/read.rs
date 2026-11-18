//! Fixed, bounded read-only inventory subprocesses. Never accept argv from HTTP.
use std::{
    io::{self, Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd},
    time::Duration,
};

#[derive(Clone, Copy)]
pub enum Query {
    Addresses,
    Neighbours,
    Links,
    Rules4,
    Rules6,
    Routes4,
    Routes6,
    NftRuleset,
    NftOwned,
    NetworkStatus,
    DnsConfig,
    ProxyConfig,
    ProxyService,
    RecoveryService,
    CoreService,
    UiService,
}

/// Captures one fixed command, at most 1 MiB and three seconds. Neither shell
/// nor caller-provided arguments are used. Output is sensitive and not logged.
pub fn query(query: Query, cgroup_dir: &std::fs::File) -> io::Result<Vec<u8>> {
    use xkeenwrt_recovery::FixedProgram::{Ip, Nft, Ubus};
    let (program, args): (xkeenwrt_recovery::FixedProgram, &[&str]) = match query {
        Query::Addresses => (Ip, &["-j", "address", "show"]),
        Query::Neighbours => (Ip, &["-j", "neigh", "show"]),
        Query::Links => (Ip, &["-j", "link", "show"]),
        Query::Rules4 => (Ip, &["-j", "-4", "rule", "show"]),
        Query::Rules6 => (Ip, &["-j", "-6", "rule", "show"]),
        Query::Routes4 => (Ip, &["-j", "-4", "route", "show", "table", "all"]),
        Query::Routes6 => (Ip, &["-j", "-6", "route", "show", "table", "all"]),
        Query::NftRuleset => (Nft, &["-j", "list", "ruleset"]),
        Query::NftOwned => (Nft, &["-j", "list", "table", "inet", "xkeenwrt"]),
        Query::NetworkStatus => (Ubus, &["call", "network.interface", "dump"]),
        Query::DnsConfig => (Ubus, &["call", "uci", "get", "{\"config\":\"dhcp\"}"]),
        Query::ProxyConfig => (Ubus, &["call", "uci", "get", "{\"config\":\"https-dns-proxy\"}"]),
        Query::ProxyService => (Ubus, &["call", "service", "list", "{\"name\":\"https-dns-proxy\"}"]),
        Query::CoreService => (Ubus, &["call", "service", "list", "{\"name\":\"xkeenwrt-core\"}"]),
        Query::UiService => (Ubus, &["call", "service", "list", "{\"name\":\"xkeenwrt-ui\"}"]),
        Query::RecoveryService => (Ubus, &["call", "service", "list", "{\"name\":\"xkeenwrt-rescue\"}"]),
    };
    let raw = unsafe { nix::libc::memfd_create(c"xkeenwrt-inventory".as_ptr(), nix::libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(raw) };
    let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let ok = xkeenwrt_recovery::run_fixed_in_cgroup(
        program,
        &args,
        cgroup_dir.as_raw_fd(),
        null.as_raw_fd(),
        output.as_raw_fd(),
        null.as_raw_fd(),
        Duration::from_secs(3),
    )?;
    if !ok {
        return Err(io::Error::other("inventory command failed"));
    }
    if output.metadata()?.len() > 1_048_576 {
        return Err(io::Error::other("inventory output too large"));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    output.take(1_048_577).read_to_end(&mut data)?;
    if data.len() > 1_048_576 {
        return Err(io::Error::other("inventory output too large"));
    }
    if matches!(query, Query::DnsConfig) {
        xkeenwrt_recovery::dns_snapshot::capture(&data)
    } else {
        Ok(data)
    }
}

/// The default dnsmasq lease file is accepted only when UCI inspection has
/// independently confirmed this exact lease path and a single instance.
pub fn default_leases() -> io::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open("/tmp/dhcp.leases")?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 || m.len() > 1_048_576 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe dnsmasq leases"));
    }
    let mut out = Vec::new();
    (&file).take(1_048_577).read_to_end(&mut out)?;
    let after = file.metadata()?;
    let path_meta = std::fs::symlink_metadata("/tmp/dhcp.leases")?;
    if path_meta.file_type().is_symlink()
        || m.dev() != after.dev()
        || m.ino() != after.ino()
        || m.len() != after.len()
        || m.mtime() != after.mtime()
        || m.mtime_nsec() != after.mtime_nsec()
        || after.dev() != path_meta.dev()
        || after.ino() != path_meta.ino()
    {
        return Err(io::Error::other("dnsmasq leases changed during read"));
    }
    if out.len() > 1_048_576 {
        return Err(io::Error::other("dnsmasq leases too large"));
    }
    Ok(out)
}
