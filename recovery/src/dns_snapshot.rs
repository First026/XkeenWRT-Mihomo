//! Read the fixed OpenWrt resolver file into the same bounded evidence used by
//! runtime and rescue. Never follow a path selected by a profile or HTTP input.
use serde_json::Value;
use std::{
    io::{self, Read},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
pub const RESOLVER: &str = "/tmp/resolv.conf.d/resolv.conf.auto";
const FIELD: &str = "xkeenwrt_resolv_servers";
fn invalid() -> io::Error {
    io::Error::other("unsupported resolver snapshot")
}
fn config(input: &[u8]) -> io::Result<(Value, bool)> {
    if input.len() > 1_048_576 {
        return Err(invalid());
    }
    let value: Value = serde_json::from_slice(input).map_err(|_| invalid())?;
    if value.get(FIELD).is_some() {
        return Err(invalid());
    }
    let instances: Vec<_> = value["values"]
        .as_object()
        .ok_or_else(invalid)?
        .values()
        .filter(|v| v[".type"] == "dnsmasq")
        .collect();
    let [instance] = instances.as_slice() else {
        return Err(invalid());
    };
    let use_file = match instance.get("noresolv").and_then(Value::as_str) {
        Some("1") => false,
        None | Some("0") => true,
        _ => return Err(invalid()),
    };
    if use_file && instance["resolvfile"].as_str() != Some(RESOLVER) {
        return Err(invalid());
    }
    Ok((value, use_file))
}
pub fn with_resolver(input: &[u8], resolvers: &[u8]) -> io::Result<Vec<u8>> {
    let (mut value, use_file) = config(input)?;
    if !use_file {
        return Ok(input.to_vec());
    }
    if resolvers.len() > 65_536 {
        return Err(invalid());
    }
    let mut servers = std::collections::BTreeSet::new();
    for line in std::str::from_utf8(resolvers)
        .map_err(|_| invalid())?
        .lines()
    {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.as_slice() {
            ["nameserver", address] => {
                let ip: IpAddr = address.parse().map_err(|_| invalid())?;
                if ip.is_unspecified() || ip.is_multicast() {
                    return Err(invalid());
                }
                servers.insert(ip.to_string());
                if servers.len() > 8 {
                    return Err(invalid());
                }
            }
            // dnsmasq reads upstream addresses only from nameserver records.
            ["search", _, ..] => {}
            _ => return Err(invalid()),
        }
    }
    if servers.is_empty() {
        return Err(invalid());
    }
    value[FIELD] = serde_json::json!(servers);
    serde_json::to_vec(&value).map_err(|_| invalid())
}
pub fn capture(input: &[u8]) -> io::Result<Vec<u8>> {
    if !config(input)?.1 {
        return Ok(input.to_vec());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(RESOLVER)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 || m.len() > 65_536 {
        return Err(invalid());
    }
    let mut resolvers = Vec::new();
    file.take(65_537).read_to_end(&mut resolvers)?;
    with_resolver(input, &resolvers)
}
