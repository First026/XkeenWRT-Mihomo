use serde::Serialize;
use std::{
    io,
    sync::{Mutex, OnceLock},
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStats {
    pub memory_used: u64,
    pub memory_total: u64,
    pub cpu_usage: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuCounters {
    total: u64,
    idle: u64,
}

static LAST_CPU: OnceLock<Mutex<Option<CpuCounters>>> = OnceLock::new();

fn read_bounded(path: &str, max: usize) -> io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    if text.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "system file exceeds limit"));
    }
    Ok(text)
}

fn memory_bytes(contents: &str) -> Option<(u64, u64)> {
    let mut values = std::collections::HashMap::new();
    for line in contents.lines() {
        let (key, rest) = line.split_once(':')?;
        if matches!(key, "MemTotal" | "MemAvailable" | "MemFree" | "Buffers" | "Cached") {
            let value = rest.split_ascii_whitespace().next()?.parse::<u64>().ok()?;
            values.insert(key, value.checked_mul(1024)?);
        }
    }
    let total = *values.get("MemTotal")?;
    let available = values.get("MemAvailable").copied().unwrap_or_else(|| {
        values
            .get("MemFree")
            .copied()
            .unwrap_or_default()
            .saturating_add(values.get("Buffers").copied().unwrap_or_default())
            .saturating_add(values.get("Cached").copied().unwrap_or_default())
    });
    if total == 0 || available > total {
        return None;
    }
    Some((total - available, total))
}

fn cpu_counters(contents: &str) -> Option<CpuCounters> {
    let line = contents.lines().next()?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let values = fields
        .take(8)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    let total = values.iter().try_fold(0u64, |sum, value| sum.checked_add(*value))?;
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or_default());
    Some(CpuCounters { total, idle })
}

fn cpu_percent(previous: Option<CpuCounters>, current: CpuCounters) -> f64 {
    let Some(previous) = previous else { return 0.0 };
    let total = current.total.saturating_sub(previous.total);
    let idle = current.idle.saturating_sub(previous.idle).min(total);
    if total == 0 {
        return 0.0;
    }
    ((total - idle) as f64 * 100.0 / total as f64).clamp(0.0, 100.0)
}

pub fn snapshot() -> io::Result<SystemStats> {
    let memory = memory_bytes(&read_bounded("/proc/meminfo", 16 * 1024)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid memory counters"))?;
    let current = cpu_counters(&read_bounded("/proc/stat", 4096)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid CPU counters"))?;
    let cpu = LAST_CPU.get_or_init(|| Mutex::new(None));
    let usage = {
        let mut previous = cpu.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let usage = cpu_percent(*previous, current);
        *previous = Some(current);
        usage
    };
    Ok(SystemStats {
        memory_used: memory.0,
        memory_total: memory.1,
        cpu_usage: usage,
    })
}

/// Identify DNS listeners from kernel socket inodes, not from saved YAML.
/// No DNS query, service operation or network configuration write is performed.
pub fn dns_snapshot() -> io::Result<serde_json::Value> {
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Read,
    };
    let mut sockets = BTreeMap::<String, u16>::new();
    for name in ["tcp", "tcp6", "udp", "udp6"] {
        let mut text = String::new();
        std::fs::File::open(format!("/proc/net/{name}"))?
            .take(512 * 1024 + 1)
            .read_to_string(&mut text)?;
        if text.len() > 512 * 1024 {
            return Err(io::Error::other("socket inventory exceeds limit"));
        }
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() < 10 || (name.starts_with("tcp") && fields[3] != "0A") {
                continue;
            }
            let Some(port) = fields[1]
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
            else {
                continue;
            };
            if matches!(port, 53 | 1053) {
                sockets.insert(fields[9].to_owned(), port);
            }
        }
    }
    let mut owners = BTreeMap::<u16, BTreeSet<String>>::new();
    for process in std::fs::read_dir("/proc")?.take(2048) {
        let process = process?;
        if !process.file_name().as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Ok(comm) = std::fs::read_to_string(process.path().join("comm")) else {
            continue;
        };
        let name: String = comm
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || "_-".contains(*ch))
            .take(32)
            .collect();
        let Ok(fds) = std::fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for fd in fds.take(1024).flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = link
                .to_str()
                .and_then(|v| v.strip_prefix("socket:["))
                .and_then(|v| v.strip_suffix(']'))
            else {
                continue;
            };
            if let Some(port) = sockets.get(inode) {
                owners.entry(*port).or_default().insert(name.clone());
            }
        }
    }
    let on53 = owners.get(&53).cloned().unwrap_or_default();
    let on1053 = owners.get(&1053).cloned().unwrap_or_default();
    Ok(serde_json::json!({"success":true,
        "portListener":if on53.is_empty() { if sockets.values().any(|p| *p==53) { "Неизвестный процесс".into() } else { "Нет слушателя".into() } } else { on53.iter().cloned().collect::<Vec<_>>().join(", ") },
        "dnsmasq":on53.contains("dnsmasq"), "dnsMihomo":on1053.contains("mihomo")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_uses_router_available_memory_and_keeps_units_as_bytes() {
        let (used, total) = memory_bytes("MemTotal: 1000 kB\nMemAvailable: 250 kB\n").unwrap();
        assert_eq!((used, total), (750 * 1024, 1000 * 1024));
    }

    #[test]
    fn cpu_usage_uses_delta_and_excludes_idle_and_iowait() {
        let before = cpu_counters("cpu 10 0 10 70 10 0 0 0 0 0\n").unwrap();
        let after = cpu_counters("cpu 20 0 20 120 20 0 0 0 0 0\n").unwrap();
        assert!((cpu_percent(Some(before), after) - 25.0).abs() < 0.01);
        assert_eq!(cpu_percent(None, after), 0.0);
    }
}
