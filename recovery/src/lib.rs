pub mod completion;
pub mod core_cache;
pub mod dns_snapshot;
/// Fixed limits shared by runtime, recovery and health verification.
pub const CORE_CGROUP_LIMITS: [(&str, &str); 4] = [
    ("memory.max", "201326592"),
    ("memory.swap.max", "0"),
    ("pids.max", "64"),
    ("memory.oom.group", "1"),
];
pub mod active;
pub mod evidence;
mod nft_ast;
pub mod rescue;
pub mod resources;
pub mod retirement;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub failure_policy: FailurePolicy,
    pub owner_id: String,
    pub generation: u64,
    pub nft_semantic_sha256: String,
    pub lan_interface: String,
    pub lan_address: std::net::Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_version: Option<u8>,
    pub selected_mac: String,
    pub management_macs: Vec<String>,
    pub source_ipv4: std::net::Ipv4Addr,
    pub management_ipv4: std::net::Ipv4Addr,
    pub management_ipv6: Vec<std::net::Ipv6Addr>,
    /// Present only for a whole-LAN generation started over the Tailscale
    /// overlay; LAN starts omit it so their bytes stay readable by r26 rescue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_channel: Option<ManagementChannel>,
    pub local_ipv4: Vec<String>,
    pub selected_ipv6: Vec<String>,
    pub local_ipv6: Vec<String>,
    pub route_table: u32,
    pub mark: u32,
    pub mask: u32,
    pub priority: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    DirectOnFailure,
    BlockSelectedOnFailure,
}
/// How the owner reached the panel when a whole-LAN generation was started
/// (decision 024). A LAN start has no channel.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagementChannel {
    Tailscale,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreSnapshot {
    pub snapshot_id: String,
    pub overlay: profile_policy::ManagedOverlay,
    pub sha256: String,
    pub running: bool,
    pub controller_port: u16,
    pub controller_secret_sha256: String,
    pub assets: Vec<SnapshotAsset>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAsset {
    pub relative_path: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchGrant {
    pub version: u32,
    pub nonce: String,
    pub desired_running: bool,
    pub config_sha256: String,
    pub controller_secret_sha256: String,
    pub assets: Vec<SnapshotAsset>,
    pub overlay: profile_policy::ManagedOverlay,
}
impl LaunchGrant {
    pub fn valid(&self) -> bool {
        self.version == 1
            && valid_owner(&self.nonce)
            && valid_digest(&self.config_sha256)
            && valid_digest(&self.controller_secret_sha256)
            && valid_assets(&self.assets)
            && self.overlay.valid()
    }
    pub fn from_snapshot(
        snapshot: &CoreSnapshot,
        nonce: String,
        desired_running: bool,
    ) -> std::io::Result<Self> {
        if !snapshot.valid() || !valid_owner(&nonce) {
            return Err(std::io::Error::other("invalid launch grant"));
        }
        Ok(Self {
            version: 1,
            nonce,
            desired_running,
            config_sha256: snapshot.sha256.clone(),
            controller_secret_sha256: snapshot.controller_secret_sha256.clone(),
            assets: snapshot.assets.clone(),
            overlay: snapshot.overlay.clone(),
        })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Confirmed,
    Revoked,
    RolledBack,
    Disabled,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Apply,
    Disable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAcceptance {
    pub candidate_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub version: u32,
    pub operation: Operation,
    pub tx_id: String,
    pub plan_id: String,
    pub candidate_id: String,
    pub profile_id: String,
    pub revision: String,
    pub idempotency_key: String,
    pub confirm_token_sha256: String,
    pub applied: bool,
    pub generation: u64,
    pub runtime_pid: u32,
    pub runtime_starttime: u64,
    pub runtime_nonce: String,
    pub boot_id: String,
    pub created_boottime_ms: u64,
    pub deadline_boottime_ms: u64,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<completion::Completion>,
    pub current: Manifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_evidence: Option<evidence::NetworkEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_network_evidence: Option<evidence::NetworkEvidence>,
    pub previous_good: Option<Manifest>,
    pub failblock_semantic_sha256: Option<String>,
    pub active_failblock_semantic_sha256: Option<String>,
    pub current_core: CoreSnapshot,
    pub previous_core: CoreSnapshot,
    pub baseline_core: CoreSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_baseline_core: Option<CoreSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_acceptance: Option<ProfileAcceptance>,
    #[serde(default)]
    pub cancel_capture: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Wait,
    Revoke,
    Settled,
    Invalid,
}
impl Journal {
    /// Call while holding the shared mutation lock, then persist before rollback.
    pub fn revoke_fenced(&mut self, expected_generation: u64) -> bool {
        if self.generation != expected_generation
            || !matches!(self.state, State::Pending | State::Confirmed)
        {
            return false;
        }
        self.state = State::Revoked;
        true
    }
    pub fn revoke(&mut self, expected_generation: u64) -> bool {
        if self.generation != expected_generation || self.state != State::Pending {
            return false;
        }
        self.state = State::Revoked;
        true
    }
    fn overlays_match(&self) -> bool {
        use profile_policy::ManagedOverlay;
        fn matches_manifest(overlay: &ManagedOverlay, m: &Manifest) -> bool {
            match overlay.gateway() {
                Some(network) => {
                    network.lan_ifname == m.lan_interface
                        && network.lan_ipv4 == m.lan_address
                        && network.selected_ipv4 == m.source_ipv4
                        && network.tproxy_port == 7893
                        && network.dns_port == 1053
                        && network.dns().is_ok()
                }
                _ => false,
            }
        }
        let current = match self.operation {
            Operation::Apply => matches_manifest(&self.current_core.overlay, &self.current),
            Operation::Disable => {
                self.current_core.overlay.gateway().is_none() && self.current_core.overlay.valid()
            }
        };
        let previous = match &self.previous_good {
            Some(m) => matches_manifest(&self.previous_core.overlay, m),
            None => {
                self.previous_core.overlay.gateway().is_none() && self.previous_core.overlay.valid()
            }
        };
        current
            && previous
            && self.baseline_core.overlay.gateway().is_none()
            && self.baseline_core.overlay.valid()
            && self
                .next_baseline_core
                .as_ref()
                .is_none_or(|b| b.valid() && b.overlay.gateway().is_none() && b.overlay.valid())
    }
    /// Only structural validation is memoized, against every serialized byte.
    /// Time, boot identity and restart decisions are evaluated on every call.
    /// Callers still securely reread the journal and check ownership/fences.
    fn structure_valid(&self) -> bool {
        struct ValidatedContents {
            bytes: Vec<u8>,
            valid: bool,
        }
        type Cache = std::sync::Mutex<Option<ValidatedContents>>;
        static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
        let Ok(bytes) = serde_json::to_vec(self) else {
            return false;
        };
        if bytes.len() > 1_048_576 {
            return false;
        }
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
        if let Ok(entry) = cache.lock()
            && let Some(checked) = entry.as_ref()
            && checked.bytes == bytes
        {
            return checked.valid;
        }
        let valid = self.check_structure();
        if let Ok(mut entry) = cache.lock() {
            *entry = Some(ValidatedContents { bytes, valid });
        }
        valid
    }
    fn check_structure(&self) -> bool {
        !(self.version != 1
            || self.completion.as_ref().is_some_and(|c| !c.valid_for(self))
            || !valid_owner(&self.tx_id)
            || !valid_owner(&self.plan_id)
            || !valid_name(&self.candidate_id)
            || !valid_name(&self.profile_id)
            || !valid_revision(&self.revision)
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 128
            || !valid_digest(&self.confirm_token_sha256)
            || self.generation == 0
            || self.generation != self.current.generation
            || self.runtime_pid == 0
            || self.runtime_starttime == 0
            || !valid_owner(&self.runtime_nonce)
            || runtime_incarnation_path(&self.runtime_identity()).is_err()
            || !self.current_core.valid()
            || !self.previous_core.valid()
            || !self.baseline_core.valid()
            || !self.overlays_match()
            || self.profile_acceptance.as_ref().is_some_and(|p| {
                !valid_name(&p.candidate_id)
                    || !self.applied
                    || self.operation != Operation::Apply
                    || self.state == State::Pending
            })
            || self.deadline_boottime_ms < self.created_boottime_ms
            || self.deadline_boottime_ms - self.created_boottime_ms > 120_000
            || self.previous_good.as_ref().is_some_and(|p| {
                p.owner_id != self.current.owner_id
                    || p.generation >= self.current.generation
                    || p.route_table == self.current.route_table
                    || p.priority == self.current.priority
                    || (p.mask & self.current.mask != 0)
            })
            || self
                .previous_good
                .as_ref()
                .is_some_and(|p| p.failure_policy == FailurePolicy::BlockSelectedOnFailure)
                && !self
                    .failblock_semantic_sha256
                    .as_deref()
                    .is_some_and(valid_digest)
            || self
                .failblock_semantic_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
            || (self.current.failure_policy == FailurePolicy::BlockSelectedOnFailure
                && !self
                    .active_failblock_semantic_sha256
                    .as_deref()
                    .is_some_and(valid_digest))
            || self
                .active_failblock_semantic_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
            || !self.current.valid()
            || self
                .network_evidence
                .as_ref()
                .is_some_and(|e| !e.matches_manifest(&self.current))
            || self.previous_good.as_ref().is_some_and(|m| !m.valid())
            || self.previous_network_evidence.as_ref().is_some_and(|e| {
                self.previous_good
                    .as_ref()
                    .is_none_or(|manifest| !e.matches_manifest(manifest))
            }))
    }
    pub fn decision(&self, boot_id: &str, now_ms: u64, restarted: bool) -> Decision {
        if !self.structure_valid() {
            return Decision::Invalid;
        }
        match self.state {
            State::Confirmed | State::RolledBack | State::Disabled => Decision::Settled,
            State::Revoked => Decision::Revoke,
            State::Pending
                if restarted
                    || self.boot_id != boot_id
                    || now_ms >= self.deadline_boottime_ms
                    || now_ms < self.created_boottime_ms =>
            {
                Decision::Revoke
            }
            State::Pending => Decision::Wait,
        }
    }
}
impl Manifest {
    pub fn whole_lan(&self) -> bool {
        self.lan_scope.is_some()
    }
    fn valid(&self) -> bool {
        matches!(self.capture_version, None | Some(1))
            && valid_owner(&self.owner_id)
            && self.generation > 0
            && self.nft_semantic_sha256.len() == 64
            && self
                .nft_semantic_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && !self.lan_interface.is_empty()
            && self.lan_interface.len() <= 15
            && self
                .lan_interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            && !self.lan_address.is_unspecified()
            && !self.lan_address.is_loopback()
            && !self.lan_address.is_multicast()
            && self.lan_address != self.source_ipv4
            && (self.whole_lan() || valid_lan_mac(&self.selected_mac))
            && (self.whole_lan() || !self.management_macs.is_empty())
            && self.management_macs.len() <= 256
            && self
                .management_macs
                .iter()
                .all(|m| valid_lan_mac(m) && m != &self.selected_mac)
            && !self.management_ipv4.is_unspecified()
            && (self.whole_lan() || self.management_ipv4 != self.source_ipv4)
            && self.management_ipv6.len() <= 256
            && !self.source_ipv4.is_unspecified()
            && !self.source_ipv4.is_loopback()
            && !self.source_ipv4.is_multicast()
            && !self.local_ipv4.is_empty()
            && self.local_ipv4.len() <= 256
            && self.local_ipv4.iter().all(|s| valid_cidr(s, false, false))
            && self.selected_ipv6.len() <= 256
            && self.selected_ipv6.iter().all(|s| valid_cidr(s, true, true))
            && !self.local_ipv6.is_empty()
            && self.local_ipv6.len() <= 256
            && self.local_ipv6.iter().all(|s| valid_cidr(s, true, false))
            && !matches!(self.route_table, 0 | 253 | 254 | 255)
            && !matches!(self.priority, 0 | 32766 | 32767)
            && self.mark != 0
            && self.mark == self.mask
            && self.mark.count_ones() == 1
            && self.management_channel.is_none_or(|_| {
                self.whole_lan() && self.failure_policy == FailurePolicy::DirectOnFailure
            })
            && self.lan_scope.as_ref().is_none_or(|scope| {
                valid_whole_lan_management(
                    scope,
                    self.lan_address,
                    self.management_ipv4,
                    self.management_channel,
                ) && self.source_ipv4 == self.management_ipv4
                    && self.selected_mac.is_empty()
                    && self.management_macs.is_empty()
                    && self.selected_ipv6.is_empty()
                    && self.management_ipv6.is_empty()
                    && self.local_ipv4.contains(scope)
            })
    }
}

/// Canonical bounded IPv4 LAN prefix; both router and administrator are usable hosts.
/// Normalize an observed interface address/prefix without widening its scope.
pub fn lan_network(cidr: &str) -> Option<String> {
    let (address, prefix) = cidr.split_once('/')?;
    let address: std::net::Ipv4Addr = address.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if !(1..=30).contains(&prefix) {
        return None;
    }
    let network = std::net::Ipv4Addr::from(u32::from(address) & (u32::MAX << (32 - prefix)));
    Some(format!("{network}/{prefix}"))
}
/// Network and mask of a canonical bounded LAN scope (/1–/30, not multicast or loopback).
fn lan_scope_parts(scope: &str) -> Option<(u32, u32)> {
    let (network, prefix) = scope.split_once('/')?;
    let network = network.parse::<std::net::Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u32>().ok()?;
    if !(1..=30).contains(&prefix) || network.is_multicast() || network.is_loopback() {
        return None;
    }
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(network);
    (net & mask == net).then_some((net, mask))
}
fn usable_lan_host(ip: std::net::Ipv4Addr, (net, mask): (u32, u32)) -> bool {
    let address = u32::from(ip);
    address & mask == net && address != net && address != (net | !mask)
}
/// Tailscale assigns node addresses from 100.64.0.0/10.
pub fn tailscale_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 0x40
}
/// Whole-LAN scope managed over the Tailscale overlay: the router is a usable
/// LAN host and the administrator is a Tailscale address outside the LAN.
pub fn valid_overlay_scope(
    scope: &str,
    router: std::net::Ipv4Addr,
    peer: std::net::Ipv4Addr,
) -> bool {
    tailscale_ipv4(peer)
        && lan_scope_parts(scope).is_some_and(|(net, mask)| {
            usable_lan_host(router, (net, mask)) && u32::from(peer) & mask != net
        })
}
/// The management rule for whole-LAN capture, shared by plan, manifest and
/// evidence: a LAN host when started from the LAN, a Tailscale peer otherwise.
pub fn valid_whole_lan_management(
    scope: &str,
    router: std::net::Ipv4Addr,
    peer: std::net::Ipv4Addr,
    channel: Option<ManagementChannel>,
) -> bool {
    match channel {
        None => valid_lan_scope(scope, router, peer),
        Some(ManagementChannel::Tailscale) => valid_overlay_scope(scope, router, peer),
    }
}
pub fn valid_lan_scope(scope: &str, router: std::net::Ipv4Addr, peer: std::net::Ipv4Addr) -> bool {
    router != peer
        && lan_scope_parts(scope)
            .is_some_and(|parts| usable_lan_host(router, parts) && usable_lan_host(peer, parts))
}

/// Atomically replace a journal and sync both contents and parent directory.
pub fn write_journal(dir: &std::path::Path, journal: &Journal) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".recovery.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        serde_json::to_writer(&mut file, journal).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&tmp, dir.join("recovery.json"))?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

pub fn read_journal(dir: &std::path::Path) -> std::io::Result<Journal> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("recovery.json"))?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("invalid journal file"));
    }
    let mut contents = Vec::new();
    f.take(1_048_577).read_to_end(&mut contents)?;
    if contents.len() > 1_048_576 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "journal too large",
        ));
    }
    serde_json::from_slice(&contents).map_err(std::io::Error::other)
}

pub fn boottime_ms() -> std::io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(std::io::Error::other("invalid CLOCK_BOOTTIME"));
    }
    (time.tv_sec as u64)
        .checked_mul(1_000)
        .and_then(|ms| ms.checked_add((time.tv_nsec as u64) / 1_000_000))
        .ok_or_else(|| std::io::Error::other("CLOCK_BOOTTIME overflow"))
}

/// `flock` is released on process exit, including termination of a hung runtime.
pub struct MutationLock {
    _file: std::fs::File,
}
impl MutationLock {
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self._file.as_raw_fd()
    }
    pub fn acquire(path: &std::path::Path, wait: std::time::Duration) -> std::io::Result<Self> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::OpenOptionsExt,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let file = if file.as_raw_fd() < 3 {
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe { std::fs::File::from_raw_fd(fd) }
        } else {
            file
        };
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("invalid mutation lock"));
        }
        let started = std::time::Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
            if started.elapsed() >= wait {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mutation lock timed out",
                ));
            }
            std::thread::sleep(
                wait.saturating_sub(started.elapsed())
                    .min(std::time::Duration::from_millis(10)),
            );
        }
    }
}

fn valid_cidr(s: &str, v6: bool, host_only: bool) -> bool {
    if s.len() > 64 {
        return false;
    }
    let Some((address, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if v6 {
        address.parse::<std::net::Ipv6Addr>().is_ok()
            && if host_only {
                prefix == 128
            } else {
                (1..=128).contains(&prefix)
            }
    } else {
        address.parse::<std::net::Ipv4Addr>().is_ok() && (1..=32).contains(&prefix)
    }
}

fn valid_owner(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
            }
        })
}

/// ConfigStore revisions are canonical lowercase UUID strings, not content hashes.
fn valid_revision(s: &str) -> bool {
    valid_owner(s)
}

/// Digest nft JSON while excluding kernel-assigned handles and counter values.
pub fn nft_semantic_digest(input: &[u8]) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut value: serde_json::Value =
        serde_json::from_slice(input).map_err(std::io::Error::other)?;
    let items = value
        .get_mut("nftables")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| std::io::Error::other("invalid nft JSON"))?;
    items.retain(|item| item.get("metainfo").is_none());
    let table_count = items
        .iter()
        .filter(|item| item.get("table").is_some())
        .count();
    if table_count != 1 {
        return Err(std::io::Error::other("expected exactly one nft table"));
    }
    let mut chain_names = std::collections::BTreeSet::new();
    for item in items.iter() {
        if let Some(table) = item.get("table")
            && (table.get("family").and_then(serde_json::Value::as_str) != Some("inet")
                || table.get("name").and_then(serde_json::Value::as_str) != Some("xkeenwrt"))
        {
            return Err(std::io::Error::other("unexpected nft table"));
        }
        if let Some(chain) = item.get("chain") {
            if chain.get("family").and_then(serde_json::Value::as_str) != Some("inet")
                || chain.get("table").and_then(serde_json::Value::as_str) != Some("xkeenwrt")
            {
                return Err(std::io::Error::other("unexpected nft chain"));
            }
            let name = chain
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| std::io::Error::other("unnamed nft chain"))?;
            if !chain_names.insert(name.to_owned()) {
                return Err(std::io::Error::other("duplicate nft chain"));
            }
        }
    }
    for item in items {
        let object = item
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("invalid nft object"))?;
        if object.len() != 1 {
            return Err(std::io::Error::other("invalid nft object"));
        }
        let (kind, body) = object
            .iter_mut()
            .next()
            .ok_or_else(|| std::io::Error::other("empty nft object"))?;
        if !["table", "chain", "rule"].contains(&kind.as_str()) {
            return Err(std::io::Error::other("unsupported nft state"));
        }
        let body = body
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("invalid nft body"))?;
        body.remove("handle");
        body.remove("index");
        if kind == "rule" {
            if body.get("family").and_then(serde_json::Value::as_str) != Some("inet")
                || body.get("table").and_then(serde_json::Value::as_str) != Some("xkeenwrt")
                || !body
                    .get("chain")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|c| chain_names.contains(c))
            {
                return Err(std::io::Error::other("unexpected nft rule"));
            }
            if let Some(serde_json::Value::Array(exprs)) = body.get_mut("expr") {
                for expr in exprs {
                    if let Some(serde_json::Value::Object(counter)) = expr.get_mut("counter") {
                        counter.remove("packets");
                        counter.remove("bytes");
                    }
                }
            }
        }
    }
    let canonical = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
    Ok(Sha256::digest(canonical)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn nft_literal_type_matches(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    match expected {
        serde_json::Value::String(_) => actual.is_string(),
        serde_json::Value::Number(_) => actual.is_number(),
        serde_json::Value::Object(object) if object.len() == 1 && object.contains_key("prefix") => {
            let Some(expected_prefix) = object.get("prefix").and_then(serde_json::Value::as_object)
            else {
                return false;
            };
            let Some(actual_prefix) = actual.get("prefix").and_then(serde_json::Value::as_object)
            else {
                return false;
            };
            expected_prefix.len() == 2
                && actual_prefix.len() == 2
                && expected_prefix.get("addr").is_some_and(|v| {
                    v.is_string()
                        && actual_prefix
                            .get("addr")
                            .is_some_and(serde_json::Value::is_string)
                })
                && expected_prefix.get("len") == actual_prefix.get("len")
        }
        _ => expected == actual,
    }
}

fn nft_schema_matches(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) if e.keys().eq(a.keys()) => {
            if let Some(e_match) = e.get("match") {
                let Some(a_match) = a.get("match").and_then(Value::as_object) else {
                    return false;
                };
                let Some(e_match) = e_match.as_object() else {
                    return false;
                };
                e_match.len() == 3
                    && a_match.len() == 3
                    && e_match.get("op") == a_match.get("op")
                    && e_match
                        .get("left")
                        .zip(a_match.get("left"))
                        .is_some_and(|(left_e, left_a)| nft_schema_matches(left_e, left_a))
                    && e_match.get("right").zip(a_match.get("right")).is_some_and(
                        |(right_e, right_a)| nft_literal_type_matches(right_e, right_a),
                    )
            } else if let Some(e_tproxy) = e.get("tproxy") {
                let Some(e_tproxy) = e_tproxy.as_object() else {
                    return false;
                };
                let Some(a_tproxy) = a.get("tproxy").and_then(Value::as_object) else {
                    return false;
                };
                e_tproxy.len() == 3
                    && a_tproxy.len() == 3
                    && e_tproxy.get("family") == a_tproxy.get("family")
                    && e_tproxy
                        .get("addr")
                        .zip(a_tproxy.get("addr"))
                        .is_some_and(|(e, a)| e.is_string() && a.is_string())
                    && e_tproxy
                        .get("port")
                        .zip(a_tproxy.get("port"))
                        .is_some_and(|(e, a)| e.is_number() && a.is_number())
            } else if let Some(e_redirect) = e.get("redirect") {
                let Some(e_redirect) = e_redirect.as_object() else {
                    return false;
                };
                let Some(a_redirect) = a.get("redirect").and_then(Value::as_object) else {
                    return false;
                };
                e_redirect.len() == 1
                    && a_redirect.len() == 1
                    && e_redirect
                        .get("port")
                        .zip(a_redirect.get("port"))
                        .is_some_and(|(e, a)| e.is_number() && a.is_number())
            } else if let Some(e_mangle) = e.get("mangle") {
                let Some(e_mangle) = e_mangle.as_object() else {
                    return false;
                };
                let Some(a_mangle) = a.get("mangle").and_then(Value::as_object) else {
                    return false;
                };
                e_mangle.len() == 2
                    && a_mangle.len() == 2
                    && e_mangle
                        .get("key")
                        .zip(a_mangle.get("key"))
                        .is_some_and(|(e, a)| nft_schema_matches(e, a))
                    && e_mangle
                        .get("value")
                        .zip(a_mangle.get("value"))
                        .is_some_and(|(e, a)| nft_mangle_value_matches(e, a))
            } else {
                e.iter()
                    .all(|(key, e)| a.get(key).is_some_and(|a| nft_schema_matches(e, a)))
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            e.len() == a.len() && e.iter().zip(a).all(|(e, a)| nft_schema_matches(e, a))
        }
        _ => expected == actual,
    }
}

fn nft_mangle_value_matches(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (expected, actual) {
        (Value::Number(_), Value::Number(_)) => true,
        (Value::Object(e), Value::Object(a)) if e.keys().eq(a.keys()) => {
            e.iter().all(|(key, e)| {
                if key == "mark" {
                    a.get(key).is_some_and(Value::is_number)
                } else {
                    a.get(key).is_some_and(|a| nft_mangle_value_matches(e, a))
                }
            })
        }
        (Value::Array(e), Value::Array(a)) => {
            e.len() == a.len() && e.iter().zip(a).all(|(e, a)| nft_mangle_value_matches(e, a))
        }
        _ => expected == actual,
    }
}

/// Prove that a ruleset still has exactly one of the journal's generated
/// table layouts. Only literal operands, redirect/TPROXY endpoints, and the
/// mark value may differ; object count, order, chain hooks, operators, and
/// verdicts remain exact. This is suitable for emergency deletion after
/// semantic drift, never as a semantic health check.
pub fn nft_ownership_proof(
    actual: &[u8],
    expected_states: &[serde_json::Value],
) -> std::io::Result<bool> {
    let mut actual: serde_json::Value =
        serde_json::from_slice(actual).map_err(std::io::Error::other)?;
    let actual_items = actual
        .get_mut("nftables")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| std::io::Error::other("invalid nft JSON"))?;
    actual_items.retain(|item| item.get("metainfo").is_none());
    for item in actual_items.iter_mut() {
        let Some((_, body)) = item.as_object_mut().and_then(|item| item.iter_mut().next()) else {
            return Err(std::io::Error::other("invalid nft object"));
        };
        let Some(body) = body.as_object_mut() else {
            return Err(std::io::Error::other("invalid nft object body"));
        };
        body.remove("handle");
        body.remove("index");
    }
    for expected in expected_states {
        let Some(expected_items) = expected
            .get("nftables")
            .and_then(serde_json::Value::as_array)
        else {
            return Err(std::io::Error::other("invalid expected nft state"));
        };
        if actual_items.len() == expected_items.len()
            && actual_items
                .iter()
                .zip(expected_items)
                .all(|(actual, expected)| nft_schema_matches(expected, actual))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn valid_assets(assets: &[SnapshotAsset]) -> bool {
    if assets.len() > profile_policy::MAX_PROVIDER_FILES {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for asset in assets {
        let Some((kind, file)) = asset
            .relative_path
            .strip_prefix("providers/")
            .and_then(|s| s.split_once('/'))
        else {
            return false;
        };
        if !["proxies", "rules"].contains(&kind) {
            return false;
        }
        let Some(index) = file.strip_suffix(".yaml") else {
            return false;
        };
        if index.is_empty()
            || index.len() > 6
            || !index.bytes().all(|c| c.is_ascii_digit())
            || !seen.insert(&asset.relative_path)
        {
            return false;
        }
        if asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return false;
        }
        let Some(next) = total.checked_add(asset.size) else {
            return false;
        };
        total = next;
    }
    total <= 8 * 1024 * 1024
}

impl CoreSnapshot {
    fn valid(&self) -> bool {
        valid_owner(&self.snapshot_id)
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && valid_assets(&self.assets)
            && valid_digest(&self.controller_secret_sha256)
            && self.overlay.valid()
            && (!self.running || self.controller_port == 9090)
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn valid_lan_mac(value: &str) -> bool {
    if value.len() != 17 {
        return false;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in value.split(':').enumerate() {
        if i >= 6
            || part.len() != 2
            || !part
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return false;
        }
        let Ok(byte) = u8::from_str_radix(part, 16) else {
            return false;
        };
        bytes[i] = byte;
    }
    value.bytes().filter(|b| *b == b':').count() == 5 && bytes != [0; 6] && bytes[0] & 1 == 0
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupervisorIdentity {
    pub version: u32,
    pub owner_id: String,
    pub nonce: String,
    pub pid: u32,
    pub starttime: u64,
    pub boot_id: String,
    pub exe_sha256: String,
}
impl SupervisorIdentity {
    pub fn valid(&self) -> bool {
        self.version == 1
            && valid_owner(&self.owner_id)
            && valid_owner(&self.nonce)
            && valid_owner(&self.boot_id)
            && self.pid != 0
            && self.starttime != 0
            && valid_digest(&self.exe_sha256)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIncarnationIdentity {
    pub version: u32,
    pub boot_id: String,
    pub pid: u32,
    pub starttime: u64,
    pub nonce: String,
}
impl Journal {
    pub fn runtime_identity(&self) -> RuntimeIncarnationIdentity {
        RuntimeIncarnationIdentity {
            version: 1,
            boot_id: self.boot_id.clone(),
            pid: self.runtime_pid,
            starttime: self.runtime_starttime,
            nonce: self.runtime_nonce.clone(),
        }
    }
}
pub fn runtime_incarnation_path(
    identity: &RuntimeIncarnationIdentity,
) -> std::io::Result<std::path::PathBuf> {
    if identity.version != 1
        || !valid_owner(&identity.boot_id)
        || identity.pid == 0
        || identity.starttime == 0
        || !valid_owner(&identity.nonce)
    {
        return Err(std::io::Error::other("invalid runtime incarnation"));
    }
    Ok(std::path::PathBuf::from(format!(
        "/sys/fs/cgroup/xkeenwrt/incarnations/{}-{}-{}-{}",
        identity.boot_id, identity.pid, identity.starttime, identity.nonce
    )))
}
pub fn operation_cgroup_path(
    identity: &RuntimeIncarnationIdentity,
    owner: &str,
    generation: u64,
    tx: &str,
) -> std::io::Result<std::path::PathBuf> {
    if !valid_owner(owner) || !valid_owner(tx) || generation == 0 {
        return Err(std::io::Error::other("invalid operation identity"));
    }
    Ok(runtime_incarnation_path(identity)?
        .join("ops")
        .join(format!("{owner}-{generation}-{tx}")))
}
/// Only these fixed platform executables can be started by the isolated launcher.
#[derive(Clone, Copy)]
pub enum FixedProgram {
    Nft,
    Ip,
    Ubus,
    CoreInit,
    RecoveryInit,
    RescueInit,
    RuntimeInit,
    Apk,
    #[cfg(feature = "lab-hooks")]
    LabProbe,
}
impl FixedProgram {
    fn path(self) -> &'static str {
        match self {
            Self::Nft => "/usr/sbin/nft",
            Self::Ip => "/sbin/ip",
            Self::Ubus => "/bin/ubus",
            Self::CoreInit => "/etc/init.d/xkeenwrt-core",
            Self::RecoveryInit => "/etc/init.d/xkeenwrt-recovery",
            Self::RescueInit => "/etc/init.d/xkeenwrt-rescue",
            Self::RuntimeInit => "/usr/libexec/xkeenwrt/init/xkeenwrt-runtime",
            Self::Apk => "/usr/bin/apk",
            #[cfg(feature = "lab-hooks")]
            Self::LabProbe => "/usr/libexec/xkeenwrt/lab-clone-probe",
        }
    }
}
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedPurpose {
    Validator,
    ValidatorCleanup,
}
impl VerifiedPurpose {
    pub fn permits(self, timeout: std::time::Duration) -> bool {
        !timeout.is_zero()
            && timeout
                <= std::time::Duration::from_secs(match self {
                    Self::Validator => 75,
                    Self::ValidatorCleanup => 25,
                })
    }
}
/// Atomically place a child in the verified cgroup at creation, before it can
/// retain a flock outside the group. All child work before exec is syscall-only.
pub fn run_fixed_in_cgroup(
    program: FixedProgram,
    args: &[String],
    cgroup_dir: std::os::fd::RawFd,
    stdin: std::os::fd::RawFd,
    stdout: std::os::fd::RawFd,
    stderr: std::os::fd::RawFd,
    timeout: std::time::Duration,
) -> std::io::Result<bool> {
    #[cfg(feature = "lab-hooks")]
    let max_timeout = if matches!(program, FixedProgram::LabProbe) {
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(10)
    };
    #[cfg(not(feature = "lab-hooks"))]
    let max_timeout = std::time::Duration::from_secs(10);
    run_in_cgroup(
        Some(program),
        None,
        args,
        cgroup_dir,
        stdin,
        stdout,
        stderr,
        timeout,
        max_timeout,
    )
}
/// Execute the already authenticated regular root-owned ELF by its pinned FD.
/// Caller must verify the trusted SHA-256 over this same open file before use.
// These are syscall-level descriptor arguments with distinct child FD roles.
#[allow(clippy::too_many_arguments)]
pub fn run_verified_fd_in_cgroup(
    executable_fd: std::os::fd::RawFd,
    args: &[String],
    cgroup_dir: std::os::fd::RawFd,
    stdin: std::os::fd::RawFd,
    stdout: std::os::fd::RawFd,
    stderr: std::os::fd::RawFd,
    purpose: VerifiedPurpose,
    timeout: std::time::Duration,
) -> std::io::Result<bool> {
    if !purpose.permits(timeout) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid verified execution budget",
        ));
    }
    run_in_cgroup(
        None,
        Some(executable_fd),
        args,
        cgroup_dir,
        stdin,
        stdout,
        stderr,
        timeout,
        std::time::Duration::from_secs(match purpose {
            VerifiedPurpose::Validator => 75,
            VerifiedPurpose::ValidatorCleanup => 25,
        }),
    )
}
// Keep each descriptor role explicit at the clone3/exec boundary.
#[allow(clippy::too_many_arguments)]
fn run_in_cgroup(
    program: Option<FixedProgram>,
    executable_fd: Option<std::os::fd::RawFd>,
    args: &[String],
    cgroup_dir: std::os::fd::RawFd,
    stdin: std::os::fd::RawFd,
    stdout: std::os::fd::RawFd,
    stderr: std::os::fd::RawFd,
    timeout: std::time::Duration,
    max_timeout: std::time::Duration,
) -> std::io::Result<bool> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::Instant,
    };
    fn duplicate(fd: i32) -> std::io::Result<OwnedFd> {
        let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(result) })
    }
    if args.len() > 32
        || args.iter().any(|arg| arg.len() > 1024)
        || timeout.is_zero()
        || timeout > max_timeout
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid command bounds",
        ));
    }
    let cg = duplicate(cgroup_dir)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(cg.as_raw_fd(), &mut stat) } != 0
        || unsafe { libc::fstatfs(cg.as_raw_fd(), &mut fs) } != 0
        || stat.st_uid != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o022 != 0
        || fs.f_type as u64 != 0x6367_7270
    {
        return Err(std::io::Error::other("unsafe command cgroup"));
    }
    let pinned = executable_fd.map(duplicate).transpose()?;
    if let Some(fd) = &pinned {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
            || st.st_uid != 0
            || st.st_mode & libc::S_IFMT != libc::S_IFREG
            || st.st_mode & 0o022 != 0
            || st.st_mode & 0o111 == 0
            || st.st_nlink != 1
        {
            return Err(std::io::Error::other("unsafe executable fd"));
        }
    }
    let input = duplicate(stdin)?;
    let output = duplicate(stdout)?;
    let errors = duplicate(stderr)?;
    let executable = CString::new(
        program
            .map(FixedProgram::path)
            .unwrap_or("xkeenwrt-verified-elf"),
    )
    .map_err(std::io::Error::other)?;
    let mut arguments = Vec::with_capacity(args.len() + 1);
    arguments.push(executable.clone());
    for arg in args {
        arguments.push(CString::new(arg.as_str()).map_err(std::io::Error::other)?);
    }
    let mut argv: Vec<*const libc::c_char> = arguments.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env1 = c"PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    let env2 = c"LC_ALL=C";
    let envp = [env1.as_ptr(), env2.as_ptr(), std::ptr::null()];
    #[cfg(feature = "lab-hooks")]
    let lab_pre_stop = matches!(program, Some(FixedProgram::LabProbe))
        && args.first().is_some_and(|s| s == "preclose");
    #[cfg(feature = "lab-hooks")]
    if matches!(program, Some(FixedProgram::LabProbe)) {
        let errno = match args.first().map(String::as_str) {
            Some("fail_enosys") => Some(libc::ENOSYS),
            Some("fail_einval") => Some(libc::EINVAL),
            Some("fail_eperm") => Some(libc::EPERM),
            _ => None,
        };
        if let Some(errno) = errno {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
    }
    let parent = unsafe { libc::getpid() };
    let child_file_limit = if pinned.is_some() {
        16 * 1024 * 1024
    } else {
        1024 * 1024
    };
    let clone = CloneArgs {
        flags: 0x2_0000_0000,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cg.as_raw_fd() as u64,
        ..Default::default()
    };
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &clone, std::mem::size_of::<CloneArgs>()) };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            #[cfg(feature = "lab-hooks")]
            if lab_pre_stop {
                let own_pid = libc::syscall(libc::SYS_getpid);
                let own_tid = libc::syscall(libc::SYS_gettid);
                if libc::syscall(libc::SYS_tgkill, own_pid, own_tid, libc::SIGSTOP) != 0 {
                    libc::syscall(libc::SYS_exit_group, 126);
                }
            }
            if libc::syscall(libc::SYS_setpgid, 0, 0) != 0
                || libc::syscall(
                    libc::SYS_prctl,
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL,
                    0,
                    0,
                    0,
                ) != 0
                || libc::syscall(libc::SYS_getppid) != parent as libc::c_long
            {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            for (from, to) in [
                (input.as_raw_fd(), 0),
                (output.as_raw_fd(), 1),
                (errors.as_raw_fd(), 2),
            ] {
                if from != to && libc::syscall(libc::SYS_dup3, from, to, 0) < 0 {
                    libc::syscall(libc::SYS_exit_group, 126);
                }
            }
            if let Some(fd) = &pinned
                && ((fd.as_raw_fd() != 3
                    && libc::syscall(libc::SYS_dup3, fd.as_raw_fd(), 3, 0) < 0)
                    || libc::syscall(libc::SYS_fcntl, 3, libc::F_SETFD, libc::FD_CLOEXEC) < 0)
            {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            let limit = libc::rlimit {
                rlim_cur: child_file_limit,
                rlim_max: child_file_limit,
            };
            let first_close = if pinned.is_some() { 4u32 } else { 3u32 };
            if libc::syscall(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_FSIZE,
                &limit,
                std::ptr::null_mut::<libc::rlimit>(),
            ) != 0
                || libc::syscall(libc::SYS_close_range, first_close, u32::MAX, 0u32) != 0
            {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            if pinned.is_some() {
                libc::syscall(
                    libc::SYS_execveat,
                    3,
                    c"".as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
            } else {
                libc::syscall(
                    libc::SYS_execve,
                    executable.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                );
            }
            libc::syscall(libc::SYS_exit_group, 127);
        }
    }
    let pid = pid as libc::pid_t;
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            #[cfg(feature = "lab-hooks")]
            if matches!(program, Some(FixedProgram::LabProbe)) {
                eprintln!("LAB_CHILD_WAIT_STATUS={status}");
            }
            return Ok(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
        if result < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            let until = Instant::now() + std::time::Duration::from_millis(100);
            while Instant::now() < until {
                if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fixed command timed out",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn supervisor_cgroup_path(owner: &str, nonce: &str) -> std::io::Result<std::path::PathBuf> {
    if !valid_owner(owner) || !valid_owner(nonce) {
        return Err(std::io::Error::other("invalid supervisor identity"));
    }
    Ok(std::path::PathBuf::from(format!(
        "/sys/fs/cgroup/xkeenwrt/recovery/{owner}-{nonce}"
    )))
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    #[default]
    Remove,
    Upgrade,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Requested,
    CleanupComplete,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub version: u32,
    pub owner_id: String,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub kind: LifecycleKind,
    pub state: LifecycleState,
}

/// Separate, request-bound readiness published by the persistent supervisor
/// after a completed Remove. Upgrade continues to use its existing marker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoveResumeReady {
    pub version: u32,
    pub request_id: String,
    pub supervisor: SupervisorIdentity,
}
impl RemoveResumeReady {
    pub fn valid_for(
        &self,
        owner: &str,
        request_id: &str,
        boot_id: &str,
        exe_sha256: &str,
    ) -> bool {
        self.version == 1
            && valid_owner(owner)
            && valid_owner(request_id)
            && self.request_id == request_id
            && self.supervisor.valid()
            && self.supervisor.owner_id == owner
            && self.supervisor.boot_id == boot_id
            && self.supervisor.exe_sha256 == exe_sha256
    }
}

fn read_lifecycle_request(dir: &std::path::Path) -> std::io::Result<Option<LifecycleRequest>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("removal.json"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 4096
    {
        return Err(std::io::Error::other("unsafe lifecycle receipt"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(std::io::Error::other("oversized lifecycle receipt"));
    }
    let receipt =
        serde_json::from_slice::<LifecycleRequest>(&bytes).map_err(std::io::Error::other)?;
    if receipt.version != 1
        || !valid_owner(&receipt.owner_id)
        || receipt
            .request_id
            .as_deref()
            .is_some_and(|request_id| !valid_owner(request_id))
    {
        return Err(std::io::Error::other("invalid lifecycle receipt identity"));
    }
    Ok(Some(receipt))
}

/// Read the exact completed Remove request that may be offered to an
/// authenticated owner. This does not start helpers, change readiness, or
/// mutate the receipt.
pub fn completed_remove_request_id(
    dir: &std::path::Path,
    owner: &str,
) -> std::io::Result<Option<String>> {
    if !valid_owner(owner) {
        return Err(std::io::Error::other("invalid lifecycle owner"));
    }
    let Some(receipt) = read_lifecycle_request(dir)? else {
        return Ok(None);
    };
    if receipt.owner_id != owner {
        return Err(std::io::Error::other("lifecycle owner mismatch"));
    }
    if receipt.kind != LifecycleKind::Remove || receipt.state != LifecycleState::CleanupComplete {
        return Ok(None);
    }
    let request_id = receipt
        .request_id
        .as_deref()
        .ok_or_else(|| std::io::Error::other("completed Remove request has no identity"))?;
    verify_remove_after_integrity_check(dir, owner, request_id)?;
    Ok(Some(request_id.to_owned()))
}

/// Clear only an exact completed upgrade receipt. Caller must hold the shared
/// mutation lock and must first verify the installed package manifest/ELF hashes.
/// Removal receipts are intentionally never cleared by this operation.
pub fn verify_upgrade_after_integrity_check(
    dir: &std::path::Path,
    owner: &str,
    request_id: &str,
) -> std::io::Result<()> {
    verify_lifecycle_after_integrity_check(dir, owner, request_id, LifecycleKind::Upgrade)
}

/// Verify the exact completed Remove request that an explicit reinstall resume
/// may consume. This intentionally accepts no Upgrade receipt.
pub fn verify_remove_after_integrity_check(
    dir: &std::path::Path,
    owner: &str,
    request_id: &str,
) -> std::io::Result<()> {
    verify_lifecycle_after_integrity_check(dir, owner, request_id, LifecycleKind::Remove)
}

fn verify_lifecycle_after_integrity_check(
    dir: &std::path::Path,
    owner: &str,
    request_id: &str,
    kind: LifecycleKind,
) -> std::io::Result<()> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if !valid_owner(owner) || !valid_owner(request_id) {
        return Err(std::io::Error::other("invalid lifecycle receipt identity"));
    }
    let receipt = read_lifecycle_request(dir)?
        .ok_or_else(|| std::io::Error::other("missing lifecycle receipt"))?;
    if receipt.version != 1
        || receipt.owner_id != owner
        || receipt.request_id.as_deref() != Some(request_id)
        || receipt.kind != kind
        || receipt.state != LifecycleState::CleanupComplete
    {
        return Err(std::io::Error::other("lifecycle receipt mismatch"));
    }
    match read_journal(dir) {
        Ok(j) if j.state == State::Disabled => {
            let meta = std::fs::symlink_metadata(dir.join("recovery.json"))?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
                || j.current.owner_id != owner
                || j.decision(&j.boot_id, j.created_boottime_ms, false) != Decision::Settled
            {
                return Err(std::io::Error::other("unsafe disabled network journal"));
            }
        }
        Ok(_) => return Err(std::io::Error::other("network not disabled")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(dir.join("network-never-enabled"))?;
            let meta = f.metadata()?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
                || meta.len() > 64
            {
                return Err(std::io::Error::other("unsafe never-enabled marker"));
            }
            let mut text = String::new();
            f.take(65).read_to_string(&mut text)?;
            if text != "xkeenwrt-no-network-v1\n" {
                return Err(std::io::Error::other("unknown network history"));
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
/// Caller must retain the shared mutation lock across verify, manual journal
/// settle without starting core, and this exact receipt CAS/finish.
pub fn finish_upgrade_after_integrity_check(
    dir: &std::path::Path,
    owner: &str,
    request_id: &str,
) -> std::io::Result<()> {
    verify_upgrade_after_integrity_check(dir, owner, request_id)?;
    require_terminal_lifecycle_cleanup(dir)?;
    std::fs::remove_file(dir.join("removal.json"))?;
    std::fs::File::open(dir)?.sync_all()
}

/// Caller must retain the shared mutation lock across verification, stopped
/// manual-state settlement, and this final durable Remove-receipt consumption.
pub fn finish_remove_after_integrity_check(
    dir: &std::path::Path,
    owner: &str,
    request_id: &str,
) -> std::io::Result<()> {
    verify_remove_after_integrity_check(dir, owner, request_id)?;
    require_terminal_lifecycle_cleanup(dir)?;
    std::fs::remove_file(dir.join("removal.json"))?;
    std::fs::File::open(dir)?.sync_all()
}

fn require_terminal_lifecycle_cleanup(dir: &std::path::Path) -> std::io::Result<()> {
    match read_journal(dir) {
        Ok(j) => {
            let request = read_lifecycle_request(dir)?
                .ok_or_else(|| std::io::Error::other("missing lifecycle request"))?;
            if !j.lifecycle_cleanup_matches(&request) {
                return Err(std::io::Error::other(
                    "network lifecycle completion pending",
                ));
            }
            match std::fs::symlink_metadata(dir.join("active-reconcile.json")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(std::io::Error::other("active event retirement pending")),
            }
        }
        // verify_lifecycle_after_integrity_check already proves never-enabled.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Publish a fully-synced file atomically without replacing an existing name.
/// Both paths must be trusted siblings in the same protected directory.
pub fn publish_noreplace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<bool> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    if from.parent() != to.parent() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "publication paths must share a directory",
        ));
    }
    let from = CString::new(from.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            1u32,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        Ok(false)
    } else {
        Err(error)
    }
}

pub mod flow_offload;
pub mod topology;

pub mod explicit;

pub mod input_state;
