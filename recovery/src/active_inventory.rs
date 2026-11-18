//! Fixed, bounded read-only topology recapture for independent rescue.
//! The shared pure parser validates UCI and lease-path assumptions before use.
use crate::commands::{self, InventoryQuery as Q};
use std::io;

pub(crate) struct RawInventory {
    pub flowtables: Vec<xkeenwrt_recovery::flow_offload::FlowTable>,
    pub addresses: Vec<u8>,
    pub neighbours: Vec<u8>,
    pub links: Vec<u8>,
    pub rules4: Vec<u8>,
    pub rules6: Vec<u8>,
    pub routes4: Vec<u8>,
    pub routes6: Vec<u8>,
    pub nft: Vec<u8>,
    pub network: Vec<u8>,
    pub dns: Vec<u8>,
    pub proxyconfig: Vec<u8>,
    pub proxyservice: Vec<u8>,
    pub tcp4: Vec<u8>,
    pub udp4: Vec<u8>,
    pub tcp6: Vec<u8>,
    pub udp6: Vec<u8>,
    pub leases: Vec<u8>,
}
pub(crate) fn capture() -> io::Result<RawInventory> {
    let dns = commands::inventory(Q::DnsConfig)?;
    let dns_facts = xkeenwrt_recovery::evidence::inventory::dnsmasq_facts(&dns)
        .map_err(|_| io::Error::other("invalid dnsmasq inventory"))?;
    let (proxyconfig, proxyservice) = if dns_facts.has_loopback_upstream() {
        (
            commands::inventory(Q::ProxyConfig)?,
            commands::inventory(Q::ProxyService)?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let (nft, flowtables) =
        xkeenwrt_recovery::flow_offload::capture_nft(|| commands::inventory(Q::NftRuleset))?;
    Ok(RawInventory {
        flowtables,
        addresses: commands::inventory(Q::Addresses)?,
        neighbours: commands::inventory(Q::Neighbours)?,
        links: commands::inventory(Q::Links)?,
        rules4: commands::inventory(Q::Rules4)?,
        rules6: commands::inventory(Q::Rules6)?,
        routes4: commands::inventory(Q::Routes4)?,
        routes6: commands::inventory(Q::Routes6)?,
        nft,
        network: commands::inventory(Q::NetworkStatus)?,
        dns,
        proxyconfig,
        proxyservice,
        tcp4: read_proc("/proc/net/tcp")?,
        udp4: read_proc("/proc/net/udp")?,
        tcp6: read_proc("/proc/net/tcp6")?,
        udp6: read_proc("/proc/net/udp6")?,
        leases: commands::default_leases()?,
    })
}
fn read_proc(path: &str) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err(io::Error::other("socket table too large"));
    }
    Ok(bytes)
}

/// Verify two separately collected snapshots against the previously pinned
/// evidence. The caller obtains the phase exclusively from its durable event.
pub(crate) fn verify_failure_topology(
    manifest: &xkeenwrt_recovery::Manifest,
    expected: &xkeenwrt_recovery::evidence::NetworkEvidence,
    nft_digest: Option<&str>,
    routing: (bool, bool),
) -> io::Result<()> {
    use xkeenwrt_recovery::evidence::{
        FixedInputs, NetworkEvidence, NftExpectation, OwnedExpectation, RoutingExpectation,
    };
    if !expected.matches_manifest(manifest) {
        return Err(io::Error::other("invalid pinned topology"));
    }
    for _ in 0..2 {
        let raw = capture()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        let input = FixedInputs {
            flowtables: Some(&raw.flowtables),
            links: &raw.links,
            addresses: &raw.addresses,
            neighbours: &raw.neighbours,
            leases: &raw.leases,
            netifd: &raw.network,
            dnsconfig: &raw.dns,
            proxyconfig: &raw.proxyconfig,
            proxyservice: &raw.proxyservice,
            tcp4: &raw.tcp4,
            udp4: &raw.udp4,
            tcp6: &raw.tcp6,
            udp6: &raw.udp6,
            nft: &raw.nft,
            rules4: &raw.rules4,
            rules6: &raw.rules6,
            routes4: &raw.routes4,
            routes6: &raw.routes6,
            now_unix: now,
        };
        let owned = OwnedExpectation {
            manifest,
            scope_manifest: None,
            nft: match nft_digest {
                Some(d) => NftExpectation::Digest(d),
                None => NftExpectation::Absent,
            },
            routing: match routing {
                (false, false) => RoutingExpectation::Absent,
                (true, false) => RoutingExpectation::RouteOnly,
                (false, true) => RoutingExpectation::RuleOnly,
                (true, true) => RoutingExpectation::Exact,
            },
        };
        if !NetworkEvidence::capture_fixed(&input, owned)?.compatible_with(expected) {
            return Err(io::Error::other("trusted topology changed"));
        }
    }
    Ok(())
}
