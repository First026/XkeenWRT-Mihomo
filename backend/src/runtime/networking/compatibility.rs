//! One read-only evaluator for the compatibility API and fresh Start admission.
//! Missing independent inputs become separate prerequisites; findings never
//! carry raw inventory, addresses, YAML, subscription URLs or connection tuples.
use super::{
    collector, inventory,
    read::{self, Query},
};
use serde::Serialize;
use std::{collections::BTreeSet, io::Read, net::Ipv4Addr};
use xkeenwrt_recovery::{
    Manifest,
    flow_offload::FlowTable,
    topology::{FirewallConflict, Severity},
};
#[derive(Default)]
pub struct Inputs {
    pub links: Vec<u8>,
    pub addresses: Vec<u8>,
    pub neighbours: Vec<u8>,
    pub leases: Vec<u8>,
    pub netifd: Vec<u8>,
    pub dnsconfig: Vec<u8>,
    pub proxyconfig: Vec<u8>,
    pub proxyservice: Vec<u8>,
    pub rules4: Vec<u8>,
    pub rules6: Vec<u8>,
    pub routes4: Vec<u8>,
    pub routes6: Vec<u8>,
    pub nft: Vec<u8>,
    pub modules: Vec<u8>,
    pub sockets: [Vec<u8>; 4],
    pub flowtables: Option<Vec<FlowTable>>,
    pub ipv6_offloaded: Option<usize>,
    pub owned_listeners: bool,
    /// Router address of the current tailscale0 management boundary, if any.
    pub tailscale: Option<Ipv4Addr>,
}
pub use crate::runtime::resources::{Forecast, Shortage};
#[derive(Clone, Debug, Serialize)]
pub struct Application {
    pub packages_verified: bool,
    pub rescue_verified: bool,
    pub accepted_profile: bool,
    /// Forecast for the next Start: each shortage carries its numbers.
    pub resources: Forecast,
    pub lifecycle_clear: bool,
    pub journal_readable: bool,
}
/// Numbers behind a resource finding; never paths, addresses or YAML.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Detail {
    Resource(Shortage),
    Cleanup { cleanup_entries: usize },
}
#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub check: &'static str,
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall: Option<FirewallConflict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flowtable: Option<FlowTable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
}
#[derive(Default, Debug, Serialize)]
pub struct Report {
    pub ready: bool,
    pub issues: Vec<Issue>,
    pub completed_checks: Vec<&'static str>,
    pub truncated: usize,
}
impl Report {
    fn issue(&mut self, severity: Severity, check: &'static str, code: &'static str, message: &'static str) {
        if self.issues.len() < 256 {
            self.issues.push(Issue {
                severity,
                check,
                code,
                message,
                firewall: None,
                flowtable: None,
                detail: None,
            });
        } else {
            self.truncated += 1;
        }
    }
    fn detailed(
        &mut self, severity: Severity, check: &'static str, code: &'static str, message: &'static str, detail: Detail,
    ) {
        self.issue(severity, check, code, message);
        if let Some(issue) = self.issues.last_mut().filter(|i| i.code == code) {
            issue.detail = Some(detail);
        }
    }
    fn resources(&mut self, forecast: &Forecast) {
        self.completed_checks.push("resources");
        if forecast.unavailable {
            self.issue(
                Severity::Blocker,
                "resources",
                "NETWORK_RESOURCES",
                "Не удалось проверить свободные ресурсы роутера.",
            );
        }
        for shortage in &forecast.shortages {
            let message = match shortage {
                Shortage::Memory { .. } => "Мало свободной памяти для запуска.",
                Shortage::Tmp { .. } => "Мало места во временном хранилище.",
                Shortage::Flash { .. } => "Мало места во флеш-памяти.",
                Shortage::History { .. } => "История заполнена, и очистка не освободит достаточно места.",
            };
            self.detailed(
                Severity::Blocker,
                "resources",
                shortage.code(),
                message,
                Detail::Resource(shortage.clone()),
            );
        }
        if forecast.cleanup_entries > 0 {
            self.detailed(
                Severity::Warning,
                "resources",
                "NETWORK_HISTORY_CLEANUP",
                "Перед запуском будут удалены старые неиспользуемые записи истории.",
                Detail::Cleanup {
                    cleanup_entries: forecast.cleanup_entries,
                },
            );
        }
    }
    fn check(&mut self, name: &'static str, valid: bool, code: &'static str, message: &'static str) {
        self.completed_checks.push(name);
        if !valid {
            self.issue(Severity::Blocker, name, code, message);
        }
    }
}
fn valid_json(bytes: &[u8]) -> bool {
    bytes.len() <= 1_048_576 && serde_json::from_slice::<serde_json::Value>(bytes).is_ok()
}
pub fn main_lan(input: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(input).ok()?;
    let entries: Vec<_> = value["interface"]
        .as_array()?
        .iter()
        .filter(|i| i["interface"] == "lan" && i["up"] == true)
        .collect();
    let [lan] = entries.as_slice() else {
        return None;
    };
    Some(lan["l3_device"].as_str()?.to_owned())
}
/// Start admission for the management peer: a LAN host under the r26 rule,
/// or a Tailscale peer that reached the listener of the current tailscale0
/// boundary and lies outside the LAN (decision 024).
pub fn management_allowed(
    scope: Option<&str>, lan_address: Ipv4Addr, peer: crate::management::ManagementPeer, tailscale: Option<Ipv4Addr>,
) -> bool {
    let Some(scope) = scope else {
        return false;
    };
    match peer {
        crate::management::ManagementPeer::Lan { peer } => xkeenwrt_recovery::valid_lan_scope(scope, lan_address, peer),
        crate::management::ManagementPeer::Tailscale { peer, router } => {
            tailscale == Some(router) && xkeenwrt_recovery::valid_overlay_scope(scope, lan_address, peer)
        }
    }
}
/// Restart of the selected inputs: a LAN peer may restart any selection; over
/// Tailscale only the gateway, because HTTP/SOCKS is a main-LAN binding.
pub fn restart_allowed(
    scope: Option<&str>, lan_address: Ipv4Addr, peer: crate::management::ManagementPeer, tailscale: Option<Ipv4Addr>,
    explicit_selected: bool,
) -> bool {
    match peer {
        crate::management::ManagementPeer::Lan { .. } => management_allowed(scope, lan_address, peer, None),
        crate::management::ManagementPeer::Tailscale { .. } => {
            !explicit_selected && management_allowed(scope, lan_address, peer, tailscale)
        }
    }
}
/// Enabling HTTP/SOCKS binds a LAN address its administrator chose; it is a
/// main-LAN action. Turning it off is allowed from any channel.
pub fn explicit_allowed(peer: crate::management::ManagementPeer) -> bool {
    peer.channel().is_none()
}
/// Router address of the tailscale0 management boundary as it is right now.
pub(crate) fn current_tailscale() -> Option<Ipv4Addr> {
    crate::management::discover_tailscale().and_then(|b| match b.address.ip() {
        std::net::IpAddr::V4(router) => Some(router),
        std::net::IpAddr::V6(_) => None,
    })
}
/// This exact pure evaluator is also the offline snapshot seam. Application
/// facts and management peer must be supplied explicitly in an offline replay.
pub fn evaluate(
    i: &Inputs, app: &Application, peer: impl Into<crate::management::ManagementPeer>, current: Option<&Manifest>,
) -> Report {
    let peer = peer.into();
    let mut report = Report::default();
    for (name, valid, code, message) in [
        (
            "storage",
            app.journal_readable,
            "NETWORK_STORAGE",
            "Durable network journal недоступен или повреждён.",
        ),
        (
            "packages",
            app.packages_verified,
            "NETWORK_PACKAGES",
            "Не подтверждена целостность совместимой пары пакетов.",
        ),
        (
            "recovery",
            app.rescue_verified,
            "NETWORK_RECOVERY",
            "Не подтверждён совместимый независимый recovery.",
        ),
        (
            "profile",
            app.accepted_profile,
            "PROFILE_REQUIRED",
            "Сначала примените сохранённый профиль.",
        ),
    ] {
        report.check(name, valid, code, message);
    }
    report.resources(&app.resources);
    report.check(
        "lifecycle",
        app.lifecycle_clear,
        "NETWORK_LIFECYCLE",
        "Установка, удаление или восстановление ещё не завершены.",
    );
    let lan = main_lan(&i.netifd);
    report.check(
        "lan",
        lan.is_some(),
        "NETWORK_LAN",
        "Основная активная IPv4 LAN не определена однозначно.",
    );
    let address = lan
        .as_ref()
        .and_then(|lan| inventory::address_facts(&i.addresses, lan).ok());
    report.check(
        "addresses",
        address.is_some(),
        "NETWORK_ADDRESSES",
        "Не получен корректный полный список адресов интерфейсов.",
    );
    if let (Some(lan), Some(address)) = (&lan, &address) {
        let net: serde_json::Value = serde_json::from_slice(&i.netifd).unwrap_or_default();
        let agrees = net["interface"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| v["interface"] == "lan")
            .all(|v| {
                v["ipv4-address"].as_array().is_some_and(|a| {
                    a.iter().any(|x| {
                        x["address"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) == Some(address.lan_address)
                    })
                })
            });
        report.check(
            "lan_link",
            agrees && inventory::ethernet_like(&i.links, lan).unwrap_or(false),
            "NETWORK_LAN_LINK",
            "Адрес и Ethernet/bridge LAN не согласованы между kernel и netifd.",
        );
        let scope = address.lan_cidrs.as_slice();
        let scope = if scope.len() == 1 {
            xkeenwrt_recovery::lan_network(&scope[0])
        } else {
            None
        };
        report.check(
            "management",
            management_allowed(scope.as_deref(), address.lan_address, peer, i.tailscale),
            "NETWORK_MANAGEMENT",
            match peer {
                crate::management::ManagementPeer::Lan { .. } => {
                    "Запуск разрешён только из основной IPv4 LAN с сохранённым путём управления."
                }
                crate::management::ManagementPeer::Tailscale { .. } => {
                    "Tailscale-вход изменился или недоступен: обновите страницу панели."
                }
            },
        );
    }
    let modules = std::str::from_utf8(&i.modules)
        .ok()
        .filter(|_| i.modules.len() <= 1_048_576);
    report.check(
        "modules",
        modules.is_some_and(|m| {
            ["nft_tproxy", "nft_socket"]
                .iter()
                .all(|name| m.lines().any(|l| l.split_ascii_whitespace().next() == Some(name)))
        }),
        "NETWORK_MODULES_MISSING",
        "Не загружены обязательные nft_tproxy/nft_socket.",
    );
    let foreign = match current {
        Some(m) => collector::strip_owned_nft(&i.nft, m).ok(),
        None => Some(i.nft.clone()),
    };
    let occupied = foreign.as_ref().and_then(|f| inventory::occupied_nft(f).ok());
    report.check(
        "firewall_inventory",
        occupied.is_some(),
        "NETWORK_FIREWALL_UNAVAILABLE",
        "Полный nft inventory недоступен или повреждён.",
    );
    if let Some(occupied) = &occupied {
        report.check(
            "firewall_owner",
            !occupied.xkeenwrt_table_exists,
            "NETWORK_OWNER_CONFLICT",
            "Таблица приложения не имеет подтверждённого владельца.",
        );
    }
    if let (Some(nft), Some(lan)) = (&foreign, &lan) {
        match xkeenwrt_recovery::topology::compatibility_report(nft, &[lan], &i.addresses) {
            Ok(firewall) => {
                report.completed_checks.push("firewall_rules");
                report.truncated += firewall.truncated;
                for finding in firewall.findings {
                    if report.issues.len() < 256 {
                        report.issues.push(Issue {
                            severity: finding.severity,
                            check: "firewall_rules",
                            code: if finding.severity == Severity::Blocker {
                                "NETWORK_FIREWALL_CONFLICT"
                            } else {
                                "FIREWALL_UNKNOWN"
                            },
                            message: if finding.severity == Severity::Blocker {
                                "Доказано пересечение с перехватываемым трафиком LAN."
                            } else {
                                "Синтаксис или эффект не установлен; повреждающее пересечение не доказано."
                            },
                            firewall: Some(finding.detail),
                            flowtable: None,
                            detail: None,
                        });
                    } else {
                        report.truncated += 1;
                    }
                }
            }
            Err(_) => report.issue(
                Severity::Blocker,
                "firewall_rules",
                "NETWORK_FIREWALL_UNAVAILABLE",
                "Семантическая проверка не выполнена: обязательный nft/address inventory неполон.",
            ),
        }
    }
    match &i.flowtables {
        Some(tables) => {
            match xkeenwrt_recovery::flow_offload::verify_metadata(&i.nft, tables) {
                Ok(()) => report.completed_checks.push("flowtable_metadata"),
                Err(_) => report.issue(
                    Severity::Blocker,
                    "flowtables",
                    "FLOWTABLE_METADATA_UNAVAILABLE",
                    "Kernel flags/devices/hook flowtable не согласованы с nft snapshot.",
                ),
            }
            if let Some(lan) = &lan {
                for table in tables {
                    match xkeenwrt_recovery::flow_offload::affects_lan(table, &i.links, lan) {
                        Ok(true) if table.flags & !2 != 0 => {
                            report.issue(Severity::Blocker,"flowtables","HARDWARE_OFFLOAD_UNVERIFIED","Настроен аппаратный flow offload; завершение targeted hardware teardown не подтверждено на этом оборудовании.");
                            if let Some(issue) = report.issues.last_mut() {
                                issue.flowtable = Some(table.clone());
                            }
                        }
                        Ok(true) => {
                            report.issue(Severity::Warning,"flowtables","SOFTWARE_OFFLOAD_RECONNECT","Старые захватываемые TCP/UDP соединения будут выборочно сброшены; может потребоваться переподключение.");
                            if let Some(issue) = report.issues.last_mut() {
                                issue.flowtable = Some(table.clone());
                            }
                        }
                        Err(_) => report.issue(
                            Severity::Blocker,
                            "flowtables",
                            "FLOWTABLE_SCOPE_UNAVAILABLE",
                            "Не доказана связь flowtable devices с bridge/ingress основной LAN.",
                        ),
                        _ => (),
                    }
                }
            }
            let affected = lan.as_ref().is_some_and(|lan| {
                xkeenwrt_recovery::flow_offload::transition_required(tables, &i.links, lan).unwrap_or(true)
            });
            if affected && let (Some(lan), Some(address)) = (&lan, &address) {
                let scope = address.lan_cidrs.as_slice();
                let scope = if scope.len() == 1 {
                    xkeenwrt_recovery::lan_network(&scope[0])
                } else {
                    None
                };
                report.check("offload_scope",scope.is_some_and(|scope|xkeenwrt_recovery::flow_offload::scope_admissible(lan,&scope,&i.addresses,&i.links,&i.nft,&i.rules4,&i.routes6).is_ok()),"OFFLOAD_SCOPE_UNVERIFIED","Default zone и непересекающаяся область LAN/IPv6 для selective conntrack transition не подтверждены.");
            }
            if affected {
                match i.ipv6_offloaded {
                    Some(0)=>report.completed_checks.push("ipv6_offload_connections"),
                    Some(_)=>report.issue(Severity::Blocker,"ipv6_offload_connections","IPV6_OFFLOAD_UNVERIFIED","Обнаружены старые IPv6 OFFLOAD соединения; их область и переход не подтверждены. IPv6 conntrack не удаляется."),
                    None=>report.issue(Severity::Blocker,"ipv6_offload_connections","IPV6_OFFLOAD_NOT_OBSERVED","Не получен полный bounded conntrack snapshot для исключения старых IPv6 OFFLOAD соединений."),
                }
                report.check(
                    "conntrack_module",
                    modules.is_some_and(|m| {
                        m.lines()
                            .any(|l| l.split_ascii_whitespace().next() == Some("nf_conntrack_netlink"))
                    }),
                    "CONNTRACK_UNAVAILABLE",
                    "Не загружен native ctnetlink для безопасного перехода software offload.",
                );
            }
        }
        None => report.issue(
            Severity::Blocker,
            "flowtables",
            "FLOWTABLE_METADATA_UNAVAILABLE",
            "Не получены обязательные свежие runtime flags flowtable.",
        ),
    }
    let r4 = inventory::occupied_rules(&i.rules4);
    let r6 = inventory::occupied_rules(&i.rules6);
    report.check(
        "rules4",
        r4.is_ok(),
        "NETWORK_RULES_UNAVAILABLE",
        "IPv4 policy rules недоступны или неоднозначны.",
    );
    report.check(
        "rules6",
        r6.is_ok(),
        "NETWORK_RULES_UNAVAILABLE",
        "IPv6 policy rules недоступны или неоднозначны.",
    );
    let mut tables = BTreeSet::new();
    let mut local4 = BTreeSet::new();
    let mut local6 = BTreeSet::new();
    report.check(
        "routes4",
        inventory::route_facts(&i.routes4, false, &mut tables, &mut local4).is_ok(),
        "NETWORK_ROUTES_UNAVAILABLE",
        "IPv4 маршруты недоступны или не поддерживаются.",
    );
    report.check(
        "routes6",
        inventory::route_facts(&i.routes6, true, &mut tables, &mut local6).is_ok(),
        "NETWORK_ROUTES_UNAVAILABLE",
        "IPv6 маршруты недоступны или не поддерживаются.",
    );
    if let (Ok(r4), Ok(r6), Some(nft)) = (&r4, &r6, &occupied) {
        let mut occupied_tables: Vec<_> = tables.iter().copied().collect();
        occupied_tables.extend(&r4.tables);
        occupied_tables.extend(&r6.tables);
        let mut marks = r4.marks.clone();
        marks.extend(&r6.marks);
        marks.push((nft.used_mark_mask, nft.used_mark_mask));
        let mut priorities = r4.priorities.clone();
        priorities.extend(&r6.priorities);
        let (table, mark, priority) = crate::network::allocation_candidates(&occupied_tables, &marks, &priorities);
        report.check(
            "mark_allocation",
            mark.is_some(),
            "NETWORK_MARK_CONFLICT",
            "Не осталось свободных mark bits, занятых известными действиями/селекторами.",
        );
        report.check(
            "table_allocation",
            table.is_some(),
            "NETWORK_TABLE_CONFLICT",
            "Нет свободной policy routing table в диапазоне100..252.",
        );
        report.check(
            "priority_allocation",
            priority.is_some(),
            "NETWORK_PRIORITY_CONFLICT",
            "Нет свободного policy rule priority в диапазоне10000..32000.",
        );
    }
    if let Some(current) = current {
        report.check(
            "owned_routing",
            super::status::routing_matches(current, &i.rules4, &i.routes4).unwrap_or(false),
            "NETWORK_OWNER_CONFLICT",
            "Подтверждённые policy route/rule изменены.",
        );
    }
    for (index, socket) in i.sockets.iter().enumerate() {
        match collector::occupied_listener_port(socket) {
            Ok(None) => report.completed_checks.push(match index {
                0 => "tcp4",
                1 => "udp4",
                2 => "tcp6",
                _ => "udp6",
            }),
            Ok(Some(_)) if i.owned_listeners => (), // Exact live PID ownership is checked below by Start collector.
            Ok(Some(_)) => report.issue(
                Severity::Blocker,
                "listeners",
                "NETWORK_PORT_CONFLICT",
                "Служебный TCP/UDP порт 7893 или 1053 занят чужим сокетом.",
            ),
            Err(_) => report.issue(
                Severity::Blocker,
                "listeners",
                "NETWORK_LISTENERS_UNAVAILABLE",
                "Не получен корректный полный список TCP/UDP сокетов.",
            ),
        }
    }
    match inventory::dnsmasq_facts(&i.dnsconfig) {
        Ok(mut dns) => {
            let config: serde_json::Value = serde_json::from_slice(&i.dnsconfig).unwrap_or_default();
            let lease_path = config["values"]
                .as_object()
                .into_iter()
                .flat_map(|v| v.values())
                .filter(|v| v[".type"] == "dnsmasq")
                .all(|v| v.get("leasefile").is_none_or(|p| p == "/tmp/dhcp.leases"));
            report.check(
                "dns_lease_path",
                lease_path,
                "NETWORK_DNS_UNSUPPORTED",
                "Используется неподдерживаемый путь dnsmasq leases.",
            );

            let inodes = if dns.has_loopback_upstream() {
                inventory::https_dns_proxy_socket_inodes(&i.proxyservice)
            } else {
                Ok(Vec::new())
            };
            let verified = inodes.ok().and_then(|inodes| {
                inventory::verified_loopback_chain(
                    &dns,
                    &i.dnsconfig,
                    &i.proxyconfig,
                    &i.proxyservice,
                    [&i.sockets[0], &i.sockets[1], &i.sockets[2], &i.sockets[3]],
                    &inodes,
                )
                .ok()
            });
            dns.verified_loopback_chain_sha256 = verified.clone().flatten();
            report.check(
                "dns_chain",
                verified.is_some(),
                "NETWORK_DNS_UNSUPPORTED",
                "DNS upstream/loopback proxy chain не подтверждён.",
            );
            if let Some(a) = &address {
                report.check(
                    "dns_targets",
                    inventory::validate_dns_targets(
                        &dns,
                        &a.local_ipv4,
                        &a.local_ipv6,
                        dns.verified_loopback_chain_sha256.as_deref(),
                    )
                    .is_ok(),
                    "NETWORK_DNS_UNSUPPORTED",
                    "DNS upstream конфликтует с локальным или перехватываемым назначением.",
                );
            }
        }
        Err(_) => report.issue(
            Severity::Blocker,
            "dns",
            "NETWORK_DNS_UNSUPPORTED",
            "Не получена поддерживаемая конфигурация dnsmasq/resolver.",
        ),
    }
    for (name, input) in [
        ("neighbours", &i.neighbours),
        ("links_inventory", &i.links),
        ("netifd_inventory", &i.netifd),
    ] {
        report.check(
            name,
            valid_json(input),
            "NETWORK_INVENTORY_UNAVAILABLE",
            "Независимый обязательный inventory недоступен или повреждён.",
        );
    }
    report.ready = report.truncated == 0 && !report.issues.iter().any(|i| i.severity == Severity::Blocker);
    report
}
fn proc_read(path: &str) -> Vec<u8> {
    let mut b = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(1_048_577).read_to_end(&mut b);
    }
    b
}
pub(crate) fn collect(cgroup: &std::fs::File) -> Inputs {
    let q = |query| read::query(query, cgroup).unwrap_or_default();
    let firewall = xkeenwrt_recovery::flow_offload::capture_nft(|| read::query(Query::NftRuleset, cgroup)).ok();
    let (nft, flowtables) = firewall.map(|(n, f)| (n, Some(f))).unwrap_or_default();
    let mut result = Inputs {
        links: q(Query::Links),
        addresses: q(Query::Addresses),
        neighbours: q(Query::Neighbours),
        leases: read::default_leases().unwrap_or_default(),
        netifd: q(Query::NetworkStatus),
        dnsconfig: q(Query::DnsConfig),
        proxyconfig: q(Query::ProxyConfig),
        proxyservice: q(Query::ProxyService),
        rules4: q(Query::Rules4),
        rules6: q(Query::Rules6),
        routes4: q(Query::Routes4),
        routes6: q(Query::Routes6),
        nft,
        modules: proc_read("/proc/modules"),
        sockets: [
            proc_read("/proc/net/tcp"),
            proc_read("/proc/net/udp"),
            proc_read("/proc/net/tcp6"),
            proc_read("/proc/net/udp6"),
        ],
        ipv6_offloaded: if flowtables.as_ref().is_some_and(|t| !t.is_empty()) {
            xkeenwrt_recovery::flow_offload::ipv6_offloaded().ok()
        } else {
            Some(0)
        },
        flowtables,
        owned_listeners: false,
        tailscale: current_tailscale(),
    };
    if let Some(lan) = main_lan(&result.netifd)
        && let (Ok(address), Ok(before)) = (
            inventory::address_facts(&result.addresses, &lan),
            super::helper::core_identity(cgroup),
        )
        && let Ok(inodes) = super::helper::process_socket_inodes(before.0)
    {
        result.owned_listeners = collector::listeners_owned(
            [&result.sockets[0], &result.sockets[1], &result.sockets[2], &result.sockets[3]],
            address.lan_address,
            &inodes,
        )
        .unwrap_or(false)
            && super::helper::core_identity(cgroup).ok() == Some(before);
    }
    result
}

/// Same admission thresholds as native core resource checks; offline callers
/// must supply real, timestamped capacity evidence rather than VM defaults.
/// History is not replayed offline: a foreign tree cannot be planned here.
pub fn resource_forecast(memory: u64, reclaimable: u64, tmp: u64, flash: u64, bundle: u64, staging: u64) -> Forecast {
    crate::runtime::resources::evaluate(
        &crate::runtime::resources::Measured {
            memory_available: memory,
            memory_reclaimable: reclaimable,
            tmp_free: tmp,
            tmp_block: 1,
            flash_free: flash,
            flash_block: 1,
        },
        bundle,
        staging,
        crate::runtime::resources::HistoryOutlook::Fits { cleanup_entries: 0 },
    )
}

/// Shared durable input for both Service Start and the read-only report.
/// An unreadable/corrupt journal is never equivalent to no prior generation.
pub fn network_journal(dir: &std::path::Path) -> std::io::Result<Option<xkeenwrt_recovery::Journal>> {
    use std::os::unix::fs::MetadataExt;
    let m = match std::fs::symlink_metadata(dir.join("recovery.json")) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err(std::io::Error::other("unsafe recovery journal"));
    }
    let journal = xkeenwrt_recovery::read_journal(dir)?;
    if journal.decision(&journal.boot_id, journal.created_boottime_ms, false) == xkeenwrt_recovery::Decision::Invalid {
        return Err(std::io::Error::other("invalid recovery journal"));
    }
    Ok(Some(journal))
}
