//! Independent, exact ownership of the optional LAN HTTP/SOCKS input guard.
//! No capture routes, DNS configuration or foreign tables are changed here.
use profile_policy::ExplicitOverlay;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const TABLE: &str = "xkeenwrt_explicit";
const STATE: &str = "/etc/xkeenwrt/explicit-guard.json";
fn fail() -> io::Error {
    io::Error::other("explicit input ownership or protection cannot be verified")
}

pub fn expected(e: &ExplicitOverlay) -> io::Result<Value> {
    if !e.valid() {
        return Err(fail());
    }
    let (address, prefix) = e.lan_scope.split_once('/').ok_or_else(fail)?;
    let port = json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":e.port}});
    let mut ast = json!({"nftables":[
        {"table":{"family":"inet","name":TABLE,"comment":format!("xkeenwrt-explicit:{}:{}",e.owner_id,e.generation)}},
        {"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":-200,"policy":"accept"}},
        {"rule":{"family":"inet","table":TABLE,"chain":"input","expr":[
            port.clone(),
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":e.lan_ifname}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":e.lan_ipv4.to_string()}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":address,"len":prefix.parse::<u8>().map_err(|_|fail())?}}}},
            {"counter":{"packets":0,"bytes":0}},{"accept":null}
        ]}},
        {"rule":{"family":"inet","table":TABLE,"chain":"input","expr":[port,{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}
    ]});
    for index in [2usize, 3usize] {
        let mut rule = ast["nftables"][index].clone();
        for e in rule["rule"]["expr"].as_array_mut().ok_or_else(fail)? {
            if e["match"]["left"] == json!({"payload":{"protocol":"tcp","field":"dport"}}) {
                e["match"]["left"] = json!({"payload":{"protocol":"udp","field":"dport"}});
            }
        }
        ast["nftables"].as_array_mut().ok_or_else(fail)?.push(rule);
    }
    Ok(ast)
}
fn digest(mut value: Value) -> io::Result<String> {
    for item in value["nftables"].as_array_mut().ok_or_else(fail)? {
        let object = item.as_object_mut().ok_or_else(fail)?;
        if object.len() != 1 {
            return Err(fail());
        }
        let (kind, body) = object.iter_mut().next().ok_or_else(fail)?;
        if !["table", "chain", "rule"].contains(&kind.as_str()) || body["family"] != "inet" {
            return Err(fail());
        }
        let field = if kind == "table" { "name" } else { "table" };
        if body[field] != TABLE {
            return Err(fail());
        }
        body[field] = json!("xkeenwrt");
    }
    crate::nft_semantic_digest(&serde_json::to_vec(&value).map_err(|_| fail())?)
}
pub fn owned_snapshot(input: &[u8]) -> io::Result<Option<Value>> {
    if input.len() > 1_048_576 {
        return Err(fail());
    }
    let input: Value = serde_json::from_slice(input).map_err(|_| fail())?;
    let mut items = Vec::new();
    for item in input["nftables"].as_array().ok_or_else(fail)? {
        let object = item.as_object().ok_or_else(fail)?;
        if object.len() != 1 {
            return Err(fail());
        }
        let (kind, body) = object.iter().next().ok_or_else(fail)?;
        if body["family"] == "inet" && body[if kind == "table" { "name" } else { "table" }] == TABLE
        {
            items.push(item.clone());
        }
    }
    Ok((!items.is_empty()).then(|| json!({"nftables":items})))
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardState {
    pub current: Option<ExplicitOverlay>,
    pub pending: Option<GuardIntent>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardIntent {
    pub target: Option<ExplicitOverlay>,
}
impl GuardState {
    pub fn valid(&self) -> bool {
        self.current.as_ref().is_none_or(ExplicitOverlay::valid)
            && self
                .pending
                .as_ref()
                .is_none_or(|p| p.target.as_ref().is_none_or(ExplicitOverlay::valid))
    }
}
pub trait Adapter {
    fn read_nft(&mut self) -> io::Result<Vec<u8>>;
    fn apply_nft(&mut self, batch: &str) -> io::Result<()>;
    fn load(&mut self) -> io::Result<GuardState>;
    fn persist(&mut self, state: &GuardState) -> io::Result<()>;
}
/// Persist an intent before the atomic table change. A crash permits cleanup
/// of exactly the old or proposed semantics, never a table identified by name.
pub fn reconcile(a: &mut impl Adapter, target: Option<&ExplicitOverlay>) -> io::Result<()> {
    if target.is_some_and(|e| !e.valid()) {
        return Err(fail());
    }
    let mut state = a.load()?;
    if !state.valid() {
        return Err(fail());
    }
    let actual = owned_snapshot(&a.read_nft()?)?;
    if let Some(actual) = &actual {
        let actual = digest(actual.clone())?;
        if !std::iter::once(state.current.as_ref())
            .chain(state.pending.as_ref().map(|p| p.target.as_ref()))
            .flatten()
            .any(|e| expected(e).and_then(digest).is_ok_and(|s| s == actual))
        {
            return Err(fail());
        }
    }
    let wanted = target.map(expected).transpose()?;
    if actual.as_ref().map(|v| digest(v.clone())).transpose()?
        != wanted.as_ref().map(|v| digest(v.clone())).transpose()?
    {
        state.pending = Some(GuardIntent {
            target: target.cloned(),
        });
        a.persist(&state)?;
        let mut batch = Vec::new();
        if actual.is_some() {
            batch.push(json!({"delete":{"table":{"family":"inet","name":TABLE}}}));
        }
        if let Some(wanted) = &wanted {
            for item in wanted["nftables"].as_array().ok_or_else(fail)? {
                batch.push(json!({"add":item}));
            }
        }
        a.apply_nft(&serde_json::to_string(&json!({"nftables":batch})).map_err(|_| fail())?)?;
    }
    let after = owned_snapshot(&a.read_nft()?)?;
    if after.as_ref().map(|v| digest(v.clone())).transpose()? != wanted.map(digest).transpose()? {
        return Err(fail());
    }
    if state.current.as_ref() == target && state.pending.is_none() {
        return Ok(());
    }
    state.current = target.cloned();
    state.pending = None;
    a.persist(&state)
}
pub fn load_state() -> io::Result<GuardState> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(STATE)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(GuardState::default()),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > 16384
    {
        return Err(fail());
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    let state: GuardState = serde_json::from_slice(&bytes).map_err(|_| fail())?;
    if !state.valid() {
        return Err(fail());
    }
    Ok(state)
}
pub fn persist_state(state: &GuardState) -> io::Result<()> {
    if !state.valid() {
        return Err(fail());
    }
    let dir = Path::new("/etc/xkeenwrt");
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err(fail());
    }
    let mut nonce = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let temp = dir.join(format!(
        ".explicit-{}-{}",
        std::process::id(),
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        f.write_all(&serde_json::to_vec(state).map_err(|_| fail())?)?;
        f.sync_all()?;
        fs::rename(&temp, STATE)?;
        fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

/// Corroborate the selected binding with kernel addresses and the one netifd
/// administrative LAN. Connected/private-looking destinations alone do not count.
pub fn verify_binding(e: &ExplicitOverlay, addresses: &[u8], netifd: &[u8]) -> io::Result<()> {
    if !e.valid() || netifd.len() > 1_048_576 {
        return Err(fail());
    }
    let facts =
        crate::evidence::inventory::address_facts(addresses, &e.lan_ifname).map_err(|_| fail())?;
    if facts.lan_address != e.lan_ipv4
        || facts.lan_cidrs.len() != 1
        || crate::lan_network(&facts.lan_cidrs[0]).as_deref() != Some(&e.lan_scope)
    {
        return Err(fail());
    }
    let value: Value = serde_json::from_slice(netifd).map_err(|_| fail())?;
    let entries: Vec<_> = value["interface"]
        .as_array()
        .ok_or_else(fail)?
        .iter()
        .filter(|v| v["interface"] == "lan" && v["up"] == true)
        .collect();
    let [lan] = entries.as_slice() else {
        return Err(fail());
    };
    if lan["l3_device"] != e.lan_ifname
        || !lan["ipv4-address"]
            .as_array()
            .is_some_and(|a| a.iter().any(|i| i["address"] == e.lan_ipv4.to_string()))
    {
        return Err(fail());
    }
    Ok(())
}

pub fn verify(e: &ExplicitOverlay, nft: &[u8]) -> io::Result<()> {
    let actual = owned_snapshot(nft)?.ok_or_else(fail)?;
    if digest(actual)? != digest(expected(e)?)? {
        return Err(fail());
    }
    Ok(())
}
/// Only the exact IPv4 listener and established sockets of the verified PID
/// can occupy mixed port. IPv6/wildcard/foreign sockets always fail admission.
pub fn socket_proof(
    tables: [&[u8]; 4],
    target: Option<&ExplicitOverlay>,
    inodes: &[u64],
    required: bool,
) -> io::Result<bool> {
    let mut tcp = 0;
    let address = target.map(|e| {
        let a = e.lan_ipv4.octets();
        format!("{:02X}{:02X}{:02X}{:02X}", a[3], a[2], a[1], a[0])
    });
    for (kind, table) in tables.iter().enumerate() {
        if table.len() > 1_048_576 {
            return Err(fail());
        }
        let text = std::str::from_utf8(table).map_err(|_| fail())?;
        let mut lines = text.lines();
        if !lines
            .next()
            .is_some_and(|s| s.split_ascii_whitespace().any(|s| s == "local_address"))
        {
            return Err(fail());
        }
        for line in lines {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let (host, port) = fields
                .get(1)
                .and_then(|s| s.split_once(':'))
                .ok_or_else(fail)?;
            if u16::from_str_radix(port, 16).map_err(|_| fail())? != 7890 {
                continue;
            }
            let state = *fields.get(3).ok_or_else(fail)?;
            let inode = fields
                .get(9)
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(fail)?;
            if kind % 2 == 0 && state == "06" && inode == 0 {
                continue;
            }
            if target.is_none()
                || kind >= 2
                || !address
                    .as_ref()
                    .is_some_and(|a| host.eq_ignore_ascii_case(a))
                || inode == 0
                || !inodes.contains(&inode)
            {
                return Ok(false);
            }
            if kind == 0 && state == "0A" {
                tcp += 1;
            }
        }
    }
    Ok(if required { tcp == 1 } else { tcp <= 1 })
}
