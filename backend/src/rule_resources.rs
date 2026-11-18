//! Bounded readers for Mihomo MRS v1 and v2ray GeoSite/GeoIP DAT.
//! MRS wire layout: MetaCubeX/mihomo rules/provider/mrs_reader.go and
//! component/{trie/domain_set_bin.go,cidr/ipcidr_set_bin.go} (v1.19.34).
use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
const LIMIT: usize = 16 * 1024 * 1024;
const INVALID: &str = "Некорректный или слишком большой геофайл";

pub struct Mrs {
    pub behavior: &'static str,
    pub rules: Vec<String>,
}
fn take<'a>(data: &mut &'a [u8], count: usize) -> Result<&'a [u8], &'static str> {
    let (head, tail) = data.split_at_checked(count).ok_or(INVALID)?;
    *data = tail;
    Ok(head)
}
fn number(data: &mut &[u8]) -> Result<usize, &'static str> {
    let n = u64::from_be_bytes(take(data, 8)?.try_into().map_err(|_| INVALID)?);
    if n > LIMIT as u64 {
        return Err(INVALID);
    }
    Ok(n as usize)
}
fn words(data: &mut &[u8]) -> Result<Vec<u64>, &'static str> {
    let count = number(data)?;
    take(data, count.checked_mul(8).ok_or(INVALID)?)?
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| Ok(u64::from_be_bytes(*b)))
        .collect()
}
fn bit(words: &[u64], at: usize) -> Result<bool, &'static str> {
    Ok(words.get(at / 64).ok_or(INVALID)? & (1u64 << (at % 64)) != 0)
}
fn zstd_window(data: &[u8]) -> Result<(), &'static str> {
    let mut data = data;
    if take(&mut data, 4)? != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(INVALID);
    }
    let descriptor = take(&mut data, 1)?[0];
    if descriptor & 0x18 != 0 {
        return Err(INVALID);
    }
    let single = descriptor & 0x20 != 0;
    if !single {
        let w = take(&mut data, 1)?[0];
        let base = 1u64.checked_shl(10 + (w >> 3) as u32).ok_or(INVALID)?;
        if base.saturating_add((base / 8) * u64::from(w & 7)) > LIMIT as u64 {
            return Err(INVALID);
        }
    }
    let dict_size = [0, 1, 2, 4][(descriptor & 3) as usize];
    if take(&mut data, dict_size)?.iter().any(|b| *b != 0) {
        return Err(INVALID);
    }
    let size_len = match descriptor >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if size_len != 0 {
        let mut bytes = [0; 8];
        bytes[..size_len].copy_from_slice(take(&mut data, size_len)?);
        let size = u64::from_le_bytes(bytes) + if size_len == 2 { 256 } else { 0 };
        if size > LIMIT as u64 {
            return Err(INVALID);
        }
    }
    Ok(())
}
pub fn read_mrs(compressed: &[u8]) -> Result<Mrs, &'static str> {
    if compressed.len() > 8 * 1024 * 1024 {
        return Err(INVALID);
    }
    zstd_window(compressed)?;
    let mut cursor = Cursor::new(compressed);
    let mut decoded = Vec::new();
    {
        let reader = ruzstd::decoding::StreamingDecoder::new(&mut cursor).map_err(|_| INVALID)?;
        reader
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut decoded)
            .map_err(|_| INVALID)?;
    }
    if decoded.len() > LIMIT || cursor.position() != compressed.len() as u64 {
        return Err(INVALID);
    }
    read_mrs_payload(&decoded)
}
fn read_mrs_payload(mut data: &[u8]) -> Result<Mrs, &'static str> {
    if take(&mut data, 4)? != b"MRS\x01" {
        return Err(INVALID);
    }
    let behavior = match take(&mut data, 1)?[0] {
        0 => "domain",
        1 => "ipcidr",
        _ => return Err("MRS classical не поддерживается Mihomo"),
    };
    let count = number(&mut data)?;
    if count > 200_000 {
        return Err(INVALID);
    }
    let extra = number(&mut data)?;
    take(&mut data, extra)?;
    if take(&mut data, 1)? != [1] {
        return Err(INVALID);
    }
    let mut rules = Vec::new();
    if behavior == "domain" {
        let leaves = words(&mut data)?;
        let bitmap = words(&mut data)?;
        let label_count = number(&mut data)?;
        if label_count > 1_000_000 {
            return Err(INVALID);
        }
        let labels = take(&mut data, label_count)?;
        let mut parents = Vec::with_capacity(label_count + 1);
        parents.push((0usize, 0u8));
        let (mut node, mut edge, mut total) = (0usize, 0usize, 0usize);
        while node < parents.len() {
            while !bit(&bitmap, edge + node)? {
                let label = *labels.get(edge).ok_or(INVALID)?;
                if !(label.is_ascii_alphanumeric() || b"._-*+".contains(&label)) {
                    return Err(INVALID);
                }
                parents.push((node, label));
                edge += 1;
            }
            if bit(&leaves, node)? {
                let mut name = Vec::new();
                let mut at = node;
                while at > 0 {
                    let (parent, label) = parents[at];
                    name.push(label);
                    at = parent;
                    if name.len() > 253 {
                        return Err(INVALID);
                    }
                }
                if name.is_empty() {
                    return Err(INVALID);
                }
                total += name.len();
                if total > LIMIT || rules.len() >= 200_000 {
                    return Err(INVALID);
                }
                rules.push(String::from_utf8(name).map_err(|_| INVALID)?);
            }
            node += 1;
        }
        if edge != label_count {
            return Err(INVALID);
        }
    } else {
        let ranges = number(&mut data)?;
        if ranges > 200_000 {
            return Err(INVALID);
        }
        for _ in 0..ranges {
            let from = u128::from_be_bytes(take(&mut data, 16)?.try_into().map_err(|_| INVALID)?);
            let to = u128::from_be_bytes(take(&mut data, 16)?.try_into().map_err(|_| INVALID)?);
            if from > to {
                return Err(INVALID);
            }
            let v4 = from >> 32 == 0xffff && to >> 32 == 0xffff;
            let (mut from, to, bits) = if v4 {
                (from & 0xffff_ffff, to & 0xffff_ffff, 32)
            } else {
                (from, to, 128)
            };
            loop {
                let mut shift = from.trailing_zeros().min(bits);
                while shift > 0
                    && (shift == 128 && (from != 0 || to != u128::MAX)
                        || shift < 128 && (from | ((1u128 << shift) - 1)) > to)
                {
                    shift -= 1;
                }
                let address = if v4 {
                    IpAddr::V4(Ipv4Addr::from(from as u32))
                } else {
                    IpAddr::V6(Ipv6Addr::from(from))
                };
                rules.push(format!("{address}/{}", bits - shift));
                if rules.len() > 200_000 {
                    return Err(INVALID);
                }
                let end = if shift == 128 {
                    u128::MAX
                } else {
                    from | ((1u128 << shift) - 1)
                };
                if end == to {
                    break;
                }
                from = end.checked_add(1).ok_or(INVALID)?;
            }
        }
    }
    if !data.is_empty() || (count > 0 && rules.is_empty()) {
        return Err(INVALID);
    }
    Ok(Mrs { behavior, rules })
}

#[derive(Clone, Copy)]
enum Field<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}
fn fields(mut data: &[u8]) -> Result<Vec<(u64, Field<'_>)>, &'static str> {
    use prost::encoding::decode_varint;
    let mut result = Vec::new();
    while !data.is_empty() {
        if result.len() >= 200_000 {
            return Err(INVALID);
        }
        let key = decode_varint(&mut data).map_err(|_| INVALID)?;
        if key >> 3 == 0 {
            return Err(INVALID);
        }
        let field = match key & 7 {
            0 => Field::Number(decode_varint(&mut data).map_err(|_| INVALID)?),
            2 => {
                let size = decode_varint(&mut data).map_err(|_| INVALID)?;
                if size > LIMIT as u64 {
                    return Err(INVALID);
                }
                Field::Bytes(take(&mut data, size as usize)?)
            }
            1 => {
                take(&mut data, 8)?;
                continue;
            }
            5 => {
                take(&mut data, 4)?;
                continue;
            }
            _ => return Err(INVALID),
        };
        result.push((key >> 3, field));
    }
    Ok(result)
}
pub fn suffix(domain: &str, value: &str) -> bool {
    domain == value || domain.strip_suffix(value).is_some_and(|head| head.ends_with('.'))
}
pub fn domain_pattern(domain: &str, pattern: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(tail) = pattern.strip_prefix("+.") {
        return suffix(&domain, tail);
    }
    if let Some(tail) = pattern.strip_prefix('.') {
        return domain != tail && suffix(&domain, tail);
    }
    let escaped = pattern
        .split('.')
        .map(|part| {
            if part == "*" {
                "[^.]+".to_owned()
            } else {
                regex_lite::escape(part)
            }
        })
        .collect::<Vec<_>>()
        .join("\\.");
    regex_lite::Regex::new(&format!("^{escaped}$")).is_ok_and(|re| re.is_match(&domain))
}
pub fn cidr_matches(ip: IpAddr, cidr: &str) -> Result<bool, &'static str> {
    let (net, prefix) = cidr.split_once('/').ok_or(INVALID)?;
    let net = net.parse::<IpAddr>().map_err(|_| INVALID)?;
    let prefix = prefix.parse::<u8>().map_err(|_| INVALID)?;
    Ok(crate::management::Cidr::new(net, prefix).ok_or(INVALID)?.contains(ip))
}
pub fn dat_categories(data: &[u8], target: &str, ip_mode: bool) -> Result<Vec<String>, &'static str> {
    if data.len() > 8 * 1024 * 1024 {
        return Err(INVALID);
    }
    let ip = if ip_mode {
        Some(target.parse::<IpAddr>().map_err(|_| "Введите IP-адрес")?)
    } else {
        None
    };
    let domain = target.to_ascii_lowercase();
    let mut matches = Vec::new();
    let mut entries = 0;
    for (tag, entry) in fields(data)? {
        let (1, Field::Bytes(entry)) = (tag, entry) else {
            continue;
        };
        entries += 1;
        let entry = fields(entry)?;
        let code = entry
            .iter()
            .find_map(|(tag, field)| match (tag, field) {
                (1, Field::Bytes(value)) => std::str::from_utf8(value).ok(),
                _ => None,
            })
            .ok_or(INVALID)?;
        if code.is_empty() || code.len() > 128 {
            return Err(INVALID);
        }
        let mut found = false;
        for (tag, field) in &entry {
            let (2, Field::Bytes(payload)) = (tag, field) else {
                continue;
            };
            let values = fields(payload)?;
            if let Some(ip) = ip {
                let address = values
                    .iter()
                    .find_map(|(tag, value)| match (tag, value) {
                        (1, Field::Bytes(value)) => Some(*value),
                        _ => None,
                    })
                    .ok_or(INVALID)?;
                let prefix = values
                    .iter()
                    .find_map(|(tag, value)| match (tag, value) {
                        (2, Field::Number(n)) => Some(*n),
                        _ => None,
                    })
                    .unwrap_or(0);
                let address = match address.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(address).map_err(|_| INVALID)?)),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(address).map_err(|_| INVALID)?)),
                    _ => return Err(INVALID),
                };
                let prefix = u8::try_from(prefix).map_err(|_| INVALID)?;
                found |= crate::management::Cidr::new(address, prefix)
                    .ok_or(INVALID)?
                    .contains(ip);
            } else {
                let kind = values
                    .iter()
                    .find_map(|(tag, value)| match (tag, value) {
                        (1, Field::Number(n)) => Some(*n),
                        _ => None,
                    })
                    .unwrap_or(0);
                let value = values
                    .iter()
                    .find_map(|(tag, value)| match (tag, value) {
                        (2, Field::Bytes(value)) => std::str::from_utf8(value).ok(),
                        _ => None,
                    })
                    .ok_or(INVALID)?;
                if value.len() > 4096 {
                    return Err(INVALID);
                }
                let value = value.to_ascii_lowercase();
                found |= match kind {
                    0 => domain.contains(&value),
                    1 => regex_lite::Regex::new(&value).map_err(|_| INVALID)?.is_match(&domain),
                    2 => suffix(&domain, &value),
                    3 => domain == value,
                    _ => return Err(INVALID),
                };
            }
        }
        if ip_mode && entry.iter().any(|(tag, f)| matches!((tag, f), (3, Field::Number(1)))) {
            found = !found;
        }
        if found {
            matches.push(code.to_owned());
        }
        if entries > 4096 {
            return Err(INVALID);
        }
    }
    if entries == 0 {
        return Err(INVALID);
    }
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_mihomo_mrs_and_protobuf_fixtures_match_domain_and_ip_queries() {
        let domains = read_mrs(include_bytes!("../tests/fixtures/geodata/domains.mrs")).unwrap();
        assert_eq!(domains.behavior, "domain");
        for host in ["example.org", "sub.example.org", "exact.test", "one.wild.test"] {
            assert!(
                domains.rules.iter().any(|r| domain_pattern(host, r)),
                "{host}: {:?}",
                domains.rules
            );
        }
        assert!(!domains.rules.iter().any(|r| domain_pattern("other.test", r)));
        let ips = read_mrs(include_bytes!("../tests/fixtures/geodata/addresses.mrs")).unwrap();
        assert_eq!(ips.behavior, "ipcidr");
        for ip in ["192.0.2.7", "2001:db8::7"] {
            assert!(ips.rules.iter().any(|r| cidr_matches(ip.parse().unwrap(), r).unwrap()));
        }
        assert_eq!(
            dat_categories(
                include_bytes!("../tests/fixtures/geodata/geosite.dat"),
                "sub.example.org",
                false
            )
            .unwrap(),
            ["TEST"]
        );
        assert!(
            dat_categories(
                include_bytes!("../tests/fixtures/geodata/geosite.dat"),
                "other.test",
                false
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            dat_categories(include_bytes!("../tests/fixtures/geodata/geoip.dat"), "192.0.2.7", true).unwrap(),
            ["TEST"]
        );
        assert!(
            dat_categories(
                include_bytes!("../tests/fixtures/geodata/geoip.dat"),
                "198.51.100.1",
                true
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn domain_boundaries_and_ip_families_are_preserved() {
        assert!(domain_pattern("cdn.example.com", "+.example.com"));
        assert!(domain_pattern("example.com", "+.example.com"));
        assert!(!domain_pattern("notexample.com", "+.example.com"));
        assert!(!domain_pattern("deep.cdn.example.com", "*.example.com"));
        assert!(cidr_matches("192.0.2.4".parse().unwrap(), "192.0.2.0/24").unwrap());
        assert!(!cidr_matches("::ffff:192.0.2.4".parse().unwrap(), "192.0.2.0/24").unwrap());
        assert!(cidr_matches("192.0.2.4".parse().unwrap(), "192.0.2.0/33").is_err());
    }
    #[test]
    fn invalid_mrs_headers_are_rejected_before_allocating() {
        assert!(read_mrs(b"not zstd").is_err());
        assert!(read_mrs(&[0x28, 0xb5, 0x2f, 0xfd, 0, 255]).is_err());
        assert!(read_mrs_payload(b"MRS\x01").is_err());
    }
}
