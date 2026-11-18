//! Client names from the fixed OpenWrt dnsmasq lease file. No Keenetic RCI.
use std::{
    io::Read,
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

fn leases(text: &str, now: u64) -> Vec<serde_json::Value> {
    text.lines()
        .take(512)
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let expires = fields.next()?.parse::<u64>().ok()?;
            fields.next()?; // MAC is neither needed nor returned.
            let ip = fields.next()?.parse::<IpAddr>().ok()?;
            let name = fields.next()?;
            if (expires != 0 && expires <= now)
                || ip.is_unspecified()
                || ip.is_multicast()
                || name == "*"
                || name.len() > 253
                || !name.chars().all(|c| c.is_alphanumeric() || ".-_".contains(c))
            {
                return None;
            }
            Some(serde_json::json!({"ip": ip.to_string(), "name": name}))
        })
        .collect()
}

pub async fn get() -> axum::Json<serde_json::Value> {
    let hosts = (|| -> std::io::Result<_> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open("/tmp/dhcp.leases")?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != 0 || meta.len() > 524288 {
            return Err(std::io::Error::other("invalid lease file"));
        }
        let mut text = String::new();
        file.take(524289).read_to_string(&mut text)?;
        if text.len() > 524288 {
            return Err(std::io::Error::other("oversized leases"));
        }
        Ok(leases(&text, chrono::Utc::now().timestamp().max(0) as u64))
    })()
    .unwrap_or_default();
    axum::Json(serde_json::json!({"success": true, "host": hosts, "source": "dnsmasq-leases"}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn names_use_only_current_valid_leases_without_exposing_mac() {
        let hosts = super::leases(
            "200 aa:bb:cc:dd:ee:ff 192.0.2.2 laptop *\n99 aa 192.0.2.3 stale *\n0 aa 192.0.2.4 * *\n0 aa 192.0.2.5 <script> *",
            100,
        );
        assert_eq!(hosts, vec![serde_json::json!({"ip":"192.0.2.2", "name":"laptop"})]);
    }
}
