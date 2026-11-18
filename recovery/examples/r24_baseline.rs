//! Read-only baseline probe at the production firewall classifier seam.
use std::{env, fs, path::PathBuf};
fn main() {
    let root = PathBuf::from(env::args_os().nth(1).expect("snapshot path"));
    let nft = fs::read(root.join("nft-ruleset.json")).unwrap();
    let addresses = fs::read(root.join("ip-address.json")).unwrap();
    let result = xkeenwrt_recovery::topology::topology_conflict_with_inventory(
        &nft,
        &["br-lan"],
        &addresses,
    );
    match result {
        Ok(finding) => println!(
            "{}",
            serde_json::json!({"scope":"production firewall seam only; r23 has no full report","first_finding":finding})
        ),
        Err(e) => println!("{{\"inventory_error\":\"{e:?}\"}}"),
    }
}
