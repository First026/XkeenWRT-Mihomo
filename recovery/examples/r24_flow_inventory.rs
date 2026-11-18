fn main() {
    let result = if std::env::args().any(|s| s == "--paired") {
        xkeenwrt_recovery::flow_offload::capture_nft(|| {
            let out = std::process::Command::new("/usr/sbin/nft")
                .args(["-j", "list", "ruleset"])
                .output()?;
            if !out.status.success() {
                return Err(std::io::Error::other("nft read failed"));
            }
            Ok(out.stdout)
        })
        .map(|(_, tables)| tables)
    } else {
        xkeenwrt_recovery::flow_offload::flowtables()
    };
    match result {
        Ok(tables) => println!("{}", serde_json::to_string_pretty(&tables).unwrap()),
        Err(e) => {
            eprintln!("FLOWTABLE_INVENTORY_ERROR: {e}");
            std::process::exit(1);
        }
    }
}
