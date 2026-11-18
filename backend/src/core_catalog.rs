//! Static, ABI-specific release allowlist for the OpenWrt Mihomo updater.
//! Hashes are pinned from the official MetaCubeX GitHub release asset metadata.

pub use mihomo_release::{RELEASES, Release};

pub fn release(version: &str) -> Option<&'static Release> {
    mihomo_release::release(version)
}
