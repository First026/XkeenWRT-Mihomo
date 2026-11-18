//! OpenWrt-specific entry points. Upstream modules remain in the source tree but
//! are deliberately not linked into the router-facing server.
pub mod platform;
pub mod runtime;

pub mod configuration;
pub mod http;
pub mod mihomo;
pub mod network;

mod frontend_embedder;

pub mod core_catalog;
pub mod core_update;
pub mod management;
pub mod private_file;
pub mod self_update;
pub mod system;
pub mod system_log;

pub mod backups;
pub mod diagnostics;
pub mod resources;
pub mod rule_resources;

pub mod device_list;
