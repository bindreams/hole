//! Built-in DNS forwarder — carries DNS over the shadowsocks tunnel so
//! clients paired with TCP-only plugins (v2ray-plugin) can still resolve.
//!
//! The architecture is in `docs/contributing/architecture/dns-forwarder.md` and
//! `docs/contributing/architecture/datapath.md`.

pub mod bootstrap;
pub mod connector;
pub mod ech;
pub mod forwarder;
pub mod providers;
pub mod recovery;
pub(crate) mod self_test;
pub mod socks5_connector;
pub mod system;
