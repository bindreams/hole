//! Built-in DNS forwarder — carries DNS over the shadowsocks tunnel so
//! clients paired with TCP-only plugins (v2ray-plugin) can still resolve.
//!
//! See `CLAUDE.md` ("UDP policy" + "Crash recovery") for the architectural
//! context.

pub mod connector;
pub mod forwarder;
pub mod providers;
pub mod server;
pub mod socks5_connector;
