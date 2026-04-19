//! Shared test fixtures for bridge integration tests.
//!
//! Spawns real in-process shadowsocks servers (via `shadowsocks-service`'s
//! `server` feature, already a dev-dep) and optional v2ray-plugin
//! subprocesses, with variants for each supported transport. Consumed by
//! `*_tests.rs` files across the crate.
//!
//! **Convention deviation**: this module is registered directly from
//! `lib.rs` rather than via the project-wide `#[path = "foo_tests.rs"] mod
//! foo_tests;` sibling-source pattern, because there is no business-logic
//! counterpart — it is pure cross-cutting test infrastructure used by
//! multiple `*_tests.rs` files (`server_test_tests.rs`,
//! `proxy_manager_e2e_tests.rs`, ...). The `#[cfg(test)]` gate lives on the
//! `mod test_support;` declaration in `lib.rs`.
#![allow(dead_code)]

pub(crate) mod certs;
pub(crate) mod dist_fixture;
pub(crate) mod dist_harness;
pub(crate) mod http_connect_client;
pub(crate) mod http_target;
pub(crate) mod net_discovery;
pub(crate) mod port_alloc;
pub(crate) mod skuld_fixtures;
pub(crate) mod socks5_client;
pub(crate) mod ssserver;
pub(crate) mod udp_echo;

/// Build a fresh tokio runtime for one test. Mirrors `ipc_tests::rt()`.
///
/// Lives at the module root because it's useful to every test file, not just
/// ssserver-related ones.
pub(crate) fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}
