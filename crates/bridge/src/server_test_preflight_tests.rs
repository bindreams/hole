//! Unit tests for [`super::server_endpoint_is_udp`] — the transport-aware
//! preflight gate added in bindreams/hole#421.
//!
//! Deliberately NOT in `server_test_tests.rs`: that module is gated
//! `cfg(not(any(macos, windows)))` (Linux-only, #197/#200). These are pure,
//! I/O-free table assertions that MUST run on every platform, because the QUIC
//! interop tests that depend on the preflight skip run on Windows too.

use super::server_endpoint_is_udp;
use hole_common::config::ServerEntry;

/// A `ServerEntry` with only `plugin` / `plugin_opts` set to the values under
/// test; every other field is an irrelevant placeholder.
fn entry(plugin: Option<&str>, plugin_opts: Option<&str>) -> ServerEntry {
    ServerEntry {
        plugin: plugin.map(Into::into),
        plugin_opts: plugin_opts.map(Into::into),
        ..ServerEntry::default_placeholder()
    }
}

#[skuld::test]
fn quic_endpoint_is_udp() {
    // Direct v2ray-plugin/ex-ray QUIC server.
    assert!(server_endpoint_is_udp(&entry(
        Some("v2ray-plugin"),
        Some("host=cloudfront.com;mode=quic;cert=/x;key=/y"),
    )));
    // galoshes passes `mode=quic` through to its embedded ex-ray.
    assert!(server_endpoint_is_udp(&entry(
        Some("galoshes"),
        Some("server;mode=quic;host=cdn"),
    )));
}

#[skuld::test]
fn non_quic_endpoint_is_tcp() {
    // websocket (the default transport) is TCP.
    assert!(!server_endpoint_is_udp(&entry(
        Some("v2ray-plugin"),
        Some("host=cloudfront.com;path=/"),
    )));
    // Plugin configured but no options at all.
    assert!(!server_endpoint_is_udp(&entry(Some("v2ray-plugin"), None)));
    // No plugin → plain shadowsocks, always TCP-fronted.
    assert!(!server_endpoint_is_udp(&entry(None, None)));
    // Options mention quic but no plugin is configured: the gate requires a
    // plugin (a plain SS server never speaks quic).
    assert!(!server_endpoint_is_udp(&entry(None, Some("mode=quic"))));
    // A key that merely contains "mode" must not match (exact-key parse).
    assert!(!server_endpoint_is_udp(&entry(
        Some("v2ray-plugin"),
        Some("servermode=quic"),
    )));
}
