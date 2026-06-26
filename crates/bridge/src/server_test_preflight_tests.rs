//! Unit tests for [`super::server_endpoint_is_udp`] — the transport-aware
//! preflight gate added in bindreams/hole#421.
//!
//! Kept separate from `server_test_tests.rs`: these are pure, I/O-free table
//! assertions that must run on every platform, whereas `server_test_tests` does
//! real connectivity I/O. The QUIC interop tests that depend on the preflight
//! skip run on Windows too.

use super::{preflight, server_endpoint_is_udp};
use hole_common::config::ServerEntry;
use hole_common::protocol::ServerTestOutcome;
use std::net::SocketAddr;
use std::time::Duration;

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

// preflight ===========================================================================================================
//
// `preflight` takes a resolved `SocketAddr` (DoH already resolved the
// hostname), so it does no DNS and connects to the raw IP. This is the
// platform-independent guard for the IPv6 bug: a bracketed-string target would
// fail `IpAddr::parse` and be mistreated as a hostname.

use crate::test_support::rt;
use tokio::net::TcpListener;

#[skuld::test]
fn preflight_connects_to_raw_ipv6_socketaddr() {
    rt().block_on(async {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        assert!(addr.is_ipv6(), "listener bound to IPv6 loopback");
        let res = preflight(addr, Duration::from_millis(500)).await;
        assert!(
            res.is_ok(),
            "preflight to a live raw [::1] target must succeed, got {res:?}"
        );
    });
}

#[skuld::test]
fn preflight_reports_tcp_failure_for_closed_ipv6_port() {
    rt().block_on(async {
        // [::1]:1 is a closed IPv6 loopback port — refused or timed out, never DnsFailed.
        let addr: SocketAddr = "[::1]:1".parse().unwrap();
        let res = preflight(addr, Duration::from_millis(500)).await;
        assert!(
            matches!(
                res,
                Err(ServerTestOutcome::TcpRefused) | Err(ServerTestOutcome::TcpTimeout)
            ),
            "closed IPv6 port must surface a TCP failure, got {res:?}"
        );
    });
}
