//! Tests for [`server_test::run_server_test`].
//!
//! Each test stands up a real shadowsocks server fixture (via `shadowsocks-service`
//! with the `server` feature, dev-dep) bound to `127.0.0.1:0`, plus a tiny tokio
//! TCP "fake sentinel" listener. The test runner is then pointed at the fixture
//! and asserted against.
//!
//! The server/sentinel/port helpers live in the crate-wide `test_support`
//! module so `proxy_manager_e2e_tests.rs` can reuse them.

// Sanctioned per-test CancellationToken::new (no caller-side token in these unit
// fixtures). See clippy.toml.
#![allow(clippy::disallowed_methods)]

use super::{run_server_test, TestConfig};
use crate::test_support::port_alloc::wait_for_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::PORT_ALLOC;
use hole_common::config::ServerEntry;
use hole_common::protocol::ServerTestOutcome;
use plugin_e2e::locators::locate_ex_ray;
use plugin_e2e::sentinel::start_fake_sentinel;
use plugin_e2e::ssserver::{
    start_real_ss_server, start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_METHOD_STR, TEST_PASSWORD,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Build a [`ServerEntry`] for the runner under test.
fn entry(host: &str, port: u16, method: &str, password: &str) -> ServerEntry {
    ServerEntry {
        id: "test-entry".into(),
        name: "test".into(),
        server: host.into(),
        server_port: port,
        method: method.into(),
        password: password.into(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    }
}

/// Fast defaults for tests that don't need plugin startup.
///
/// These tests no longer touch the routing table, so tight timeouts are
/// safe. If CI fails, investigate root cause rather than bumping these.
fn fast_test_config(sentinel_a: SocketAddr, sentinel_b: SocketAddr) -> TestConfig {
    TestConfig {
        preflight_timeout: Duration::from_millis(500),
        ss_connect_timeout: Duration::from_millis(800),
        sentinel_read_timeout: Duration::from_millis(800),
        sentinels: [sentinel_a.to_string(), sentinel_b.to_string()],
        plugin_path_override: None,
        dns: hole_common::config::DnsConfig::default(),
        bootstrap_querier: None,
    }
}

// Tests ===============================================================================================================

/// Sanity test for the [`start_real_ss_server`] fixture: bind it, accept one
/// raw TCP connect (no shadowsocks handshake), and verify both addresses are
/// loopback. This guards against fixture-API drift in `shadowsocks-service`
/// — if it stops compiling, every other test in this file fails too.
///
/// `[PORT_ALLOC] + serial = PORT_ALLOC` because the test inline-calls
/// `start_real_ss_server` (which allocates a loopback port) without
/// going through an `ssserver_*` fixture, so the label does not
/// propagate transitively. See `PORT_ALLOC`'s docstring.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn fixture_starts_real_ss_server() {
    rt().block_on(async {
        let (svr_addr, _svr_handle) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        assert!(svr_addr.ip().is_loopback(), "server bound to non-loopback");
        assert_ne!(svr_addr.port(), 0, "server port not assigned");

        // Raw TCP connect — proves the listener is up. We do NOT speak
        // shadowsocks here; the full-protocol path is exercised by the
        // other tests.
        let stream = tokio::net::TcpStream::connect(svr_addr).await.unwrap();
        assert!(stream.peer_addr().unwrap().ip().is_loopback());
    });
}

/// Build a [`TestConfig`] pointing at a single bogus IP for both sentinels.
/// Used by the pre-flight tests, where the test never reaches Phase 3.
///
/// Empty `servers` + `allow_insecure_bootstrap = true`: the DoH loop has no
/// resolver to try, so the bootstrap skips straight to the OS resolver. No live
/// DoH endpoint is contacted.
fn preflight_only_config() -> TestConfig {
    let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
    TestConfig {
        preflight_timeout: Duration::from_millis(500),
        ss_connect_timeout: Duration::from_millis(500),
        sentinel_read_timeout: Duration::from_millis(500),
        sentinels: [bogus.to_string(), bogus.to_string()],
        plugin_path_override: None,
        dns: hole_common::config::DnsConfig {
            servers: Vec::new(),
            allow_insecure_bootstrap: true,
            ..hole_common::config::DnsConfig::default()
        },
        bootstrap_querier: None,
    }
}

/// Test 1: happy path. Real server, valid credentials, fake sentinel that
/// returns a HTTP-prefixed response. Should produce
/// [`ServerTestOutcome::Reachable`] with `latency_ms >= 1`.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_reachable_for_valid_credentials() {
    rt().block_on(async {
        let (svr_addr, _svr_handle) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            TEST_PASSWORD,
        );
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::Reachable { latency_ms } => {
                assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1");
            }
            other => panic!("expected Reachable, got {other:?}"),
        }
    });
}

/// Test 2: DNS failure for unresolvable host.
///
/// Uses the RFC 2606-reserved `.invalid` TLD, which compliant resolvers MUST
/// fail. Caveat: some captive-portal / ISP DNS hijacks return a synthetic
/// A record for unknown names; on those networks the test will reach the
/// TCP-connect phase and fail with `TcpRefused`/`TcpTimeout` instead. CI
/// runners (GitHub Actions) do not hijack DNS, so this is CI-deterministic.
/// On a contributor's hostile-DNS local network, accept any preflight failure.
#[skuld::test]
fn run_test_returns_dns_failed_for_unresolvable_host() {
    rt().block_on(async {
        let entry = entry("no-such-host.invalid", 8388, TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = preflight_only_config();
        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::DnsFailed => {}
            // Tolerate the captive-portal hijack case for off-CI runs:
            ServerTestOutcome::TcpRefused | ServerTestOutcome::TcpTimeout => {
                eprintln!(
                    "WARNING: .invalid TLD resolved to a synthetic address — \
                     local DNS appears to hijack NXDOMAIN. Test still passes."
                );
            }
            other => panic!("expected DnsFailed (or hijack-fallback), got {other:?}"),
        }
    });
}

/// Test 3: TCP connection refused for a closed loopback port.
///
/// `127.0.0.1:1` is reliably closed on Linux/macOS — the kernel sends RST.
/// On Windows, GitHub Actions `windows-latest` drops inbound SYNs to closed
/// ephemeral loopback ports, so the result is `TcpTimeout`, not `TcpRefused`.
/// Both are correct outcomes for "this port is closed"; accept either on
/// Windows. (Per the project's "fail loudly" rule: this is a documented
/// platform difference, not a silent skip — both branches assert something
/// concrete.)
#[skuld::test]
fn run_test_returns_tcp_refused_for_closed_port() {
    rt().block_on(async {
        let entry = entry("127.0.0.1", 1, TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = preflight_only_config();
        let outcome = run_server_test(&entry, &cfg).await;
        if cfg!(target_os = "windows") {
            assert!(
                matches!(outcome, ServerTestOutcome::TcpRefused | ServerTestOutcome::TcpTimeout),
                "expected TcpRefused or TcpTimeout on Windows, got {outcome:?}"
            );
        } else {
            assert!(
                matches!(outcome, ServerTestOutcome::TcpRefused),
                "expected TcpRefused, got {outcome:?}"
            );
        }
    });
}

/// Test 5: tunnel handshake failed for wrong password.
///
/// Server is started with [`TEST_PASSWORD`]; runner is called with a
/// different password. The server's AEAD decrypt fails on the address frame,
/// it closes the stream, and the runner observes EOF on its first read →
/// [`ServerTestOutcome::TunnelHandshakeFailed`].
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_tunnel_handshake_failed_for_wrong_password() {
    rt().block_on(async {
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            "definitely-not-the-right-password",
        );
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            matches!(outcome, ServerTestOutcome::TunnelHandshakeFailed),
            "expected TunnelHandshakeFailed, got {outcome:?}"
        );
    });
}

/// Test 6: tunnel handshake failed for wrong cipher.
///
/// Server is started with `aes-256-gcm`; runner uses `chacha20-ietf-poly1305`.
/// Same observable behavior as test 5 — the AEAD frame fails to decrypt and
/// the server closes the stream.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_tunnel_handshake_failed_for_wrong_cipher() {
    rt().block_on(async {
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            "chacha20-ietf-poly1305",
            TEST_PASSWORD,
        );
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            matches!(outcome, ServerTestOutcome::TunnelHandshakeFailed),
            "expected TunnelHandshakeFailed, got {outcome:?}"
        );
    });
}

/// Test 7: sentinel mismatch — bytes flow back, but they don't start with
/// `"HTTP"`. The test must encode the first ~5 bytes as hex and report
/// [`ServerTestOutcome::SentinelMismatch`].
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_sentinel_mismatch_for_garbage_response() {
    rt().block_on(async {
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        // Six all-zero bytes — definitely not "HTTP".
        let (sentinel_a, _sa) = start_fake_sentinel(vec![0u8, 0, 0, 0, 0, 0]).await;
        let (sentinel_b, _sb) = start_fake_sentinel(vec![0u8, 0, 0, 0, 0, 0]).await;

        let entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            TEST_PASSWORD,
        );
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::SentinelMismatch { detail } => {
                assert!(
                    detail.starts_with("000000"),
                    "detail should hex-encode the bytes, got {detail:?}"
                );
            }
            other => panic!("expected SentinelMismatch, got {other:?}"),
        }
    });
}

/// Test 8: server cannot reach internet — handshake succeeds but the
/// upstream sentinel closes the connection immediately (simulating an
/// upstream that cannot service the request).
///
/// The SS server decrypts our address frame successfully, connects to the
/// fake sentinel, forwards the HEAD request, receives EOF on its upstream
/// half, and closes the tunnel side. The runner observes EOF on its first
/// read → [`ServerTestOutcome::ServerCannotReachInternet`].
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_server_cannot_reach_internet_when_sentinels_close_empty() {
    rt().block_on(async {
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        // Empty response — fake sentinel reads our HEAD, writes nothing,
        // closes its socket. This is the cleanest simulation of "upstream
        // accepted connection but had nothing to say".
        let (sentinel_a, _sa) = start_fake_sentinel(vec![]).await;
        let (sentinel_b, _sb) = start_fake_sentinel(vec![]).await;

        let entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            TEST_PASSWORD,
        );
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            matches!(outcome, ServerTestOutcome::ServerCannotReachInternet),
            "expected ServerCannotReachInternet, got {outcome:?}"
        );
    });
}

/// Test 9: plugin start failure for a non-existent plugin binary.
///
/// The runner asks for a plugin called `plugin-that-does-not-exist`, which
/// is not on PATH and not next to any plugin directory. `Plugin::start`
/// returns Err immediately, surfaced as
/// [`ServerTestOutcome::PluginStartFailed`].
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_returns_plugin_start_failed_for_bad_plugin_path() {
    rt().block_on(async {
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let mut entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            TEST_PASSWORD,
        );
        entry.plugin = Some("plugin-that-does-not-exist".into());
        let cfg = fast_test_config(sentinel_a, sentinel_b);

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::PluginStartFailed { detail } => {
                assert!(!detail.is_empty(), "detail should describe the failure");
            }
            other => panic!("expected PluginStartFailed, got {other:?}"),
        }
    });
}

/// Test 11: internal error for an unsupported cipher string.
///
/// The runner is given a non-existent cipher name; `entry.method.parse()`
/// fails. The runner returns
/// [`ServerTestOutcome::InternalError`] with the literal "unsupported
/// cipher" in the detail string.
#[skuld::test]
fn run_test_returns_internal_error_for_unsupported_cipher() {
    rt().block_on(async {
        let entry = entry("127.0.0.1", 8388, "this-cipher-does-not-exist", TEST_PASSWORD);
        let cfg = preflight_only_config();
        // The runner does pre-flight first, but pre-flight to 127.0.0.1:8388
        // is irrelevant — what matters is the cipher parse error happens
        // before sentinel phase. We need a host that DOES preflight-pass so
        // we exercise the cipher parse code. Use a real listener for that.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let preflight_addr = listener.local_addr().unwrap();
        // Hold the listener — drop at end of scope cleans up.
        let mut entry_with_real_addr = entry;
        entry_with_real_addr.server = preflight_addr.ip().to_string();
        entry_with_real_addr.server_port = preflight_addr.port();

        let outcome = run_server_test(&entry_with_real_addr, &cfg).await;
        drop(listener);
        match outcome {
            ServerTestOutcome::InternalError { detail } => {
                assert!(
                    detail.contains("unsupported cipher"),
                    "detail should mention unsupported cipher, got: {detail}"
                );
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    });
}

/// Test 10: end-to-end happy path through v2ray-plugin (websocket, no TLS).
///
/// Spins up a real shadowsocks server with a server-mode ex-ray (the binary
/// the friendly `v2ray-plugin` wire name resolves to, #414) in front, then
/// runs the test runner with `entry.plugin = "v2ray-plugin"`. The runner
/// spawns its own client-mode ex-ray via [`Plugin::start`], which talks WS
/// to the server-mode instance, which forwards to the SS server, which
/// forwards to the fake sentinel. End-to-end success →
/// [`ServerTestOutcome::Reachable`].
///
/// **Skip-on-missing rule**: if the ex-ray binary is not built, the test
/// panics with a clear instruction. Per CLAUDE.md: fail loudly, never
/// silently skip on missing dependencies.
///
/// `labels = [PORT_ALLOC]` + `serial = PORT_ALLOC`: this test has the same
/// async plugin-bind TOCTOU as the `ssserver_ws/ws_tls/quic` fixtures, but
/// doesn't use the fixture (spawns inline). Both the label and the filter
/// are needed for mutual exclusion with fixture-backed plugin tests — see
/// skuld coordination's `can_start` check.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_with_v2ray_plugin_happy_path() {
    let plugin_path = locate_ex_ray();
    if !plugin_path.is_file() {
        panic!("ex-ray not built at {plugin_path:?} — run 'cargo xtask ex-ray' before 'cargo test'");
    }

    rt().block_on(async {
        let (svr_addr, _svr) =
            start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, plugin_path.to_str().unwrap()).await;
        // The SS server's plugin is spawned async; wait for it to bind the
        // public port before letting the runner attempt preflight.
        wait_for_port(svr_addr, Duration::from_secs(7)).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let mut entry = entry(
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD_STR,
            TEST_PASSWORD,
        );
        entry.plugin = Some("v2ray-plugin".into());

        // Generous plugin window for cold start. fast_test_config's 800 ms
        // SS/sentinel timeouts are too short for the WS handshake.
        let cfg = TestConfig {
            plugin_path_override: Some(plugin_path.to_str().unwrap().to_string()),
            // Generous SS connect/sentinel timeouts because the WS handshake
            // adds latency on top of the raw TCP connect.
            ss_connect_timeout: Duration::from_secs(5),
            sentinel_read_timeout: Duration::from_secs(5),
            ..fast_test_config(sentinel_a, sentinel_b)
        };

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::Reachable { latency_ms } => {
                assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1");
            }
            other => panic!("expected Reachable, got {other:?}"),
        }
    });
}

/// Test 4: TCP connection timeout for an unroutable address.
///
/// `192.0.2.1` is in TEST-NET-1 (RFC 5737), guaranteed unroutable on the
/// public internet. The pre-flight TCP connect must time out within
/// `preflight_timeout` (500 ms here).
#[skuld::test]
fn run_test_returns_tcp_timeout_for_blackhole() {
    rt().block_on(async {
        let entry = entry("192.0.2.1", 80, TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = preflight_only_config();
        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            matches!(outcome, ServerTestOutcome::TcpTimeout),
            "expected TcpTimeout, got {outcome:?}"
        );
    });
}
/// Drives the full `run_server_test` resolve→preflight path through the DoH
/// querier seam. `entry.server` is a NON-literal host that only the stub can
/// resolve (to loopback). A live loopback listener on `entry.server_port` makes
/// preflight's TCP connect succeed — but ONLY if `run_server_test` connects to
/// the DoH-resolved IP. If the wiring regressed to the unresolved hostname,
/// preflight's `lookup_host("preflight.example")` would fail → `DnsFailed`, so
/// any non-`DnsFailed`/non-`Tcp*` outcome proves the resolved IP was used.
#[skuld::test]
fn preflight_path_uses_doh_resolved_ip() {
    use crate::dns::bootstrap::DohQuerier;
    use hole_common::config::{DnsConfig, DnsProtocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    // Resolves any A query to loopback so preflight connects to the live
    // listener; the stub keys on hostname (the production resolver prefers A).
    struct LoopbackQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for LoopbackQuerier {
        async fn query(&self, _s: IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
            use hickory_proto::op::{Message, MessageType, OpCode, Query};
            use hickory_proto::rr::rdata::A;
            use hickory_proto::rr::{Name, RData, Record, RecordType};
            let q = Message::from_vec(wire).ok()?;
            if q.queries.first()?.query_type() != RecordType::A {
                return None;
            }
            let n = Name::from_ascii("preflight.example.").ok()?;
            let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
            reply.add_query(Query::query(n.clone(), RecordType::A));
            reply.add_answer(Record::from_rdata(n, 60, RData::A(A(Ipv4Addr::LOCALHOST))));
            reply.to_vec().ok()
        }
    }

    rt().block_on(async {
        // Live loopback listener so the post-preflight TCP connect succeeds.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let entry = entry("preflight.example", port, TEST_METHOD_STR, TEST_PASSWORD);
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cfg = TestConfig {
            preflight_timeout: Duration::from_millis(500),
            ss_connect_timeout: Duration::from_millis(500),
            sentinel_read_timeout: Duration::from_millis(500),
            sentinels: [bogus.to_string(), bogus.to_string()],
            plugin_path_override: None,
            dns: DnsConfig {
                enabled: true,
                servers: vec!["1.1.1.1".parse().unwrap()],
                protocol: DnsProtocol::Https,
                allow_insecure_bootstrap: false,
            },
            bootstrap_querier: Some(Arc::new(LoopbackQuerier)),
        };

        let outcome = run_server_test(&entry, &cfg).await;
        // Preflight reached + passed the DoH-resolved loopback IP; the listener
        // is not a real ss-server, so Phase 3 fails — but NOT at DNS or preflight.
        assert!(
            !matches!(
                outcome,
                ServerTestOutcome::DnsFailed | ServerTestOutcome::TcpRefused | ServerTestOutcome::TcpTimeout
            ),
            "preflight must have connected to the DoH-resolved IP, got {outcome:?}"
        );
    });
}

// `reclassify_blocked` tests ==========================================================================================
//
// These exercise the post-tunnel-failure reclassification helper DIRECTLY: it
// runs only the out-of-band reachability probe (no plugin / SS server), so the
// fixtures are two tiny loopback listeners. The probe upgrades a tunnel failure
// a network block can masquerade as (`TunnelHandshakeFailed` /
// `ServerCannotReachInternet`) to `NetworkBlocked` iff the probe says `Blocked`;
// every other outcome passes through untouched.

/// Fixture: accept, then drop the socket (RST / FIN with zero app bytes) — the
/// probe reads no reply and reports `Blocked`.
async fn accept_then_reset() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s);
        }
    });
    addr
}

/// Fixture: accept, read the first-flight, write a few bytes (server
/// "answered"), then drain to EOF so the reply lands before the socket closes
/// (closing with unread bytes RSTs on Windows and discards the reply). The
/// probe sees bytes back and reports `Reachable`.
async fn accept_then_answer() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await; // wait for the first-flight
            let _ = s.write_all(b"\x15\x03\x03\x00\x02\x02\x28").await; // bytes came back
            let mut drain = [0u8; 256];
            while let Ok(n) = s.read(&mut drain).await {
                if n == 0 {
                    break; // peer closed: reply has been delivered
                }
            }
        }
    });
    addr
}

/// `TunnelHandshakeFailed` + a TLS-WS plugin + a reset endpoint → the probe
/// confirms the block, so the helper upgrades to `NetworkBlocked`.
#[skuld::test]
fn run_test_reclassify_handshake_failed_reset_is_network_blocked() {
    rt().block_on(async {
        let addr = accept_then_reset().await;
        let out = super::reclassify_blocked(
            ServerTestOutcome::TunnelHandshakeFailed,
            &addr.ip().to_string(),
            addr.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(out, ServerTestOutcome::NetworkBlocked),
            "expected NetworkBlocked, got {out:?}"
        );
    });
}

/// Drives the full `run_server_test` Phase-3 tunnel through the DoH seam for a
/// BARE-SS (no-plugin) server with a NON-literal host. The real ss-server
/// fixture is on loopback; only the stub resolves `tunnel.example` to it. A
/// `Reachable` outcome proves the bare-SS connect dialed the DoH-resolved IP —
/// if it regressed to the hostname, shadowsocks-rust would OS-resolve
/// `tunnel.example` (RFC 6761 reserved, non-resolving) and the connect would
/// fail, never reaching `Reachable`.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn bare_ss_tunnel_uses_doh_resolved_ip() {
    use crate::dns::bootstrap::DohQuerier;
    use hole_common::config::{DnsConfig, DnsProtocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    // Resolves the A query to the fixture's loopback IP (the production resolver
    // prefers A, so answering only A is sufficient).
    struct FixtureQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for FixtureQuerier {
        async fn query(&self, _s: IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
            use hickory_proto::op::{Message, MessageType, OpCode, Query};
            use hickory_proto::rr::rdata::A;
            use hickory_proto::rr::{Name, RData, Record, RecordType};
            let q = Message::from_vec(wire).ok()?;
            if q.queries.first()?.query_type() != RecordType::A {
                return None;
            }
            let n = Name::from_ascii("tunnel.example.").ok()?;
            let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
            reply.add_query(Query::query(n.clone(), RecordType::A));
            reply.add_answer(Record::from_rdata(n, 60, RData::A(A(Ipv4Addr::LOCALHOST))));
            reply.to_vec().ok()
        }
    }

    rt().block_on(async {
        let (svr_addr, _svr_handle) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        // NON-literal host: only the stub can resolve it, and only to the
        // loopback fixture. The fixture's port is the SS port we dial.
        let entry = entry("tunnel.example", svr_addr.port(), TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = TestConfig {
            dns: DnsConfig {
                enabled: true,
                servers: vec!["1.1.1.1".parse().unwrap()],
                protocol: DnsProtocol::Https,
                allow_insecure_bootstrap: false,
            },
            bootstrap_querier: Some(Arc::new(FixtureQuerier)),
            ..fast_test_config(sentinel_a, sentinel_b)
        };

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::Reachable { latency_ms } => {
                assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1");
            }
            other => panic!("bare-SS tunnel must dial the DoH-resolved IP and reach the fixture, got {other:?}"),
        }
    });
}

/// Production-default fail-closed path: `allow_insecure_bootstrap = false` with
/// a configured resolver that never answers must yield `DnsFailed` with no OS
/// resolver and no network. Mirrors
/// `proxy_manager_tests::full_start_fails_closed_when_doh_cannot_resolve`.
/// Distinct from `run_test_returns_dns_failed_for_unresolvable_host`, which
/// exercises the `allow_insecure_bootstrap = true` OS-fallback path.
#[skuld::test]
fn run_test_fails_closed_when_doh_cannot_resolve() {
    use crate::dns::bootstrap::DohQuerier;
    use hole_common::config::{DnsConfig, DnsProtocol};

    struct NeverQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for NeverQuerier {
        async fn query(&self, _s: std::net::IpAddr, _w: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    rt().block_on(async {
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let entry = entry("proxy.example", 8388, TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = TestConfig {
            dns: DnsConfig {
                enabled: true,
                servers: vec!["1.1.1.1".parse().unwrap()],
                protocol: DnsProtocol::Https,
                allow_insecure_bootstrap: false,
            },
            bootstrap_querier: Some(std::sync::Arc::new(NeverQuerier)),
            ..fast_test_config(bogus, bogus)
        };

        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            matches!(outcome, ServerTestOutcome::DnsFailed),
            "fail-closed DoH no-answer must be DnsFailed, got {outcome:?}"
        );
    });
}

/// `TunnelHandshakeFailed` + a TLS-WS plugin + an answering endpoint → the probe
/// reports `Reachable`, so the original `TunnelHandshakeFailed` is preserved.
#[skuld::test]
fn run_test_reclassify_handshake_failed_answered_stays_handshake_failed() {
    rt().block_on(async {
        let addr = accept_then_answer().await;
        let out = super::reclassify_blocked(
            ServerTestOutcome::TunnelHandshakeFailed,
            &addr.ip().to_string(),
            addr.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(out, ServerTestOutcome::TunnelHandshakeFailed),
            "expected TunnelHandshakeFailed (probe Reachable), got {out:?}"
        );
    });
}

/// Resolves any AAAA query to `::1` so preflight connects to an IPv6 loopback
/// listener; answers no A so the v6 fallback branch is exercised.
struct Ipv6LoopbackQuerier;
#[async_trait::async_trait]
impl crate::dns::bootstrap::DohQuerier for Ipv6LoopbackQuerier {
    async fn query(&self, _s: std::net::IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::AAAA;
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        let q = Message::from_vec(wire).ok()?;
        if q.queries.first()?.query_type() != RecordType::AAAA {
            return None;
        }
        let n = Name::from_ascii("v6.example.").ok()?;
        let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
        reply.add_query(Query::query(n.clone(), RecordType::AAAA));
        reply.add_answer(Record::from_rdata(
            n,
            60,
            RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST)),
        ));
        reply.to_vec().ok()
    }
}

fn ipv6_doh_config(sentinel_a: SocketAddr, sentinel_b: SocketAddr) -> TestConfig {
    use hole_common::config::{DnsConfig, DnsProtocol};
    TestConfig {
        dns: DnsConfig {
            enabled: true,
            servers: vec!["1.1.1.1".parse().unwrap()],
            protocol: DnsProtocol::Https,
            allow_insecure_bootstrap: false,
        },
        bootstrap_querier: Some(std::sync::Arc::new(Ipv6LoopbackQuerier)),
        ..fast_test_config(sentinel_a, sentinel_b)
    }
}

/// Preflight must connect to the RAW IPv6 address `::1`, not the bracketed
/// `handoff_host` string. A live `[::1]:port` listener makes the TCP connect
/// succeed; if `run_server_test` fed `"[::1]"` to preflight, `IpAddr::parse`
/// would reject the brackets and the value would be (mis)treated as a hostname
/// — `lookup_host(("[::1]", port))` fails on macOS getaddrinfo → `DnsFailed`.
/// A non-DnsFailed/non-Tcp outcome proves the raw IP was used.
#[skuld::test]
fn preflight_uses_raw_ipv6_not_bracketed_host() {
    use tokio::net::TcpListener;
    rt().block_on(async {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = entry("v6.example", port, TEST_METHOD_STR, TEST_PASSWORD);
        let cfg = ipv6_doh_config(bogus, bogus);

        let outcome = run_server_test(&entry, &cfg).await;
        assert!(
            !matches!(
                outcome,
                ServerTestOutcome::DnsFailed | ServerTestOutcome::TcpRefused | ServerTestOutcome::TcpTimeout
            ),
            "preflight must connect to the raw IPv6 ::1, got {outcome:?}"
        );
    });
}

/// `ServerCannotReachInternet` + a TLS-WS plugin + a reset endpoint → upgraded
/// to `NetworkBlocked`.
#[skuld::test]
fn run_test_reclassify_cannot_reach_reset_is_network_blocked() {
    rt().block_on(async {
        let addr = accept_then_reset().await;
        let out = super::reclassify_blocked(
            ServerTestOutcome::ServerCannotReachInternet,
            &addr.ip().to_string(),
            addr.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(out, ServerTestOutcome::NetworkBlocked),
            "expected NetworkBlocked, got {out:?}"
        );
    });
}

/// The plugin path runs the same IPv6 preflight before spawning the plugin. A
/// live `[::1]:port` listener makes preflight pass; a bogus plugin name then
/// fails at spawn → `PluginStartFailed`. Reaching plugin-start proves preflight
/// connected to the raw IPv6 IP rather than failing `DnsFailed` on the bracket.
#[skuld::test]
fn plugin_preflight_uses_raw_ipv6_not_bracketed_host() {
    use tokio::net::TcpListener;
    rt().block_on(async {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut entry = entry("v6.example", port, TEST_METHOD_STR, TEST_PASSWORD);
        entry.plugin = Some("plugin-that-does-not-exist".into());
        let cfg = ipv6_doh_config(bogus, bogus);

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::PluginStartFailed { detail } => {
                assert!(!detail.is_empty(), "detail should describe the failure");
            }
            other => panic!("plugin preflight must pass on raw IPv6 then fail at spawn, got {other:?}"),
        }
    });
}

/// A `Reachable` outcome is not one a block can masquerade as: the probe must
/// NOT run and the outcome passes through unchanged. Points at a reset endpoint
/// to prove the probe is never consulted (a probe would have said `Blocked`).
#[skuld::test]
fn run_test_reclassify_reachable_passes_through() {
    rt().block_on(async {
        let addr = accept_then_reset().await;
        let out = super::reclassify_blocked(
            ServerTestOutcome::Reachable { latency_ms: 5 },
            &addr.ip().to_string(),
            addr.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(out, ServerTestOutcome::Reachable { latency_ms: 5 }),
            "expected unchanged Reachable, got {out:?}"
        );
    });
}

/// A `PluginStartFailed` outcome passes through unchanged (probe must NOT run).
#[skuld::test]
fn run_test_reclassify_plugin_start_failed_passes_through() {
    rt().block_on(async {
        let addr = accept_then_reset().await;
        let out = super::reclassify_blocked(
            ServerTestOutcome::PluginStartFailed { detail: "x".into() },
            &addr.ip().to_string(),
            addr.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        match out {
            ServerTestOutcome::PluginStartFailed { detail } => assert_eq!(detail, "x"),
            other => panic!("expected unchanged PluginStartFailed, got {other:?}"),
        }
    });
}
