//! Tests for [`server_test::run_server_test`].
//!
//! Each test stands up a real shadowsocks server fixture (via `shadowsocks-service`
//! with the `server` feature, dev-dep) bound to `127.0.0.1:0`, plus a tiny tokio
//! TCP "fake sentinel" listener. The test runner is then pointed at the fixture
//! and asserted against.
//!
//! The server/sentinel/port helpers live in the crate-wide `test_support`
//! module so `proxy_manager_e2e_tests.rs` can reuse them.

use super::{run_server_test, TestConfig};
use crate::test_support::http_target::start_fake_sentinel;
use crate::test_support::port_alloc::{allocate_ephemeral_port, wait_for_port};
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::PORT_ALLOC;
use crate::test_support::ssserver::{
    locate_built_v2ray_plugin, start_real_ss_server, start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_METHOD_STR,
    TEST_PASSWORD,
};
use hole_common::config::ServerEntry;
use hole_common::protocol::ServerTestOutcome;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

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
/// Reverted to pre-#165 values in PR-A (#169). The #165 bug was that
/// every test that went through `ProxyManager::start/stop` shelled out
/// to real `netsh`/`route` via a RouteGuard that bypassed the backend
/// trait, corrupting loopback state over time. Now that the refactor
/// eliminates the bypass, tests no longer touch the routing table, so
/// the original tight timeouts hold. If CI fails after this revert,
/// investigate root cause — do NOT bump the values back.
fn fast_test_config(sentinel_a: SocketAddr, sentinel_b: SocketAddr) -> TestConfig {
    TestConfig {
        preflight_timeout: Duration::from_millis(500),
        ss_connect_timeout: Duration::from_millis(800),
        sentinel_read_timeout: Duration::from_millis(800),
        sentinels: [sentinel_a.to_string(), sentinel_b.to_string()],
        plugin_path_override: None,
    }
}

// Tests ===============================================================================================================

/// Sanity test for the [`start_real_ss_server`] fixture: bind it, accept one
/// raw TCP connect (no shadowsocks handshake), and verify both addresses are
/// loopback. This guards against fixture-API drift in `shadowsocks-service`
/// — if it stops compiling, every other test in this file fails too.
#[skuld::test]
fn fixture_starts_real_ss_server() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr_handle) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
fn preflight_only_config() -> TestConfig {
    let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
    TestConfig {
        preflight_timeout: Duration::from_millis(500),
        ss_connect_timeout: Duration::from_millis(500),
        sentinel_read_timeout: Duration::from_millis(500),
        sentinels: [bogus.to_string(), bogus.to_string()],
        plugin_path_override: None,
    }
}

/// Test 1: happy path. Real server, valid credentials, fake sentinel that
/// returns a HTTP-prefixed response. Should produce
/// [`ServerTestOutcome::Reachable`] with `latency_ms >= 1`.
#[skuld::test]
fn run_test_returns_reachable_for_valid_credentials() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr_handle) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
#[skuld::test]
fn run_test_returns_tunnel_handshake_failed_for_wrong_password() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
#[skuld::test]
fn run_test_returns_tunnel_handshake_failed_for_wrong_cipher() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
#[skuld::test]
fn run_test_returns_sentinel_mismatch_for_garbage_response() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
#[skuld::test]
fn run_test_returns_server_cannot_reach_internet_when_sentinels_close_empty() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
#[skuld::test]
fn run_test_returns_plugin_start_failed_for_bad_plugin_path() {
    rt().block_on(async {
        let port = crate::test_support::port_alloc::allocate_ephemeral_port().await;
        let (svr_addr, _svr) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD, port).await;
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
/// Spins up a real shadowsocks server with a server-mode v2ray-plugin in
/// front, then runs the test runner with `entry.plugin = "v2ray-plugin"`.
/// The runner spawns its own client-mode v2ray-plugin via [`Plugin::start`],
/// which talks WS to the server-mode instance, which forwards to the SS
/// server, which forwards to the fake sentinel. End-to-end success →
/// [`ServerTestOutcome::Reachable`].
///
/// **Skip-on-missing rule**: if the v2ray-plugin binary is not built, the
/// test panics with a clear instruction. Per CLAUDE.md: fail loudly, never
/// silently skip on missing dependencies.
///
/// `labels = [PORT_ALLOC]` + `serial = PORT_ALLOC`: this test has the same
/// async plugin-bind TOCTOU as the `ssserver_ws/ws_tls/quic` fixtures, but
/// doesn't use the fixture (spawns inline). Both the label and the filter
/// are needed for mutual exclusion with fixture-backed plugin tests — see
/// skuld coordination's `can_start` check.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn run_test_with_v2ray_plugin_happy_path() {
    let plugin_path = locate_built_v2ray_plugin();
    if !plugin_path.is_file() {
        panic!(
            "v2ray-plugin not built at {plugin_path:?} — \
             run 'cargo build --workspace' before 'cargo test'"
        );
    }

    rt().block_on(async {
        let public_port = allocate_ephemeral_port().await;
        let (svr_addr, _svr) =
            start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, public_port, plugin_path.to_str().unwrap())
                .await;
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

        // Generous plugin window for cold start. The CI default of 2 s in
        // fast_test_config is too short for the WS handshake.
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
