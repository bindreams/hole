//! End-to-end tests for the bridge, driven as a real subprocess spawned
//! from a staged dist directory.
//!
//! Each test:
//!
//! 1. Takes a reference to the process-scoped `dist_dir` fixture (staged
//!    once per test binary).
//! 2. Spawns a fresh `hole bridge run` subprocess via [`DistHarness::spawn`],
//!    which binds its own ephemeral IPC socket and writes route-recovery
//!    state into a per-test tempdir.
//! 3. Takes references to the process-scoped ssserver / http_target
//!    fixtures (shared across tests for speed).
//! 4. Sends `BridgeRequest::Start { config: ProxyConfig { tunnel_mode: SocksOnly, ... } }`
//!    over IPC. `SocksOnly` tells the bridge to bind its SOCKS5 listener
//!    without touching TUN, routes, or the wintun/DNS/gateway pipeline,
//!    so the subprocess does not need elevation.
//! 5. Runs a SOCKS5 HTTP round-trip through the bridge's local port to
//!    the `HttpTarget` fixture.
//! 6. Sends `BridgeRequest::Stop` and asserts the result.
//!
//! TUN tests go through the same pipeline with `tunnel_mode: Full` and are
//! `cfg(target_os = "windows")` + `labels = [TUN]` because macOS CI does
//! not run elevated and spawning an elevated child from an unelevated
//! test binary would fail on both OSes.

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::http_target::HttpTarget;
use crate::test_support::port_alloc::{allocate_ephemeral_port, wait_for_port};
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use crate::test_support::socks5_client::{http_get_request, http_response_body, socks5_request};
use crate::test_support::ssserver::random_password_for;
use hole_common::config::ServerEntry;
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use shadowsocks::crypto::CipherKind;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

// Helpers =============================================================================================================

/// Build a `ServerEntry` from a shared `SsServerHandle` fixture.
fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "e2e-test".into(),
        name: "e2e-test".into(),
        server: ss.addr.ip().to_string(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

/// Assert that a SOCKS5 GET to `target` through `proxy_port` returns the
/// `HttpTarget` sentinel body.
///
/// Sends a `Status` health check before polling the port so that a dead
/// proxy task produces a clear assertion ("proxy reports not running")
/// instead of a blind 10-second timeout on `wait_for_port`.
async fn assert_socks5_roundtrip(harness: &mut DistHarness, proxy_port: u16, target_addr: SocketAddr) {
    eprintln!("[test] pid={} polling 127.0.0.1:{proxy_port}", std::process::id());
    // Health check: if the proxy task exited between Start and now,
    // the bridge's check_health() will notice and report running=false.
    let status = harness.send(BridgeRequest::Status).await.expect("send Status");
    match &status {
        BridgeResponse::Status { running, error, .. } => {
            assert!(
                *running,
                "proxy reports not running before SOCKS5 roundtrip (error: {error:?})"
            );
        }
        other => panic!("expected Status response, got {other:?}"),
    }

    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    // The bridge has already returned Ack from Start, but the SOCKS5
    // listener may not have reached `accept()` yet. Poll until it does.
    wait_for_port(proxy_addr, Duration::from_secs(10)).await;

    let request = http_get_request(&target_addr, "/");
    let response = socks5_request(proxy_addr, target_addr, &request, 8192)
        .await
        .expect("SOCKS5 request through bridge");

    let body = http_response_body(&response).expect("HTTP response has header terminator");
    assert_eq!(
        body,
        crate::test_support::http_target::SENTINEL_BODY,
        "expected sentinel body, got {response:?}"
    );
}

/// Full template: start a bridge subprocess, send Start with the given
/// `ProxyConfig`, do a SOCKS5 round-trip, send Stop, assert Ack.
async fn run_socks_only_e2e(dist: &Path, ss: &SsServerHandle, http: &HttpTarget) {
    let local_port = allocate_ephemeral_port().await;
    let config = ProxyConfig {
        server: entry_from(ss),
        local_port,
        tunnel_mode: TunnelMode::SocksOnly,
        filters: vec![],
        dns: hole_common::config::DnsConfig::default(),
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
    };

    let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
    let resp = harness.send(BridgeRequest::Start { config }).await.expect("send Start");
    assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");

    assert_socks5_roundtrip(&mut harness, local_port, http.addr).await;

    let resp = harness.send(BridgeRequest::Stop).await.expect("send Stop");
    assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");
}

// Core flow matrix ====================================================================================================

/// Test 1: SocksOnly mode, no plugin. Baseline — proves the dist harness +
/// SocksOnly config path work end-to-end.
#[skuld::test(labels = [DIST_BIN])]
fn e2e_none_socks_only_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(run_socks_only_e2e(dist, ss, http));
}

/// Test 2: SocksOnly mode with galoshes (websocket, no TLS).
///
/// Skipped on Windows (and macOS via the module gate) because the
/// `PluginConfig` port TOCTOU in `shadowsocks-service` — tracked in
/// #197 — causes yamux-server inside galoshes to lose the bind race.
#[cfg(not(target_os = "windows"))]
#[skuld::test(labels = [DIST_BIN, PORT_ALLOC])]
fn e2e_ws_socks_only_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_ws)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(run_socks_only_e2e(dist, ss, http));
}

/// Test 3: SocksOnly mode with galoshes (websocket + TLS).
///
/// Windows-skipped: same #197 bind race as `e2e_ws_socks_only_roundtrip`.
#[cfg(not(target_os = "windows"))]
#[skuld::test(labels = [DIST_BIN, PORT_ALLOC])]
fn e2e_ws_tls_socks_only_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_ws_tls)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(run_socks_only_e2e(dist, ss, http));
}

/// Test 4: SocksOnly mode with galoshes (QUIC).
///
/// Windows-skipped: same #197 bind race as `e2e_ws_socks_only_roundtrip`.
#[cfg(not(target_os = "windows"))]
#[skuld::test(labels = [DIST_BIN, PORT_ALLOC])]
fn e2e_quic_socks_only_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_quic)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(run_socks_only_e2e(dist, ss, http));
}

// TUN matrix (Windows admin only) =====================================================================================

#[cfg(target_os = "windows")]
mod tun {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// TUN tests exercise the bridge's transparent-proxy path: the test
    /// connects directly to the HTTP target's primary non-loopback IPv4
    /// address, and the TUN routes catch that traffic and tunnel it
    /// through the shadowsocks server.
    ///
    /// **Critically**: TUN tests must NOT try to connect to anything on
    /// `127.0.0.1` while the bridge is running, because the bridge
    /// installs a `route add 127.0.0.1 mask 255.255.255.255 <tun-gw>`
    /// bypass route (so its own shadowsocks connection to a
    /// loopback-bound test server can escape the TUN). That bypass
    /// globally redirects all loopback traffic through the TUN
    /// adapter, which has no SOCKS5 server on the other side — so any
    /// attempt to connect to `127.0.0.1:<port>` from the test body
    /// times out.
    async fn direct_http_get(target_addr: SocketAddr) -> Vec<u8> {
        let mut sock = tokio::net::TcpStream::connect(target_addr)
            .await
            .expect("direct TCP connect to http_target");
        let request = http_get_request(&target_addr, "/");
        sock.write_all(&request).await.expect("write HTTP request");
        let mut response = Vec::new();
        sock.read_to_end(&mut response).await.expect("read HTTP response");
        response
    }

    async fn run_full_tunnel_e2e(dist: &Path, ss: &SsServerHandle, http: &HttpTarget) {
        let local_port = allocate_ephemeral_port().await;
        let config = ProxyConfig {
            server: entry_from(ss),
            local_port,
            tunnel_mode: TunnelMode::Full,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        let resp = harness.send(BridgeRequest::Start { config }).await.expect("send Start");
        assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");

        // Direct TCP to `http.addr` (the primary non-loopback IPv4) —
        // traffic caught by the TUN split routes, tunneled through
        // shadowsocks, and delivered to the HTTP target. This
        // exercises the transparent-proxy path.
        let response = direct_http_get(http.addr).await;
        let body = http_response_body(&response).expect("HTTP response has header terminator");
        assert_eq!(
            body,
            crate::test_support::http_target::SENTINEL_BODY,
            "expected sentinel body, got {response:?}"
        );

        let resp = harness.send(BridgeRequest::Stop).await.expect("send Stop");
        assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");
    }

    /// Test 5: Full mode (TUN + routing), no plugin. Requires Windows
    /// admin. TUN tests are serial because they all bind the hardcoded
    /// `hole-tun` device name.
    #[skuld::test(labels = [DIST_BIN, TUN], serial = TUN)]
    fn e2e_none_full_tunnel_roundtrip(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_none)] ss: &SsServerHandle,
        #[fixture(http_target_ipv4)] http: &HttpTarget,
    ) {
        rt().block_on(run_full_tunnel_e2e(dist, ss, http));
    }

    /// Test 6: Full mode with galoshes (websocket). Requires Windows
    /// admin.
    ///
    /// Currently disabled even on Windows because the galoshes
    /// `PluginConfig` bind race (#197) fires here too. The `mod tun`
    /// guard above is `cfg(target_os = "windows")`, so an additional
    /// `cfg(not(target_os = "windows"))` here resolves to always-false
    /// — the test is effectively never compiled until #197 is fixed.
    /// Keeping the function as a placeholder so the test-matrix docs
    /// stay intact; re-enable by removing this cfg once #197 lands.
    #[cfg(not(target_os = "windows"))]
    #[skuld::test(labels = [DIST_BIN, PORT_ALLOC, TUN], serial = TUN)]
    fn e2e_ws_full_tunnel_roundtrip(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_ws)] ss: &SsServerHandle,
        #[fixture(http_target_ipv4)] http: &HttpTarget,
    ) {
        rt().block_on(run_full_tunnel_e2e(dist, ss, http));
    }
}

// Lifecycle matrix ====================================================================================================

/// Test 7: starting twice without stopping returns an error from the
/// second start. The dist harness exposes the error payload via
/// `BridgeResponse::Error`.
#[skuld::test(labels = [DIST_BIN])]
fn lifecycle_start_twice_returns_error(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(async {
        let local_port = allocate_ephemeral_port().await;
        let config = ProxyConfig {
            server: entry_from(ss),
            local_port,
            tunnel_mode: TunnelMode::SocksOnly,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.unwrap();
        let resp1 = harness
            .send(BridgeRequest::Start { config: config.clone() })
            .await
            .unwrap();
        assert!(matches!(resp1, BridgeResponse::Ack));

        let resp2 = harness.send(BridgeRequest::Start { config }).await.unwrap();
        // The second start should return an Error response (the bridge
        // maps the ProxyError::AlreadyRunning into a 5xx).
        assert!(
            matches!(resp2, BridgeResponse::Error { .. }),
            "expected Error on second start, got {resp2:?}"
        );

        harness.send(BridgeRequest::Stop).await.unwrap();
    });
}

/// Test 8: stopping a bridge that never started is a clean noop. The
/// handle subprocess goes straight from its initial Stopped state through
/// another Stopped, returning Ack.
#[skuld::test(labels = [DIST_BIN])]
fn lifecycle_stop_when_idle_is_noop(#[fixture(dist_dir)] dist: &Path) {
    rt().block_on(async {
        let mut harness = DistHarness::spawn(dist).await.unwrap();
        let resp = harness.send(BridgeRequest::Stop).await.unwrap();
        assert!(
            matches!(resp, BridgeResponse::Ack),
            "Stop on idle bridge should Ack, got {resp:?}"
        );
    });
}

/// Test 9: reload swaps the proxy config. The new local_port must bind
/// after reload; the subprocess keeps running throughout.
#[skuld::test(labels = [DIST_BIN])]
fn lifecycle_reload_changes_local_port(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let port1 = allocate_ephemeral_port().await;
        let config1 = ProxyConfig {
            server: entry_from(ss),
            local_port: port1,
            tunnel_mode: TunnelMode::SocksOnly,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.unwrap();
        harness
            .send(BridgeRequest::Start {
                config: config1.clone(),
            })
            .await
            .unwrap();
        assert_socks5_roundtrip(&mut harness, port1, http.addr).await;

        let port2 = allocate_ephemeral_port().await;
        assert_ne!(port1, port2, "ephemeral allocator should give a fresh port");
        let config2 = ProxyConfig {
            local_port: port2,
            ..config1
        };
        let resp = harness.send(BridgeRequest::Reload { config: config2 }).await.unwrap();
        assert!(matches!(resp, BridgeResponse::Ack), "reload should Ack, got {resp:?}");
        assert_socks5_roundtrip(&mut harness, port2, http.addr).await;

        harness.send(BridgeRequest::Stop).await.unwrap();
    });
}

/// Test 10: SocksOnly mode does not write `bridge-routes.json`. The file
/// should not exist after Start because the state-file write path is
/// explicitly skipped for SocksOnly.
#[skuld::test(labels = [DIST_BIN])]
fn lifecycle_state_file_absent_in_socks_only_mode(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(async {
        let local_port = allocate_ephemeral_port().await;
        let config = ProxyConfig {
            server: entry_from(ss),
            local_port,
            tunnel_mode: TunnelMode::SocksOnly,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.unwrap();
        let state_file = harness.state_dir.path().join("bridge-routes.json");
        harness.send(BridgeRequest::Start { config }).await.unwrap();

        assert!(
            !state_file.exists(),
            "bridge-routes.json should be absent in SocksOnly mode, found at {state_file:?}"
        );

        harness.send(BridgeRequest::Stop).await.unwrap();
    });
}

// Cipher matrix =======================================================================================================

/// Test 11: chacha20-ietf-poly1305 cipher round-trips through a dist-backed
/// SocksOnly bridge. Uses a one-shot real ss-server spawned in-test because
/// the process-scoped `ssserver_*` fixtures are pinned to `aes-256-gcm`.
///
#[skuld::test(labels = [DIST_BIN])]
fn cipher_chacha20_ietf_poly1305_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let method = CipherKind::CHACHA20_POLY1305;
        let password = random_password_for(method);
        let (ss_addr, _ss_handle) = crate::test_support::ssserver::start_real_ss_server(method, &password).await;

        let local_port = allocate_ephemeral_port().await;
        let config = ProxyConfig {
            server: ServerEntry {
                id: "cipher-test".into(),
                name: "cipher-test".into(),
                server: ss_addr.ip().to_string(),
                server_port: ss_addr.port(),
                method: "chacha20-ietf-poly1305".into(),
                password,
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port,
            tunnel_mode: TunnelMode::SocksOnly,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.unwrap();
        harness.send(BridgeRequest::Start { config }).await.unwrap();
        assert_socks5_roundtrip(&mut harness, local_port, http.addr).await;
        harness.send(BridgeRequest::Stop).await.unwrap();
    });
}

/// Test 12: 2022-blake3-aes-256-gcm cipher round-trip. Enabled via the
/// `aead-cipher-2022` feature on `shadowsocks-service`.
///
#[skuld::test(labels = [DIST_BIN])]
fn cipher_2022_blake3_aes_256_gcm_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let method = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;
        let password = random_password_for(method);
        let (ss_addr, _ss_handle) = crate::test_support::ssserver::start_real_ss_server(method, &password).await;

        let local_port = allocate_ephemeral_port().await;
        let config = ProxyConfig {
            server: ServerEntry {
                id: "cipher-test".into(),
                name: "cipher-test".into(),
                server: ss_addr.ip().to_string(),
                server_port: ss_addr.port(),
                method: "2022-blake3-aes-256-gcm".into(),
                password,
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port,
            tunnel_mode: TunnelMode::SocksOnly,
            filters: vec![],
            dns: hole_common::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        };

        let mut harness = DistHarness::spawn(dist).await.unwrap();
        harness.send(BridgeRequest::Start { config }).await.unwrap();
        assert_socks5_roundtrip(&mut harness, local_port, http.addr).await;
        harness.send(BridgeRequest::Stop).await.unwrap();
    });
}

// IPv6 axis ===========================================================================================================

/// Test 13: ws plugin, SocksOnly mode, IPv6 HTTP target on `[::1]`.
///
/// Windows-skipped: same #197 galoshes bind race.
#[cfg(not(target_os = "windows"))]
#[skuld::test(labels = [DIST_BIN, PORT_ALLOC, IPV6], serial = IPV6)]
fn ipv6_ws_socks_only_roundtrip(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_ws)] ss: &SsServerHandle,
    #[fixture(http_target_ipv6)] http: &HttpTarget,
) {
    rt().block_on(run_socks_only_e2e(dist, ss, http));
}
