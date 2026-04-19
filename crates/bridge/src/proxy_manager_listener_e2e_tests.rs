//! End-to-end tests for the listener-selection knobs (`proxy_socks5`,
//! `proxy_http`, `local_port_http`). Complements
//! `proxy_manager_e2e_tests.rs`, which covers the pre-existing SOCKS5-only
//! path.
//!
//! Each test spawns a real `hole bridge run` subprocess via
//! [`DistHarness::spawn`] and exercises `BridgeRequest::Start` with a
//! listener combination, then asserts what binds on each port.
//!
//! * TCP tests use `TunnelMode::SocksOnly` (no elevation required).
//! * The UDP ASSOCIATE test uses `TunnelMode::Full` and is Windows-admin
//!   only, mirroring the existing `mod tun` pattern in
//!   `proxy_manager_e2e_tests.rs`. `windows-latest` GitHub Actions runs
//!   as `RUNNERADMIN` so CI does exercise it.

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::http_connect_client::http_connect_request;
use crate::test_support::http_target::HttpTarget;
use crate::test_support::port_alloc::{allocate_ephemeral_port, wait_for_port};
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use crate::test_support::socks5_client::{http_get_request, http_response_body, socks5_request};
use hole_common::config::ServerEntry;
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, TunnelMode};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

// Helpers =============================================================================================================

fn entry_from(ss: &SsServerHandle) -> ServerEntry {
    ServerEntry {
        id: "listener-e2e".into(),
        name: "listener-e2e".into(),
        server: ss.addr.ip().to_string(),
        server_port: ss.addr.port(),
        method: ss.method.into(),
        password: ss.password.clone(),
        plugin: ss.plugin.clone(),
        plugin_opts: ss.plugin_opts.clone(),
        validation: None,
    }
}

fn base_config(ss: &SsServerHandle, local_port: u16, local_port_http: u16) -> ProxyConfig {
    ProxyConfig {
        server: entry_from(ss),
        local_port,
        tunnel_mode: TunnelMode::SocksOnly,
        filters: vec![],
        proxy_socks5: true,
        proxy_http: false,
        local_port_http,
    }
}

/// Send `Start` and expect `Ack`. Panics on any other response or IPC error.
async fn start_expect_ack(harness: &mut DistHarness, config: ProxyConfig) {
    let resp = harness.send(BridgeRequest::Start { config }).await.expect("send Start");
    assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");
}

/// Send `Start` and expect `BridgeResponse::Error`. Returns the error message.
async fn start_expect_error(harness: &mut DistHarness, config: ProxyConfig) -> String {
    let resp = harness.send(BridgeRequest::Start { config }).await.expect("send Start");
    match resp {
        BridgeResponse::Error { message } => message,
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Assert that nothing is listening on `addr` — either by observing a
/// refused connect or, on Windows where the firewall can silently drop
/// SYNs to unbound ports, by successfully binding the port ourselves
/// (proving nothing else already holds it).
async fn assert_port_unbound(addr: SocketAddr) {
    let connect = tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await;
    match connect {
        Ok(Ok(_stream)) => panic!("expected {addr} unbound; connection succeeded"),
        Ok(Err(e)) => {
            let kind = e.kind();
            assert!(
                matches!(
                    kind,
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                ),
                "expected {addr} unbound; got io error kind {kind:?}: {e}"
            );
        }
        Err(_) => {
            // Windows Firewall stealth-drops SYNs to unbound localhost
            // ports in some configurations (#200's cousin). Fall back to
            // a positive check: if we can bind the port, it's free.
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => drop(listener),
                Err(e) => panic!(
                    "expected {addr} unbound; connect timed out and bind failed with {e} — \
                     something is holding the port"
                ),
            }
        }
    }
}

async fn roundtrip_socks5(proxy: SocketAddr, target: SocketAddr) {
    wait_for_port(proxy, Duration::from_secs(10)).await;
    let request = http_get_request(&target, "/");
    let response = socks5_request(proxy, target, &request, 8192)
        .await
        .expect("socks5 roundtrip");
    let body = http_response_body(&response).expect("response has header terminator");
    assert_eq!(body, crate::test_support::http_target::SENTINEL_BODY);
}

async fn roundtrip_http_connect(proxy: SocketAddr, target: SocketAddr) {
    wait_for_port(proxy, Duration::from_secs(10)).await;
    let request = http_get_request(&target, "/");
    let response = http_connect_request(proxy, &target.to_string(), &request, 8192)
        .await
        .expect("HTTP CONNECT roundtrip");
    let body = http_response_body(&response).expect("response has header terminator");
    assert_eq!(body, crate::test_support::http_target::SENTINEL_BODY);
}

// TCP listener selection ==============================================================================================

#[skuld::test(labels = [DIST_BIN])]
fn e2e_socks5_only_http_port_unbound(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port().await;
        let http_port = allocate_ephemeral_port().await;
        let config = base_config(ss, socks_port, http_port);

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        start_expect_ack(&mut harness, config).await;

        let socks_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
        let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

        roundtrip_socks5(socks_addr, http.addr).await;
        assert_port_unbound(http_addr).await;

        harness.send(BridgeRequest::Stop).await.expect("send Stop");
    });
}

#[skuld::test(labels = [DIST_BIN])]
fn e2e_http_only_socks_port_unbound(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port().await;
        let http_port = allocate_ephemeral_port().await;
        let mut config = base_config(ss, socks_port, http_port);
        config.proxy_socks5 = false;
        config.proxy_http = true;

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        start_expect_ack(&mut harness, config).await;

        let socks_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
        let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

        roundtrip_http_connect(http_addr, http.addr).await;
        assert_port_unbound(socks_addr).await;

        harness.send(BridgeRequest::Stop).await.expect("send Stop");
    });
}

#[skuld::test(labels = [DIST_BIN])]
fn e2e_both_listeners_bound(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port().await;
        let http_port = allocate_ephemeral_port().await;
        let mut config = base_config(ss, socks_port, http_port);
        config.proxy_http = true;

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        start_expect_ack(&mut harness, config).await;

        let socks_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
        let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

        roundtrip_socks5(socks_addr, http.addr).await;
        roundtrip_http_connect(http_addr, http.addr).await;

        harness.send(BridgeRequest::Stop).await.expect("send Stop");
    });
}

// Reload hot-path =====================================================================================================

/// Regression guard for the structural-same check in `ProxyManager::reload`.
/// Before #242 the reload fast path compared only `server`, `local_port`,
/// `tunnel_mode`. Toggling `proxy_http` alone would therefore hit the
/// fast path and silently leave the HTTP listener unbound.
#[skuld::test(labels = [DIST_BIN])]
fn e2e_reload_toggling_http_listener_rebinds(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port().await;
        let http_port = allocate_ephemeral_port().await;
        let config = base_config(ss, socks_port, http_port);

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        start_expect_ack(&mut harness, config.clone()).await;

        let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();
        assert_port_unbound(http_addr).await;

        // Flip HTTP on, keep every other structural field identical so
        // the pre-#242 check would have short-circuited.
        let mut reloaded = config;
        reloaded.proxy_http = true;
        let resp = harness
            .send(BridgeRequest::Reload { config: reloaded })
            .await
            .expect("send Reload");
        assert!(matches!(resp, BridgeResponse::Ack), "reload should Ack, got {resp:?}");

        roundtrip_http_connect(http_addr, http.addr).await;

        harness.send(BridgeRequest::Stop).await.expect("send Stop");
    });
}

// Validation errors ===================================================================================================

#[skuld::test(labels = [DIST_BIN])]
fn e2e_start_rejects_no_listeners(#[fixture(dist_dir)] dist: &Path, #[fixture(ssserver_none)] ss: &SsServerHandle) {
    rt().block_on(async {
        let port = allocate_ephemeral_port().await;
        let mut config = base_config(ss, port, port + 1);
        config.proxy_socks5 = false;
        config.proxy_http = false;

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        let message = start_expect_error(&mut harness, config).await;
        assert!(
            message.contains("no local listeners"),
            "expected NoListenersEnabled message, got: {message}"
        );
    });
}

#[skuld::test(labels = [DIST_BIN])]
fn e2e_start_rejects_same_port(#[fixture(dist_dir)] dist: &Path, #[fixture(ssserver_none)] ss: &SsServerHandle) {
    rt().block_on(async {
        let port = allocate_ephemeral_port().await;
        let mut config = base_config(ss, port, port);
        config.proxy_http = true;

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        let message = start_expect_error(&mut harness, config).await;
        assert!(
            message.contains("must differ") && message.contains(&port.to_string()),
            "expected DuplicateListenerPort message, got: {message}"
        );
    });
}

#[skuld::test(labels = [DIST_BIN])]
fn e2e_start_rejects_full_mode_without_socks5(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port().await;
        let http_port = allocate_ephemeral_port().await;
        let mut config = base_config(ss, socks_port, http_port);
        config.proxy_socks5 = false;
        config.proxy_http = true;
        config.tunnel_mode = TunnelMode::Full;

        let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
        let message = start_expect_error(&mut harness, config).await;
        assert!(
            message.contains("SOCKS5 listener"),
            "expected TunnelRequiresSocks5 message, got: {message}"
        );
    });
}

// UDP via TUN (Windows admin only) ====================================================================================
//
// End-to-end exercise of the SOCKS5 UDP ASSOCIATE path inside the bridge:
// the test sends a UDP datagram directly to the echo server's primary
// non-loopback IPv4, the TUN split routes capture it, the dispatcher's
// `Socks5Endpoint::serve_udp` opens a SOCKS5 UDP ASSOCIATE to the
// `ss-server`, and the reply comes back via the same tunnel.
//
// Gated to Windows for the same reason as the existing `mod tun` in
// `proxy_manager_e2e_tests.rs`: `TunnelMode::Full` needs elevation, and
// `windows-latest` CI runs as `RUNNERADMIN`. The SocksOnly path is
// unusable here because #189 forces `Mode::TcpOnly` on the SOCKS5
// listener in SocksOnly mode.
//
// The test asserts a client-facing UDP round-trip, which covers the
// entire TUN→dispatcher→Socks5Endpoint→shadowsocks-service UDP stack
// end-to-end — including the `Mode::TcpAndUdp` flag flowing through
// `build_ss_config`. Using 127.0.0.1 for either the client or the
// echo server would hit the bridge's loopback bypass route and bypass
// the TUN, defeating the point of the test — see the caveat at
// `proxy_manager_e2e_tests.rs:184-192`.

#[cfg(target_os = "windows")]
mod tun {
    use super::*;
    use crate::test_support::udp_echo::UdpEchoServer;
    use tokio::net::UdpSocket;

    #[skuld::test(labels = [DIST_BIN, TUN], serial = TUN)]
    fn e2e_socks5_udp_associate_roundtrip(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_none)] ss: &SsServerHandle,
    ) {
        rt().block_on(async {
            let echo = UdpEchoServer::start().await.expect("UDP echo server bind");
            let socks_port = allocate_ephemeral_port().await;
            let http_port = allocate_ephemeral_port().await;
            let mut config = base_config(ss, socks_port, http_port);
            config.tunnel_mode = TunnelMode::Full;

            let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
            start_expect_ack(&mut harness, config).await;

            // Direct UDP send to the echo server's primary IPv4 — the
            // bridge's TUN routes capture this and tunnel it through the
            // ss-server via SOCKS5 UDP ASSOCIATE.
            let client = UdpSocket::bind("0.0.0.0:0").await.expect("bind UDP client");
            let payload = b"HOLE-UDP-ASSOCIATE";
            client.send_to(payload, echo.addr).await.expect("send UDP");

            let mut buf = vec![0u8; 65_536];
            let (n, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buf))
                .await
                .expect("UDP reply within 10s")
                .expect("UDP recv");
            assert_eq!(&buf[..n], payload, "expected UDP echo to return the payload unchanged");

            harness.send(BridgeRequest::Stop).await.expect("send Stop");
        });
    }
}
