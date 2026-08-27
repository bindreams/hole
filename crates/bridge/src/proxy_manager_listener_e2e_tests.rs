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
//! * The `mod tun` UDP test uses `TunnelMode::Full` and is Windows-admin
//!   only, mirroring the existing `mod tun` pattern in
//!   `proxy_manager_e2e_tests.rs`. `windows-latest` GitHub Actions runs
//!   as `RUNNERADMIN` so CI does exercise it. Full mode is what that test
//!   brings up, not what carries its datagram — see the note on `mod tun`.

use crate::test_support::dist_fixture::*;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::http_connect_client::http_connect_request;
use crate::test_support::http_target::HttpTarget;
use crate::test_support::port_alloc::{allocate_ephemeral_port, wait_for_port};
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::*;
use crate::test_support::socks5_client::{http_get_request, http_response_body, socks5_request};
use hole_common::config::ServerEntry;
use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig, StartError, TunnelMode};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use util::port_alloc::Protocols;

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
        dns: hole_common::config::DnsConfig {
            enabled: false,
            ..hole_common::config::DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http,
        diagnostic_plugin_tap: false,
    }
}

/// Send `Start` and expect `Ack`. Panics on any other response or IPC error.
async fn start_expect_ack(harness: &mut DistHarness, config: ProxyConfig) {
    let resp = harness
        .send(BridgeRequest::Start {
            config,
            attempt_id: "e2e".into(),
            covered: false,
        })
        .await
        .expect("send Start");
    assert!(matches!(resp, BridgeResponse::Ack), "expected Ack, got {resp:?}");
}

/// Send `Start` and expect a typed `StartFailed(Failed)`. Returns the message.
async fn start_expect_error(harness: &mut DistHarness, config: ProxyConfig) -> String {
    let resp = harness
        .send(BridgeRequest::Start {
            config,
            attempt_id: "e2e".into(),
            covered: false,
        })
        .await
        .expect("send Start");
    match resp {
        BridgeResponse::StartFailed(StartError::Failed { message }) => message,
        other => panic!("expected StartFailed(Failed), got {other:?}"),
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
            // ports in some configurations. Fall back to a positive
            // check: if we can bind the port, it's free.
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
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
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
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
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
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
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
/// Toggling `proxy_http` alone (every other structural field unchanged)
/// must NOT take reload's no-op fast path — the HTTP listener must
/// actually bind.
#[skuld::test(labels = [DIST_BIN])]
fn e2e_reload_toggling_http_listener_rebinds(
    #[fixture(dist_dir)] dist: &Path,
    #[fixture(ssserver_none)] ss: &SsServerHandle,
    #[fixture(http_target_ipv4)] http: &HttpTarget,
) {
    rt().block_on(async {
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
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
        // Both listeners disabled — no actual bind happens, so any
        // Protocols choice would work, but keep TCP+UDP for the SOCKS5
        // slot per the SOCKS5-listener-is-TcpAndUdp invariant.
        // Allocate two distinct ports rather than `port + 1` to avoid
        // wraparound to 0 when the first allocation hits 65535.
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
        let mut config = base_config(ss, socks_port, http_port);
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
        // Same-port collision test: the port slot is the SOCKS5 listener
        // (`local_port`), allocated as TCP+UDP per the invariant.
        let port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
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
        let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let http_port = allocate_ephemeral_port(Protocols::TCP).await;
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

// UDP under a live TUN (Windows admin only) ===========================================================================
//
// What this proves, in full: Full mode starts under elevation, and a
// host-local UDP round trip still works while it is up.
//
// What it does not prove: in-TUN UDP transit. The datagram goes to the echo
// server's primary non-loopback IPv4 — an address the host holds — so the
// kernel's on-link `/32` beats whichever half of the `/1` split pair covers it
// and it is delivered locally to a `0.0.0.0`-bound socket.
// `Socks5Endpoint::serve_udp` is never invoked.
//
// There is no single-host oracle for the transit version: UDP has no
// handshake, so nothing in the TUN answers; the catch-all Block that makes
// the TCP oracle safe would drop the flow outright; and letting it reach the
// proxy re-enters via the ss-server without the `conn_semaphore` ceiling that
// bounds the TCP case. The TCP transit proof lives in
// `proxy_manager_e2e_tests.rs::tun::e2e_*_full_tunnel_captures_unowned_destination`.
//
// OPEN GAP, tracked as a follow-up to #880, not closed by this test: in-TUN
// UDP transit has no coverage anywhere in this suite. Building the oracle
// needs something that answers a datagram from inside the TUN, which the TCP
// oracle gets for free from the handshake. Do not read this test as covering
// it, and do not delete this note without landing that oracle.
//
// Gated to Windows for the same reason as the existing `mod tun` in
// `proxy_manager_e2e_tests.rs`: `TunnelMode::Full` needs elevation, and
// `windows-latest` CI runs as `RUNNERADMIN`. The SocksOnly UDP path is
// covered by `mod socks_only_udp` below — it runs in the non-TUN pass on
// every Hole platform (Win+mac), both the no-plugin and galoshes variants.

/// COUPLED NAME: this test must stay named `e2e_…full_tunnel…` so
/// `.config/nextest.toml`'s `global-net-state` filter keeps selecting it —
/// skuld gives libtest the bare function name, so there is no module path to
/// anchor on. That selection buys nextest's cross-binary thread budget; what
/// keeps this test off the tun-engine WFP tests is its `serial = TUN`. See the
/// note on `proxy_manager_e2e_tests.rs`'s `mod tun`.
#[cfg(target_os = "windows")]
mod tun {
    use super::*;
    use crate::test_support::net_discovery::block_every_in_tun_flow;
    use crate::test_support::udp_echo::UdpEchoServer;
    use tokio::net::UdpSocket;

    #[skuld::test(labels = [DIST_BIN, TUN], serial = TUN)]
    fn e2e_full_tunnel_local_udp_intact(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_none)] ss: &SsServerHandle,
    ) {
        rt().block_on(async {
            let echo = UdpEchoServer::start().await.expect("UDP echo server bind");
            let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
            let http_port = allocate_ephemeral_port(Protocols::TCP).await;
            let mut config = base_config(ss, socks_port, http_port);
            config.tunnel_mode = TunnelMode::Full;
            // See `block_every_in_tun_flow` for why (re-entry burst) and the
            // UDP/53 caveat. The echo round trip is unaffected: that datagram
            // never reaches the router.
            config.filters = block_every_in_tun_flow();

            let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
            start_expect_ack(&mut harness, config).await;

            // Direct UDP send to the echo server's primary IPv4. Delivered
            // locally by the host stack, not through the tunnel.
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

// UDP via SocksOnly ===================================================================================================
//
// End-to-end exercise of SOCKS5 UDP ASSOCIATE in `TunnelMode::SocksOnly`,
// where there is no TUN dispatcher and no loopback bypass route. The
// test client opens UDP-ASSOCIATE through the bridge's SOCKS5 listener
// at `127.0.0.1:<socks_port>`, the bridge relays datagrams via the SS
// tunnel to the upstream ss-server, the ss-server sends them on to the
// loopback echo, and replies follow the reverse path.
//
// Two variants:
// * `e2e_socks_only_udp_associate_no_plugin` — direct ss tunnel.
// * `e2e_socks_only_udp_associate_galoshes` — UDP through galoshes'
//   YAMUX-multiplexed plugin chain.
//
// Both labeled `[DIST_BIN]` (no `TUN`) → run in pass-1
// (`SKULD_LABELS="!tun"`) where loopback delivery is intact.
// The galoshes variant additionally carries `PORT_ALLOC` because
// `ssserver_ws` is `serial = PORT_ALLOC`.

mod socks_only_udp {
    use super::*;
    use crate::test_support::socks5_client::socks5_udp_associate;
    use crate::test_support::udp_echo::UdpEchoServer;

    /// Generous reply budget for the SOCKS5 UDP round-trip — a class-2
    /// failure-to-human bound sized like the galoshes+ex-ray cold-start budget
    /// in `plugin-e2e/src/roundtrip.rs`; the client retransmits within it.
    const UDP_REPLY_DEADLINE: Duration = Duration::from_secs(20);

    async fn run_udp_roundtrip(socks_addr: SocketAddr) {
        let echo = UdpEchoServer::start_loopback().await.expect("UDP echo bind");
        wait_for_port(socks_addr, Duration::from_secs(10)).await;
        let payload = b"HOLE-SOCKS-ONLY-UDP";
        let echoed = socks5_udp_associate(socks_addr, echo.addr, payload, UDP_REPLY_DEADLINE)
            .await
            .expect("UDP-ASSOCIATE roundtrip");
        assert_eq!(echoed, payload, "expected UDP echo to return the payload unchanged");
    }

    #[skuld::test(labels = [DIST_BIN])]
    fn e2e_socks_only_udp_associate_no_plugin(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_none)] ss: &SsServerHandle,
    ) {
        rt().block_on(async {
            let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
            let http_port = allocate_ephemeral_port(Protocols::TCP).await;
            let config = base_config(ss, socks_port, http_port);

            let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
            start_expect_ack(&mut harness, config).await;
            run_udp_roundtrip(format!("127.0.0.1:{socks_port}").parse().unwrap()).await;
            harness.send(BridgeRequest::Stop).await.expect("send Stop");
        });
    }

    /// galoshes (WS) carries SOCKS5 UDP ASSOCIATE over its yamux mux.
    #[skuld::test(labels = [DIST_BIN, PORT_ALLOC])]
    fn e2e_socks_only_udp_associate_galoshes(
        #[fixture(dist_dir)] dist: &Path,
        #[fixture(ssserver_ws)] ss: &SsServerHandle,
    ) {
        rt().block_on(async {
            let socks_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
            let http_port = allocate_ephemeral_port(Protocols::TCP).await;
            let config = base_config(ss, socks_port, http_port);

            let mut harness = DistHarness::spawn(dist).await.expect("spawn DistHarness");
            start_expect_ack(&mut harness, config).await;
            run_udp_roundtrip(format!("127.0.0.1:{socks_port}").parse().unwrap()).await;
            harness.send(BridgeRequest::Stop).await.expect("send Stop");
        });
    }
}
