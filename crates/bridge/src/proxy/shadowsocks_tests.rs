//! Unit tests for `ShadowsocksRunning`'s lifecycle, focused on the
//! Drop contract: dropping a wrapper that still owns a live ss task
//! must NOT panic — RAII-unwind paths drop it between
//! `proxy.start().await` and the next `?` in `start_inner`.
//!
//! The port-release tests below build their own `event_interval(1)`
//! current-thread runtime so exactly one queued task drains per
//! `block_on` poll. See CONTRIBUTING.md#proxy-shutdown-contract.

use super::ShadowsocksRunning;
use crate::proxy::{build_ss_config, Proxy, ProxyError, RunningProxy, ShadowsocksProxy};
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::skuld_fixtures::*;
use crate::test_support::socks5_client::socks5_udp_associate;
use crate::test_support::udp_echo::UdpEchoServer;
use hole_common::config::ServerEntry;
use hole_common::protocol::{ProxyConfig, TunnelMode};
use plugin_e2e::ssserver::{TEST_METHOD_STR, TEST_PASSWORD};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use util::port_alloc::Protocols;

#[skuld::test]
async fn drop_does_not_panic_when_handle_alive() {
    // A task that pends forever stands in for a freshly-spawned
    // shadowsocks server: it is unambiguously not finished by the
    // time we drop the wrapper.
    let handle = tokio::spawn(std::future::pending::<io::Result<()>>());
    let running = ShadowsocksRunning::from_handle(handle);
    drop(running); // must not panic
}

#[skuld::test]
async fn stop_then_drop_is_no_op() {
    let handle = tokio::spawn(async { Ok::<(), io::Error>(()) });
    let running = ShadowsocksRunning::from_handle(handle);
    let res: Result<(), ProxyError> = running.stop().await;
    res.expect("stop returns Ok on a clean exit");
    // `stop` consumed `running`; nothing to assert beyond "didn't
    // panic" — included as a regression guard so a future change that
    // moves cleanup state out of `stop` triggers a visible failure.
}

// Port-release contract ===============================================================================================

/// Build a `SocksOnly` config with one SOCKS5 listener on `local_port`,
/// dialing `server`. Steps 1–2 never dial the server (any address
/// works); the layer-3 test passes a live `ssserver_none` fixture
/// address, whose credentials happen to be `TEST_METHOD_STR` /
/// `TEST_PASSWORD` too.
fn socks_only_config(server: SocketAddr, local_port: u16) -> shadowsocks_service::config::Config {
    let entry = ServerEntry {
        id: "shadowsocks-shutdown-test".into(),
        name: "shadowsocks-shutdown-test".into(),
        server: server.ip().to_string(),
        server_port: server.port(),
        method: TEST_METHOD_STR.into(),
        password: TEST_PASSWORD.into(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    };
    let config = ProxyConfig {
        server: entry,
        local_port,
        tunnel_mode: TunnelMode::SocksOnly,
        filters: vec![],
        dns: hole_common::config::DnsConfig {
            enabled: false,
            ..hole_common::config::DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    };
    build_ss_config(&config, None, server.ip(), None).expect("valid ss config")
}

/// SOCKS5 method negotiation against `127.0.0.1:port` — the rendezvous
/// that proves the accept loop is actually running, not just that the
/// kernel accepted a connection into the backlog.
async fn socks5_method_negotiate(port: u16) {
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("connect to SOCKS5 listener on port {port} failed: {e}"));
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .unwrap_or_else(|e| panic!("send SOCKS5 greeting on port {port} failed: {e}"));
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply)
        .await
        .unwrap_or_else(|e| panic!("read SOCKS5 method-selection reply on port {port} failed: {e}"));
    assert_eq!(
        reply,
        [0x05, 0x00],
        "SOCKS5 method negotiation on port {port} rejected: {reply:?}"
    );
}

/// Assert the given loopback port is free for both TCP and UDP, via
/// plain `std::net` binds. No `.await` between `stop()` returning and
/// these probes, so nothing else can run in the gap on a
/// current-thread runtime.
fn assert_ports_free(port: u16) {
    std::net::TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("stop() returned but TCP port {port} is still bound: {e}"));
    std::net::UdpSocket::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("stop() returned but UDP port {port} is still bound: {e}"));
}

/// Current-thread runtime with `event_interval(1)`: exactly one queued
/// task drains per `block_on` poll. See CONTRIBUTING.md#proxy-shutdown-contract
/// for why this makes the port-release race deterministic.
fn event_interval_1_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .event_interval(1)
        .build()
        .expect("build current-thread runtime")
}

#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn stop_releases_the_listener_ports() {
    event_interval_1_runtime().block_on(async {
        let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = socks_only_config(server, local_port);

        let running = ShadowsocksProxy::new().start(config).await.expect("proxy starts");
        socks5_method_negotiate(local_port).await;

        running.stop().await.expect("stop succeeds");

        assert_ports_free(local_port);
    });
}

#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn stop_then_start_reuses_the_same_ports() {
    event_interval_1_runtime().block_on(async {
        let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let running1 = ShadowsocksProxy::new()
            .start(socks_only_config(server, local_port))
            .await
            .expect("first proxy starts");
        socks5_method_negotiate(local_port).await;
        running1.stop().await.expect("first stop succeeds");

        // This is `ProxyManager::reload`'s structural slow path with the
        // routing/DNS/plugin phases stripped out: the same fixed port,
        // started again immediately after `stop()` returns.
        let running2 = ShadowsocksProxy::new()
            .start(socks_only_config(server, local_port))
            .await
            .unwrap_or_else(|e| panic!("second start on the same port {local_port} failed: {e}"));
        running2.stop().await.expect("second stop succeeds");
    });
}

/// Exercises layer 3 (`UdpAssociation::drop`) — the deepest abort layer,
/// which holds an `Arc` clone of the inbound SOCKS5 UDP listener inside a
/// per-association task whose handle never leaves `UdpAssociationManager`.
///
/// This is NOT evidence that layer 3 leaks today: layer 2 alone already
/// holds the port, so this test is red on unmodified code for the same
/// reason `stop_releases_the_listener_ports` is. Its value is
/// forward-looking — it is the only test that would catch a future
/// regression to a layer-2-only teardown.
#[skuld::test]
fn stop_releases_the_udp_port_with_a_live_association(#[fixture(ssserver_none)] ss: &SsServerHandle) {
    event_interval_1_runtime().block_on(async {
        let echo = UdpEchoServer::start_loopback().await.expect("start udp echo server");
        let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let config = socks_only_config(ss.addr, local_port);

        let running = ShadowsocksProxy::new().start(config).await.expect("proxy starts");

        let proxy_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
        let reply = socks5_udp_associate(proxy_addr, echo.addr, b"ping", Duration::from_secs(20))
            .await
            .expect("udp echo roundtrip through the SOCKS5 relay");
        assert_eq!(reply, b"ping", "echo reply payload mismatch");

        running.stop().await.expect("stop succeeds");

        assert_ports_free(local_port);
    });
}
