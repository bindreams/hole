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
    // time we drop the wrapper. Spawned on the `SsRuntime`'s own handle —
    // not the ambient test runtime — so this exercises the real pairing.
    let running = ShadowsocksRunning::from_task(|handle| handle.spawn(std::future::pending::<io::Result<()>>()));
    drop(running); // must not panic
}

#[skuld::test]
async fn stop_then_drop_is_no_op() {
    let running = ShadowsocksRunning::from_task(|handle| handle.spawn(async { Ok::<(), io::Error>(()) }));
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

// Drop-path port release ==============================================================================================

/// Exercises `join_runtime`'s `block_in_place` arm: dropping (not
/// `stop()`ping) a started proxy on a multi-thread runtime must still
/// release both ports before `drop` returns.
///
/// Deterministic only on the fixed code, because `Drop` joins the
/// runtime. On unmodified code this is a genuine race (whichever poll
/// happens to run first), so this is not a red-on-main guard the way
/// the `stop()` tests above are.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn drop_releases_the_listener_ports_on_a_multi_thread_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build multi-thread runtime");
    rt.block_on(async {
        let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = socks_only_config(server, local_port);

        let running = ShadowsocksProxy::new().start(config).await.expect("proxy starts");
        socks5_method_negotiate(local_port).await;

        drop(running);

        assert_ports_free(local_port);
    });
}

/// Same claim as above, on a current-thread runtime — the `join()` (not
/// `block_in_place`) arm of `join_runtime`.
///
/// A *stronger* claim than the multi-thread test: `join_runtime` joins
/// on every flavour, so this must hold here too, and stops a future edit
/// from quietly reintroducing a non-joining fallback for this arm.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn drop_releases_the_listener_ports_on_a_current_thread_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");
    rt.block_on(async {
        let local_port = allocate_ephemeral_port(Protocols::TCP | Protocols::UDP).await;
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = socks_only_config(server, local_port);

        let running = ShadowsocksProxy::new().start(config).await.expect("proxy starts");
        socks5_method_negotiate(local_port).await;

        drop(running);

        assert_ports_free(local_port);
    });
}

// Upstream assumption guard ===========================================================================================

/// Guards the one property this change relies on that no behavioural test
/// can see: `drop(Runtime)` waits for *running* blocking-pool tasks, and
/// `shadowsocks-service` 1.24.0 has none on Hole's local-server path today
/// (confirmed by reading its source, not merely assumed). A version bump
/// could reintroduce one with no other test going red — this walks the
/// dependency's source tree and asserts it stays that way.
///
/// If `cargo metadata` is not resolvable in the test environment, this test
/// cannot be expressed; see CONTRIBUTING.md#proxy-shutdown-contract before
/// weakening the assertion.
#[skuld::test]
fn upstream_has_no_blocking_calls_on_the_shutdown_path() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .output()
        .expect("run `cargo metadata`");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse `cargo metadata` JSON output");
    let packages = metadata["packages"].as_array().expect("metadata packages array");

    for pkg_name in ["shadowsocks-service", "shadowsocks"] {
        let pkg = packages
            .iter()
            .find(|p| p["name"] == pkg_name)
            .unwrap_or_else(|| panic!("`{pkg_name}` not found in `cargo metadata` packages"));
        let manifest_path = pkg["manifest_path"].as_str().expect("manifest_path is a string");
        let src_dir = std::path::Path::new(manifest_path)
            .parent()
            .expect("manifest_path has a parent directory")
            .join("src");

        let mut spawn_blocking_count = 0usize;
        let mut lookup_host_count = 0usize;
        let mut lookup_host_sites = Vec::new();
        for entry in walk_rs_files(&src_dir) {
            let contents = std::fs::read_to_string(&entry).unwrap_or_else(|e| panic!("read {entry:?}: {e}"));
            spawn_blocking_count += contents.matches("spawn_blocking").count();
            // Call-syntax only ("lookup_host(") — the bare identifier also
            // matches the `use tokio::net::lookup_host;` import line, which
            // isn't a call site.
            let hits = contents.matches("lookup_host(").count();
            if hits > 0 {
                lookup_host_count += hits;
                lookup_host_sites.push((entry, hits));
            }
        }

        assert_eq!(
            spawn_blocking_count, 0,
            "`{pkg_name}` {src_dir:?} now calls `spawn_blocking` ({spawn_blocking_count} occurrence(s)) — \
             the no-hang property of `ShadowsocksRunning::stop` assumed upstream does no blocking work on the \
             local-server path; this bump breaks that assumption. Re-audit whether Hole's config reaches the \
             new call site, then update this test's expectation or the shutdown contract. \
             See CONTRIBUTING.md#proxy-shutdown-contract."
        );

        if pkg_name == "shadowsocks" {
            // The one known site: `dns_resolver/resolver.rs`'s
            // `DnsResolver::System` branch, live but unreached by Hole's
            // config (see CONTRIBUTING.md#proxy-shutdown-contract). A count
            // other than 1, or a hit outside that file, means the call site
            // moved or multiplied and needs the same re-audit as above.
            assert_eq!(
                lookup_host_count, 1,
                "`{pkg_name}` {src_dir:?} calls `lookup_host` {lookup_host_count} time(s) at {lookup_host_sites:?}, \
                 expected exactly 1 (dns_resolver/resolver.rs's DnsResolver::System branch) — the call site moved \
                 or multiplied. Re-audit whether Hole's config now reaches it. See CONTRIBUTING.md#proxy-shutdown-contract."
            );
            assert!(
                lookup_host_sites.iter().all(|(path, _)| path
                    .to_string_lossy()
                    .replace('\\', "/")
                    .ends_with("dns_resolver/resolver.rs")),
                "`{pkg_name}` `lookup_host` call site(s) {lookup_host_sites:?} are not where expected \
                 (dns_resolver/resolver.rs). See CONTRIBUTING.md#proxy-shutdown-contract."
            );
        }
    }
}

fn walk_rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
            let entry = entry.expect("read_dir entry").path();
            if entry.is_dir() {
                stack.push(entry);
            } else if entry.extension().is_some_and(|ext| ext == "rs") {
                out.push(entry);
            }
        }
    }
    out
}
