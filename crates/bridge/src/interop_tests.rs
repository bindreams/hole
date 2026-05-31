//! Cross-implementation interop tests: prove ex-ray is wire-compatible with
//! genuine upstream shadowsocks/v2ray-plugin in BOTH directions.
//!
//! ex-ray (the first-party v2ray-core shim that replaced the vendored
//! v2ray-plugin, #414) claims to be "wire-compatible with stock v2ray-plugin
//! both ways." A self-test (ex-ray↔ex-ray) cannot substantiate that claim —
//! it only proves ex-ray agrees with itself. These tests run a REAL
//! cross-process round-trip against a PINNED upstream v2ray-plugin build
//! (`xtask::upstream_v2ray::PINNED_COMMIT` == Hole's vendored base), sending
//! real bytes through real plugin subprocesses:
//!
//! - **ex-ray client ↔ stock-v2ray-plugin server** (`interop_ex_ray_client_stock_server`)
//! - **stock-v2ray-plugin client ↔ ex-ray server** (`interop_stock_client_ex_ray_server`)
//! - **ex-ray ↔ ex-ray** (`interop_ex_ray_both_ends`) — the fast inner-loop
//!   self-consistency check that needs only `cargo xtask ex-ray`, no upstream
//!   provisioning.
//!
//! ## How the round-trip sends real bytes
//!
//! Each test reuses the existing real-shadowsocks-server harness:
//!
//! 1. [`start_real_ss_server_with_plugin_ws`] spins a real
//!    `shadowsocks_service` server fronted by a SERVER-mode plugin binary
//!    (websocket transport, no TLS).
//! 2. [`run_server_test`] is then pointed at that server with `entry.plugin =
//!    "v2ray-plugin"` and `plugin_path_override = <CLIENT plugin binary>`. It
//!    spawns its own CLIENT-mode plugin, opens a real shadowsocks tunnel
//!    through the plugin chain, writes a `HEAD /` request, and inspects the
//!    reply.
//! 3. A [`start_fake_sentinel`] returning `HTTP/1.0 200 OK` stands in for the
//!    public internet. A [`ServerTestOutcome::Reachable`] result means the
//!    `HEAD` request traversed client-plugin → server-plugin → SS server →
//!    sentinel and the `HTTP/1.0 200 OK` traversed all the way back —
//!    end-to-end wire interop, not a mock.
//!
//! By mixing the SERVER plugin binary and the CLIENT plugin binary (one
//! ex-ray, one stock) we exercise each cross-implementation direction.
//!
//! ## Fail-loud, never skip
//!
//! Per CLAUDE.md, tests must fail loudly on missing dependencies, never
//! silently skip. Each test asserts its required binaries `is_file()` up
//! front with a remediation hint (`cargo xtask ex-ray` /
//! `cargo xtask provision-upstream-v2ray`). The ex-ray↔ex-ray test needs only
//! ex-ray; the two cross-impl tests additionally need the provisioned
//! upstream binary.
//!
//! ## Gate
//!
//! `labels = [PORT_ALLOC]` + `serial = PORT_ALLOC` matches the existing
//! real-plugin test (`run_test_with_v2ray_plugin_happy_path`): these spawn
//! plugins on inline-allocated loopback ports, so they participate in the
//! `PORT_ALLOC` mutual-exclusion gate. Unlike `server_test_tests` (gated
//! Linux-only behind #197/#200), these tests use NO TUN and NO routing — pure
//! loopback SS server + plugin subprocesses — so they run on every platform
//! and need no elevation.

use crate::server_test::{run_server_test, TestConfig};
use crate::test_support::http_target::start_fake_sentinel;
use crate::test_support::port_alloc::wait_for_port;
use crate::test_support::rt;
use crate::test_support::skuld_fixtures::PORT_ALLOC;
use crate::test_support::ssserver::{
    locate_ex_ray, locate_upstream_v2ray, start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_METHOD_STR,
    TEST_PASSWORD,
};
use hole_common::config::ServerEntry;
use hole_common::protocol::ServerTestOutcome;
use std::path::PathBuf;
use std::time::Duration;

/// Build a `ServerEntry` whose `plugin = "v2ray-plugin"` (the friendly wire
/// name that resolves to the on-disk plugin binary) and whose `plugin_opts`
/// mirror the server-side websocket options minus the `server` flag.
fn plugin_entry(host: &str, port: u16) -> ServerEntry {
    ServerEntry {
        id: "interop-entry".into(),
        name: "interop".into(),
        server: host.into(),
        server_port: port,
        method: TEST_METHOD_STR.into(),
        password: TEST_PASSWORD.into(),
        plugin: Some("v2ray-plugin".into()),
        // Server side uses "server;host=cloudfront.com;path=/"; the client
        // mirrors host+path without the `server` flag so the WS handshake
        // (Host header + request path) matches.
        plugin_opts: Some("host=cloudfront.com;path=/".into()),
        validation: None,
    }
}

/// `TestConfig` with the generous plugin-cold-start timeouts the WS handshake
/// needs, pointing the CLIENT plugin at `client_plugin_path`.
fn interop_config(
    sentinel_a: std::net::SocketAddr,
    sentinel_b: std::net::SocketAddr,
    client_plugin_path: &str,
) -> TestConfig {
    TestConfig {
        preflight_timeout: Duration::from_millis(500),
        // The WS handshake adds latency on top of the raw TCP connect; the
        // 2 s production default is too tight for a cold plugin start.
        ss_connect_timeout: Duration::from_secs(5),
        sentinel_read_timeout: Duration::from_secs(5),
        sentinels: [sentinel_a.to_string(), sentinel_b.to_string()],
        plugin_path_override: Some(client_plugin_path.to_string()),
    }
}

/// Assert a binary exists, failing loudly with a remediation hint otherwise.
/// Per CLAUDE.md: never silently skip on a missing test dependency.
fn require_binary(path: &PathBuf, remediation: &str) {
    assert!(
        path.is_file(),
        "interop test dependency missing at {path:?} — {remediation}"
    );
}

/// Drive one cross-implementation round-trip: a real SS server fronted by
/// `server_plugin_path`, a client driven through `client_plugin_path`, and a
/// fake sentinel. Asserts the `HEAD /` echoes back `HTTP/1.0 200 OK` through
/// both plugin processes → [`ServerTestOutcome::Reachable`].
fn assert_roundtrip(server_plugin_path: &str, client_plugin_path: &str) {
    rt().block_on(async {
        let (svr_addr, _svr) =
            start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, server_plugin_path).await;
        // The SS server's plugin binds its public port asynchronously; wait
        // for it before the client attempts preflight. This is the sanctioned
        // class-2 (external-event subprocess-startup) poll, mirroring
        // `run_test_with_v2ray_plugin_happy_path`.
        wait_for_port(svr_addr, Duration::from_secs(7)).await;

        let (sentinel_a, _sa) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
        let (sentinel_b, _sb) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let entry = plugin_entry(&svr_addr.ip().to_string(), svr_addr.port());
        let cfg = interop_config(sentinel_a, sentinel_b, client_plugin_path);

        let outcome = run_server_test(&entry, &cfg).await;
        match outcome {
            ServerTestOutcome::Reachable { latency_ms } => {
                assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1");
            }
            other => panic!(
                "expected Reachable for server={server_plugin_path:?} client={client_plugin_path:?}, got {other:?}"
            ),
        }
    });
}

// Tests ===============================================================================================================

/// Fast inner-loop self-consistency: ex-ray on BOTH ends. Needs only
/// `cargo xtask ex-ray` — no upstream provisioning. Proves the harness wiring
/// and ex-ray's own WS handshake before the cross-impl tests add the upstream
/// variable.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn interop_ex_ray_both_ends() {
    let ex_ray = locate_ex_ray();
    require_binary(&ex_ray, "run `cargo xtask ex-ray`");

    let ex_ray = ex_ray.to_str().expect("ex-ray path is valid utf-8");
    assert_roundtrip(ex_ray, ex_ray);
}

/// Cross-impl direction 1: ex-ray CLIENT talking to a stock-v2ray-plugin
/// SERVER. Proves ex-ray's client-side wire output is understood by genuine
/// upstream v2ray-plugin.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn interop_ex_ray_client_stock_server() {
    let ex_ray = locate_ex_ray();
    let stock = locate_upstream_v2ray();
    require_binary(&ex_ray, "run `cargo xtask ex-ray`");
    require_binary(&stock, "run `cargo xtask provision-upstream-v2ray`");

    assert_roundtrip(
        stock.to_str().expect("upstream path is valid utf-8"),
        ex_ray.to_str().expect("ex-ray path is valid utf-8"),
    );
}

/// Cross-impl direction 2: stock-v2ray-plugin CLIENT talking to an ex-ray
/// SERVER. Proves ex-ray's server-side wire output is understood by genuine
/// upstream v2ray-plugin.
#[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
fn interop_stock_client_ex_ray_server() {
    let ex_ray = locate_ex_ray();
    let stock = locate_upstream_v2ray();
    require_binary(&ex_ray, "run `cargo xtask ex-ray`");
    require_binary(&stock, "run `cargo xtask provision-upstream-v2ray`");

    assert_roundtrip(
        ex_ray.to_str().expect("ex-ray path is valid utf-8"),
        stock.to_str().expect("upstream path is valid utf-8"),
    );
}
