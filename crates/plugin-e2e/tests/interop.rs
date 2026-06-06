//! Cross-implementation interop tests: prove ex-ray is wire-compatible with
//! genuine upstream shadowsocks/v2ray-plugin in BOTH directions.
//!
//! ex-ray (the first-party v2ray-core shim that replaced the vendored
//! v2ray-plugin, #414) claims to be "wire-compatible with stock v2ray-plugin
//! both ways." A self-test (ex-ray↔ex-ray) cannot substantiate that claim — it
//! only proves ex-ray agrees with itself. These tests run a REAL cross-process
//! round-trip against a PINNED upstream v2ray-plugin build, sending real bytes
//! through real plugin subprocesses:
//!
//! - **ex-ray client ↔ stock-v2ray-plugin server** (`interop_ex_ray_client_stock_server`)
//! - **stock-v2ray-plugin client ↔ ex-ray server** (`interop_stock_client_ex_ray_server`)
//! - **ex-ray ↔ ex-ray** (`interop_ex_ray_both_ends`) — the fast inner-loop
//!   self-consistency check that needs only `cargo xtask ex-ray`.
//!
//! ## How the round-trip sends real bytes
//!
//! Each test reuses the shared harness: a real `shadowsocks_service` server is
//! fronted by a SERVER-mode plugin binary (websocket), and the
//! [`plugin_e2e::roundtrip`] driver runs a CLIENT-mode plugin binary, opens a
//! real shadowsocks tunnel through it, writes a `HEAD /` request, and inspects
//! the reply against a single-shot sentinel returning `HTTP/1.0 200 OK`. A
//! [`Roundtrip::Reachable`] result means the request traversed client-plugin →
//! server-plugin → SS server → sentinel and the reply traversed all the way
//! back — end-to-end wire interop, not a mock. No Hole bridge is involved.
//!
//! ## Fail-loud, never skip
//!
//! Per CLAUDE.md, tests fail loudly on missing dependencies, never silently
//! skip. Each test asserts its required binaries `is_file()` up front with a
//! remediation hint (`cargo xtask ex-ray` / `provision-upstream-v2ray`).
//!
//! ## Gate
//!
//! `labels = [PORT_ALLOC]` + `serial = PORT_ALLOC`: these spawn plugins on
//! inline-allocated loopback ports. They use NO TUN and NO routing — pure
//! loopback SS server + plugin subprocesses — so they run on every platform
//! and need no elevation. (The QUIC sub-suite is `not(windows)` — see `mod quic`.)

use plugin_e2e::locators::{locate_ex_ray, locate_upstream_v2ray};
use plugin_e2e::roundtrip::{run_roundtrip, Roundtrip, RoundtripConfig};
use plugin_e2e::sentinel::start_fake_sentinel;
use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_PASSWORD};
use plugin_e2e::util::{require_binary, rt};

// Each skuld integration-test binary installs the observability ctor and
// provides its own `fn main` (harness = false in Cargo.toml).
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const PORT_ALLOC: skuld::Label;

/// WS client opts mirror the server side minus the `server` flag.
const WS_CLIENT_OPTS: &str = "host=cloudfront.com;path=/";

/// Drive one cross-implementation round-trip: a real SS server fronted by
/// `server_plugin_path`, a client driven through `client_plugin_path`, and a
/// fake sentinel. Asserts the `HEAD /` echoes back `HTTP/1.0 200 OK` →
/// [`Roundtrip::Reachable`].
///
/// Readiness is deterministic: `start_real_ss_server_with_plugin_ws` returns
/// only once the server plugin is live — ex-ray via its sitrep `ready`, and a
/// non-sitrep stock plugin via `ReadinessMode::Auto`'s TCP probe (WS is TCP,
/// so the probe observes the real public listener). There is therefore no
/// `wait_for_port` poll before the client connects.
fn assert_roundtrip(server_plugin_path: &str, client_plugin_path: &str) {
    rt().block_on(async {
        let (svr_addr, _svr) =
            start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, server_plugin_path).await;

        let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;

        let outcome = run_roundtrip(
            client_plugin_path,
            Some(WS_CLIENT_OPTS),
            &svr_addr.ip().to_string(),
            svr_addr.port(),
            TEST_METHOD,
            TEST_PASSWORD,
            sentinel,
            &RoundtripConfig::default(),
        )
        .await;
        match outcome {
            Roundtrip::Reachable { latency_ms } => assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1"),
            other => panic!(
                "expected Reachable for server={server_plugin_path:?} client={client_plugin_path:?}, got {other:?}"
            ),
        }
    });
}

// Tests ===============================================================================================================

/// Fast inner-loop self-consistency: ex-ray on BOTH ends. Needs only
/// `cargo xtask ex-ray`. Proves the harness wiring and ex-ray's own WS
/// handshake before the cross-impl tests add the upstream variable.
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

// QUIC interop ========================================================================================================

/// QUIC cross-impl tests, mirroring the websocket trio over the QUIC transport
/// (`mode=quic`) — the path #421 unblocked. Two of three directions run; the
/// stock-as-QUIC-server direction is `#[ignore]`d (bindreams/hole#428).
///
/// **Non-Windows gate.** QUIC mandates TLS, and these tests present a
/// self-signed cert the client trusts as a custom `AUTHORITY_VERIFY` anchor.
/// v2ray-core only merges such a custom cert into the client's `RootCAs` on
/// non-Windows; on Windows `getCertPool` returns the bare system store and
/// drops the custom cert, so a self-signed server cert fails with "certificate
/// signed by unknown authority". Production is unaffected (real CA-signed QUIC
/// servers verify against the OS store with no custom cert). See bindreams/hole#421.
///
/// Like `assert_roundtrip`, readiness is deterministic via the launcher's
/// sitrep `ready`: ex-ray UDP-probes its own QUIC inbound before reporting
/// ready (bindreams/hole#421), so `start_real_ss_server_with_plugin_quic`
/// returns only once the server is accepting. A single roundtrip therefore
/// suffices — no retry, no time budget, no sleep. (A TCP `wait_for_port` would
/// not work here regardless: the public endpoint is UDP-only and a TCP poll
/// can't observe a UDP listener.) Every *active* QUIC test below uses ex-ray as
/// the server; the lone stock-as-QUIC-server direction is `#[ignore]`d (#428),
/// so `ReadinessMode::Auto`'s sitrep path always drives readiness here.
#[cfg(not(target_os = "windows"))]
mod quic {
    use super::{require_binary, rt, start_fake_sentinel, PORT_ALLOC};
    use plugin_e2e::certs::{generate_test_certs, path_for_plugin_opts, TestCerts};
    use plugin_e2e::locators::{locate_ex_ray, locate_upstream_v2ray};
    use plugin_e2e::roundtrip::{run_roundtrip, Roundtrip, RoundtripConfig};
    use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_quic, TEST_METHOD, TEST_PASSWORD};

    fn quic_client_opts(certs: &TestCerts) -> String {
        format!(
            "host=cloudfront.com;mode=quic;cert={}",
            path_for_plugin_opts(&certs.cert_path)
        )
    }

    /// Drive one cross-implementation QUIC round-trip. Readiness is deterministic
    /// (see the module doc): the launcher returns only after the server plugin's
    /// sitrep `ready`, so a single roundtrip suffices with no readiness retry and
    /// no sleep. A flake here would mean a real readiness gap in the launcher to
    /// root-cause, not a reason to re-add timing.
    fn assert_quic_roundtrip(server_plugin_path: &str, client_plugin_path: &str) {
        rt().block_on(async {
            let certs = generate_test_certs();
            let (svr_addr, _svr) =
                start_real_ss_server_with_plugin_quic(TEST_METHOD, TEST_PASSWORD, server_plugin_path, &certs).await;
            let opts = quic_client_opts(&certs);
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let outcome = run_roundtrip(
                client_plugin_path,
                Some(&opts),
                &svr_addr.ip().to_string(),
                svr_addr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            match outcome {
                Roundtrip::Reachable { latency_ms } => assert!(latency_ms >= 1, "latency_ms must be clamped to >= 1"),
                other => panic!(
                    "expected Reachable for quic server={server_plugin_path:?} client={client_plugin_path:?}, got {other:?}"
                ),
            }
        });
    }

    /// QUIC self-consistency: ex-ray on BOTH ends. Needs only `cargo xtask
    /// ex-ray`. Proves ex-ray's own QUIC server binds a UDP listener and a full
    /// client→server→sentinel round-trip works — the regression #421 fixed.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn interop_quic_ex_ray_both_ends() {
        let ex_ray = locate_ex_ray();
        require_binary(&ex_ray, "run `cargo xtask ex-ray`");

        let ex_ray = ex_ray.to_str().expect("ex-ray path is valid utf-8");
        assert_quic_roundtrip(ex_ray, ex_ray);
    }

    /// QUIC cross-impl direction 1: ex-ray CLIENT talking to a stock-v2ray-plugin
    /// QUIC SERVER.
    ///
    /// **Disabled (`#[ignore]`).** The pinned stock v2ray-plugin is frozen on
    /// quic-go v0.48.1, which panics as a QUIC *server* on Go ≥1.24. This is
    /// server-only and NOT a wire incompatibility — ex-ray's QUIC client is
    /// exercised by `interop_quic_ex_ray_both_ends`, and ex-ray's QUIC server is
    /// cross-validated against a genuine stock client by
    /// `interop_quic_stock_client_ex_ray_server`. Tracked in bindreams/hole#428.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    #[ignore = "stock v2ray-plugin (quic-go 0.48.1) panics as a QUIC server on Go >=1.24 — see bindreams/hole#428"]
    fn interop_quic_ex_ray_client_stock_server() {
        let ex_ray = locate_ex_ray();
        let stock = locate_upstream_v2ray();
        require_binary(&ex_ray, "run `cargo xtask ex-ray`");
        require_binary(&stock, "run `cargo xtask provision-upstream-v2ray`");

        assert_quic_roundtrip(
            stock.to_str().expect("upstream path is valid utf-8"),
            ex_ray.to_str().expect("ex-ray path is valid utf-8"),
        );
    }

    /// QUIC cross-impl direction 2: stock-v2ray-plugin CLIENT talking to an
    /// ex-ray QUIC SERVER. Proves ex-ray's QUIC server wire output (the path
    /// #421 unblocked) is understood by genuine upstream v2ray-plugin.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn interop_quic_stock_client_ex_ray_server() {
        let ex_ray = locate_ex_ray();
        let stock = locate_upstream_v2ray();
        require_binary(&ex_ray, "run `cargo xtask ex-ray`");
        require_binary(&stock, "run `cargo xtask provision-upstream-v2ray`");

        assert_quic_roundtrip(
            ex_ray.to_str().expect("ex-ray path is valid utf-8"),
            stock.to_str().expect("upstream path is valid utf-8"),
        );
    }
}
