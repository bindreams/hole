//! galoshes server↔client roundtrip per transport — proves galoshes *serves*
//! WS/WS-TLS/QUIC, with no `DistHarness` and no `hole` binary in the path:
//! a `shadowsocks` client (via the `roundtrip` driver, with the galoshes
//! binary as the client plugin) → galoshes-client → (transport) →
//! galoshes-server (fronting a real ss-server) → fake sentinel.
//!
//! Plain **WS** runs on all platforms. **WS-TLS** and **QUIC** are gated off
//! Windows (`#[cfg(not(target_os = "windows"))]`): both present a self-signed
//! cert the client trusts via ex-ray's `AUTHORITY_VERIFY`, and v2ray-core's
//! `getCertPool` drops custom certs on Windows — the same limitation that gates
//! `interop.rs::mod quic`. macOS + Linux run all three. (bindreams/hole#197: the
//! galoshes-server fixture is now the garter-based launcher in `ssserver.rs`,
//! not `shadowsocks-service`'s `PluginConfig`; readiness is deterministic, so
//! there is no `wait_for_port`.)

// skuld's harness (`harness = false`) needs a `main` on every platform.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

/// Focused launcher smoke check (all platforms): the garter-based fixture
/// returns a LIVE, bound loopback public TCP address for a galoshes WS server —
/// no `PluginConfig`, no `wait_for_port`. Isolates "did the launcher come up"
/// from the full client roundtrip below.
mod launcher_smoke {
    use plugin_e2e::locators::locate_built_galoshes;
    use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_PASSWORD};
    use plugin_e2e::util::{require_binary, rt};
    use tokio::net::TcpStream;

    #[skuld::test]
    fn galoshes_ws_server_launcher_returns_live_public_addr() {
        let g = locate_built_galoshes();
        require_binary(&g, "run `cargo xtask galoshes`");
        let g = g.to_str().expect("galoshes path is valid utf-8").to_string();
        rt().block_on(async {
            let (public, _server) = start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, &g).await;
            assert!(public.ip().is_loopback(), "public addr must be loopback: {public}");
            assert_ne!(public.port(), 0, "public port must be concrete");
            // The returned addr must be the REAL bound public port: a TCP connect
            // to it must succeed (WS is TCP). Proves the launcher returned the
            // plugin's actual listener, not a stale/garbage addr.
            TcpStream::connect(public)
                .await
                .expect("public WS port must accept connections");
        });
    }
}

mod roundtrips {
    use plugin_e2e::locators::locate_built_galoshes;
    use plugin_e2e::roundtrip::{run_roundtrip, Roundtrip, RoundtripConfig};
    use plugin_e2e::sentinel::start_fake_sentinel;
    use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_PASSWORD};
    use plugin_e2e::util::{require_binary, rt};

    // WS-TLS + QUIC present a self-signed cert; v2ray-core's getCertPool drops
    // custom certs on Windows, so those two transports are gated off Windows (see
    // the file header). These imports are used only by those gated tests.
    #[cfg(not(target_os = "windows"))]
    use plugin_e2e::certs::{generate_test_certs, path_for_plugin_opts};
    #[cfg(not(target_os = "windows"))]
    use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_quic, start_real_ss_server_with_plugin_ws_tls};

    #[skuld::label]
    const PORT_ALLOC: skuld::Label;

    fn require_galoshes() -> String {
        let p = locate_built_galoshes();
        require_binary(&p, "run `cargo xtask galoshes`");
        p.to_str().expect("galoshes path is valid utf-8").to_string()
    }

    /// galoshes server↔client over websocket (the baseline TCP transport) — all platforms.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_roundtrip() {
        let g = require_galoshes();
        rt().block_on(async {
            let (svr, _h) = start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, &g).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let outcome = run_roundtrip(
                &g,
                Some("host=cloudfront.com;path=/"),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(matches!(outcome, Roundtrip::Reachable { .. }), "ws: {outcome:?}");
        });
    }

    /// REPRO for bindreams/hole#541: read the tunneled response to EOF, so the
    /// roundtrip only succeeds if the sentinel's FIN propagates the whole way
    /// back through the galoshes WS chain (ss-server -> server-plugin -> ex-ray
    /// WS -> client-plugin -> ss-client). `galoshes_ws_roundtrip` takes the first
    /// chunk and so never observes the FIN — the gap that let #541 ship.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_server_fin_propagates_to_eof() {
        let g = require_galoshes();
        rt().block_on(async {
            let (svr, _h) = start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, &g).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let outcome = run_roundtrip(
                &g,
                Some("host=cloudfront.com;path=/"),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig {
                    read_to_eof: true,
                    ..RoundtripConfig::default()
                },
            )
            .await;
            assert!(matches!(outcome, Roundtrip::Reachable { .. }), "ws eof: {outcome:?}");
        });
    }

    /// galoshes server↔client over websocket + TLS (off Windows — see file header).
    #[cfg(not(target_os = "windows"))]
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_tls_roundtrip() {
        let g = require_galoshes();
        rt().block_on(async {
            let certs = generate_test_certs();
            let (svr, _h) = start_real_ss_server_with_plugin_ws_tls(TEST_METHOD, TEST_PASSWORD, &g, &certs).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let opts = format!(
                "host=cloudfront.com;path=/;tls;cert={}",
                path_for_plugin_opts(&certs.cert_path)
            );
            let outcome = run_roundtrip(
                &g,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(matches!(outcome, Roundtrip::Reachable { .. }), "ws_tls: {outcome:?}");
        });
    }

    /// galoshes server↔client over QUIC (the path #421 unblocked; off Windows —
    /// see file header). Readiness is deterministic — the launcher returns only
    /// after galoshes' sitrep `ready` — so a single roundtrip suffices, no
    /// retry/sleep. (A flake here would mean a real readiness gap to root-cause,
    /// not a reason to re-add timing.)
    #[cfg(not(target_os = "windows"))]
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_quic_roundtrip() {
        let g = require_galoshes();
        rt().block_on(async {
            let certs = generate_test_certs();
            let (svr, _h) = start_real_ss_server_with_plugin_quic(TEST_METHOD, TEST_PASSWORD, &g, &certs).await;
            let opts = format!(
                "host=cloudfront.com;mode=quic;cert={}",
                path_for_plugin_opts(&certs.cert_path)
            );
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let outcome = run_roundtrip(
                &g,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(matches!(outcome, Roundtrip::Reachable { .. }), "quic: {outcome:?}");
        });
    }
}
