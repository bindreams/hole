//! galoshes server↔client roundtrip per transport — proves galoshes *serves*
//! WS/WS-TLS/QUIC, with no `DistHarness` and no `hole` binary in the path:
//! a `shadowsocks` client (via the `roundtrip` driver, with the galoshes
//! binary as the client plugin) → galoshes-client → (transport) →
//! galoshes-server (fronting a real ss-server) → fake sentinel.
//!
//! **Linux-only (`#197`).** The galoshes-server fixture uses
//! `shadowsocks-service`'s `PluginConfig`, whose bind-and-drop port allocation
//! races galoshes' embedded yamux-server on Win+mac (bindreams/hole#197).
//! Linux is where galoshes-server works today; relocation here is correct
//! regardless of #197 (see #435). Re-enable on Win+mac once #197 lands.

// Unconditional: skuld's harness (`harness = false`) needs a `main` on every
// platform. The tests themselves are `cfg(linux)` (see `mod linux` below); on
// non-Linux this binary links and `skuld::run_all()` finds zero tests.
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

#[cfg(target_os = "linux")]
mod linux {
    use plugin_e2e::certs::{generate_test_certs, path_for_plugin_opts};
    use plugin_e2e::locators::locate_built_galoshes;
    use plugin_e2e::roundtrip::{run_roundtrip, Roundtrip, RoundtripConfig};
    use plugin_e2e::sentinel::start_fake_sentinel;
    use plugin_e2e::ssserver::{
        start_real_ss_server_with_plugin_quic, start_real_ss_server_with_plugin_ws,
        start_real_ss_server_with_plugin_ws_tls, TEST_METHOD, TEST_PASSWORD,
    };
    use plugin_e2e::util::{require_binary, rt, wait_for_port};
    use std::time::{Duration, Instant};

    #[skuld::label]
    const PORT_ALLOC: skuld::Label;

    fn require_galoshes() -> String {
        let p = locate_built_galoshes();
        require_binary(&p, "run `cargo xtask galoshes`");
        p.to_str().expect("galoshes path is valid utf-8").to_string()
    }

    /// galoshes server↔client over websocket (the baseline "TCP" transport).
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_roundtrip() {
        let g = require_galoshes();
        rt().block_on(async {
            let (svr, _h) = start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, &g).await;
            wait_for_port(svr, Duration::from_secs(10)).await;
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

    /// galoshes server↔client over websocket + TLS.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_tls_roundtrip() {
        let g = require_galoshes();
        rt().block_on(async {
            let certs = generate_test_certs();
            let (svr, _h) = start_real_ss_server_with_plugin_ws_tls(TEST_METHOD, TEST_PASSWORD, &g, &certs).await;
            wait_for_port(svr, Duration::from_secs(10)).await;
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

    /// galoshes server↔client over QUIC (the path #421 unblocked for the
    /// galoshes-fronted server). The public endpoint is UDP, so readiness is
    /// established by retrying the whole roundtrip on a failure-to-human budget
    /// (sanctioned class-2 exception).
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
            let start = Instant::now();
            loop {
                let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
                match run_roundtrip(
                    &g,
                    Some(&opts),
                    &svr.ip().to_string(),
                    svr.port(),
                    TEST_METHOD,
                    TEST_PASSWORD,
                    sentinel,
                    &RoundtripConfig::default(),
                )
                .await
                {
                    Roundtrip::Reachable { .. } => return,
                    other => {
                        assert!(
                            start.elapsed() < Duration::from_secs(30),
                            "quic not reachable in 30s; last: {other:?}"
                        );
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
}
