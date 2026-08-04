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

/// A malformed options string must stop galoshes at startup with a diagnosable
/// message. ex-ray would not: it discards every option and reports `ready` on
/// the flag-default port, so galoshes is the last place the operator can be
/// told. The bridge relays this stderr into its own log.
mod malformed_options {
    use plugin_e2e::locators::locate_built_galoshes;
    use plugin_e2e::util::{require_binary, rt};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::process::Command;
    use util::port_alloc::{self, Protocols};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// Class-2 subprocess failure bound, matching `spawn_ss_with_plugin`'s. If the
    /// guard regresses galoshes binds and runs forever; this names that instead of
    /// hanging the suite with no captured output.
    const EXIT_BUDGET: Duration = Duration::from_secs(60);

    /// A port that was free a moment ago. The refused path never binds — the guard
    /// runs before the chain starts — so this only has to be plausible; it exists
    /// so an occupied port cannot masquerade as the guard firing.
    async fn free_tcp_port() -> u16 {
        let (port, _listener) = port_alloc::bind_ephemeral(LOOPBACK, Protocols::TCP, |p| async move {
            TcpListener::bind((Ipv4Addr::LOCALHOST, p)).await
        })
        .await
        .expect("allocate a loopback tcp port");
        port
    }

    #[skuld::test]
    fn a_dangling_escape_stops_galoshes_with_a_named_reason() {
        let g = locate_built_galoshes();
        require_binary(&g, "run `cargo xtask ex-ray && cargo xtask galoshes`");
        rt().block_on(async {
            let (local, remote) = (free_tcp_port().await, free_tcp_port().await);
            let child = Command::new(&g)
                .env("SS_LOCAL_HOST", "127.0.0.1")
                .env("SS_LOCAL_PORT", local.to_string())
                .env("SS_REMOTE_HOST", "127.0.0.1")
                .env("SS_REMOTE_PORT", remote.to_string())
                .env("SS_PLUGIN_OPTIONS", "host=cloudfront.com;path=/a\\")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .expect("galoshes must be spawnable");

            let out = tokio::time::timeout(EXIT_BUDGET, child.wait_with_output())
                .await
                .expect("galoshes did not exit within the budget — the malformed-options guard did not fire")
                .expect("galoshes output");

            assert!(!out.status.success(), "galoshes must refuse to start: {:?}", out.status);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("embedded ex-ray") && stderr.contains("unpaired backslash"),
                "stderr must name the malformed options as the reason, got: {stderr}"
            );
        });
    }
}

mod roundtrips {
    use plugin_e2e::locators::locate_built_galoshes;
    use plugin_e2e::roundtrip::{run_roundtrip, NotReachableKind, Roundtrip, RoundtripConfig};
    use plugin_e2e::sentinel::start_fake_sentinel;
    use plugin_e2e::ssserver::{
        start_real_ss_server_with_plugin_ws, start_real_ss_server_with_plugin_ws_opts, TEST_METHOD, TEST_PASSWORD,
        WS_SERVER_OPTS,
    };
    use plugin_e2e::util::{require_binary, rt};
    use std::time::Duration;

    // WS-TLS + QUIC present a self-signed cert; v2ray-core's getCertPool drops
    // custom certs on Windows, so those two transports are gated off Windows (see
    // the file header). These imports are used only by those gated tests.
    #[cfg(not(target_os = "windows"))]
    use plugin_e2e::certs::{generate_test_certs, path_for_plugin_opts};
    #[cfg(not(target_os = "windows"))]
    use plugin_e2e::locators::locate_ex_ray;
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

    /// Client options for the plain-WS fixture, mirroring `WS_SERVER_OPTS`.
    const WS_CLIENT_OPTS: &str = "host=cloudfront.com;path=/";

    /// `mux` also selects the server's dokodemo destination, so a default client
    /// and a `mux=1` server no longer speak the same wire format. Proving the
    /// tunnel BREAKS is what shows the default actually changed.
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn galoshes_ws_mux_default_cannot_reach_a_mux1_server() {
        let g = require_galoshes();
        rt().block_on(async {
            let server_opts = format!("{WS_SERVER_OPTS};mux=1");
            let (svr, _h) =
                start_real_ss_server_with_plugin_ws_opts(TEST_METHOD, TEST_PASSWORD, &g, &server_opts).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let outcome = run_roundtrip(
                &g,
                Some(&format!("mux=1;{WS_CLIENT_OPTS}")),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(
                matches!(outcome, Roundtrip::Reachable { .. }),
                "mux=1 on both ends must still tunnel (control): {outcome:?}"
            );

            let (svr, _h) =
                start_real_ss_server_with_plugin_ws_opts(TEST_METHOD, TEST_PASSWORD, &g, &server_opts).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            // The teardown here is slower than the default read budget: the server
            // stops reading without closing, and the close only follows once the
            // keepalive errors the poisoned pipe — see
            // CONTRIBUTING.md#galoshes-mux-default. Outlive that bound so the
            // assertion observes the teardown instead of racing it.
            let config = RoundtripConfig {
                read_timeout: Duration::from_secs(90),
                ..RoundtripConfig::default()
            };
            let outcome = run_roundtrip(
                &g,
                Some(WS_CLIENT_OPTS),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &config,
            )
            .await;
            // ReadTimeout is excluded on purpose: it is the driver's transient
            // signal, so accepting it would let a slow-but-working tunnel stand in
            // for the break this test exists to prove.
            let Roundtrip::NotReachable { kind, detail } = &outcome else {
                panic!("a mux=0 client must NOT reach a mux=1 server: {outcome:?}");
            };
            assert!(
                matches!(kind, NotReachableKind::PeerClosed),
                "mux mismatch must tear the connection down, got {kind:?}: {detail}"
            );
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

    /// ex-ray client built by `cargo xtask ex-ray`. The ECH fail-closed gate
    /// lives in ex-ray's own client TLS dial paths, so both ends are ex-ray.
    #[cfg(not(target_os = "windows"))]
    fn require_ex_ray() -> String {
        let p = locate_ex_ray();
        require_binary(&p, "run `cargo xtask ex-ray`");
        p.to_str().expect("ex-ray path is valid utf-8").to_string()
    }

    /// Closed-port DoH source: an immediate ECONNREFUSED makes the ECH fetch fail
    /// without network, so ech=always has no config to satisfy it. The refusal is
    /// on the connect result, not a timeout.
    #[cfg(not(target_os = "windows"))]
    const UNREACHABLE_ECH_DOH: &str = "ech-doh=https://127.0.0.1:1/dns-query";

    /// Assert an ech=always run failed closed by the gate, not a transient. The
    /// gate refuses the upstream TLS dial pre-handshake, so the client plugin
    /// closes the local link before any reply — the `PeerClosed` disposition,
    /// covering both the FIN (EOF) and RST (connection reset) teardown races. A
    /// read-timeout transient is its own `ReadTimeout` kind and must NOT satisfy
    /// this; a working tunnel would be `Reachable`, never this arm.
    #[cfg(not(target_os = "windows"))]
    fn assert_gate_refusal(outcome: &Roundtrip) {
        let Roundtrip::NotReachable { kind, detail } = outcome else {
            panic!("ech=always + unreachable ech-doh must fail closed (refuse the tunnel), got {outcome:?}");
        };
        assert!(
            matches!(kind, NotReachableKind::PeerClosed),
            "fail-closed refusal must be the peer-closed-pre-reply disposition (not a timeout/transient), got {kind:?}: {detail}"
        );
    }

    /// ECH fail-closed over WS-TLS (off Windows — see file header). ech=always +
    /// an unobtainable ECH config must refuse the dial BEFORE any ClientHello, so
    /// the real SNI never reaches the wire. The ech=auto control (same closed DoH)
    /// stays Reachable, proving the refusal is the always fail-closed gate, not
    /// generic breakage from the closed port.
    #[cfg(not(target_os = "windows"))]
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn ech_always_ws_tls_fails_closed() {
        let ex_ray = require_ex_ray();
        rt().block_on(async {
            let certs = generate_test_certs();
            let cert = path_for_plugin_opts(&certs.cert_path);

            let (svr, _h) = start_real_ss_server_with_plugin_ws_tls(TEST_METHOD, TEST_PASSWORD, &ex_ray, &certs).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let opts = format!("host=cloudfront.com;path=/;tls;cert={cert};ech=always;{UNREACHABLE_ECH_DOH}");
            let outcome = run_roundtrip(
                &ex_ray,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert_gate_refusal(&outcome);

            // Negative control: ech=auto (closed DoH unchanged) must still tunnel.
            let (svr, _h) = start_real_ss_server_with_plugin_ws_tls(TEST_METHOD, TEST_PASSWORD, &ex_ray, &certs).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let opts = format!("host=cloudfront.com;path=/;tls;cert={cert};ech=auto;{UNREACHABLE_ECH_DOH}");
            let outcome = run_roundtrip(
                &ex_ray,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(
                matches!(outcome, Roundtrip::Reachable { .. }),
                "ech=auto control: {outcome:?}"
            );
        });
    }

    /// ECH fail-closed over QUIC (off Windows — see file header). QUIC's client
    /// dial path also routes through GetTLSConfigForClient, so the same
    /// always/auto contract holds as for WS-TLS above.
    #[cfg(not(target_os = "windows"))]
    #[skuld::test(labels = [PORT_ALLOC], serial = PORT_ALLOC)]
    fn ech_always_quic_fails_closed() {
        let ex_ray = require_ex_ray();
        rt().block_on(async {
            let certs = generate_test_certs();
            let cert = path_for_plugin_opts(&certs.cert_path);

            let (svr, _h) = start_real_ss_server_with_plugin_quic(TEST_METHOD, TEST_PASSWORD, &ex_ray, &certs).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let opts = format!("host=cloudfront.com;mode=quic;cert={cert};ech=always;{UNREACHABLE_ECH_DOH}");
            let outcome = run_roundtrip(
                &ex_ray,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert_gate_refusal(&outcome);

            let (svr, _h) = start_real_ss_server_with_plugin_quic(TEST_METHOD, TEST_PASSWORD, &ex_ray, &certs).await;
            let (sentinel, _s) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
            let opts = format!("host=cloudfront.com;mode=quic;cert={cert};ech=auto;{UNREACHABLE_ECH_DOH}");
            let outcome = run_roundtrip(
                &ex_ray,
                Some(&opts),
                &svr.ip().to_string(),
                svr.port(),
                TEST_METHOD,
                TEST_PASSWORD,
                sentinel,
                &RoundtripConfig::default(),
            )
            .await;
            assert!(
                matches!(outcome, Roundtrip::Reachable { .. }),
                "quic ech=auto control: {outcome:?}"
            );
        });
    }
}
