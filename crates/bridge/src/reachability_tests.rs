// Sanctioned per-test CancellationToken::new (no caller-side token in unit fixtures). See clippy.toml.
#![allow(clippy::disallowed_methods)]
use super::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// Fixture: accept then drop (RST / FIN with zero app bytes).
async fn accept_then_reset() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s);
        }
    });
    addr
}
// After writing the reply we drain to EOF instead of dropping the socket: on
// Windows, closing a TCP stream that still holds unread bytes (the rest of the
// client's first-flight that we didn't read) emits an RST that discards the
// reply we just wrote, which the probe would then misread as Blocked. Draining
// until the peer closes lets the reply land first — no timer, pure rendezvous.
async fn accept_then_answer() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await; // wait for ClientHello / GET first-flight
            let _ = s.write_all(b"\x15\x03\x03\x00\x02\x02\x28").await; // bytes came back
            let mut drain = [0u8; 256];
            while let Ok(n) = s.read(&mut drain).await {
                if n == 0 {
                    break; // peer closed: reply has been delivered
                }
            }
        }
    });
    addr
}

// All tests use `#[skuld::test]` (incl. the sync classifier ones): this crate
// runs a custom skuld harness (`harness = false`) that collects only
// `#[skuld::test]` functions — plain `#[test]` ones are silently never run.
// Each carries an explicit `name = "reachability_tests::…"`: skuld reports the
// bare fn ident as the test name (no module prefix), so the documented
// `nextest run … reachability_tests` substring filter only matches with it.
#[skuld::test(name = "reachability_tests::classify_no_plugin_is_raw")]
fn classify_no_plugin_is_raw() {
    assert!(matches!(classify_transport(None, None, "ex.com"), ProbeTransport::Raw));
}
#[skuld::test(name = "reachability_tests::classify_tls_ws_uses_host_as_sni")]
fn classify_tls_ws_uses_host_as_sni() {
    assert!(
        matches!(classify_transport(Some("galoshes"), Some("tls;path=/t/x;host=h.ex.com"), "srv"),
        ProbeTransport::TlsWs { sni } if sni == "h.ex.com")
    );
}
#[skuld::test(name = "reachability_tests::classify_plain_ws_defaults_path_and_host")]
fn classify_plain_ws_defaults_path_and_host() {
    match classify_transport(Some("galoshes"), Some("path=/t/x"), "srv.ex.com") {
        ProbeTransport::PlainWs { host, path } => {
            assert_eq!(host, "srv.ex.com");
            assert_eq!(path, "/t/x");
        }
        _ => panic!(),
    }
}
#[skuld::test(name = "reachability_tests::classify_quic_forces_quic")]
fn classify_quic_forces_quic() {
    assert!(
        matches!(classify_transport(Some("galoshes"), Some("mode=quic;host=h"), "srv"),
        ProbeTransport::Quic { sni } if sni == "h")
    );
}
#[skuld::test(name = "reachability_tests::user_message_is_host_free")]
fn user_message_is_host_free() {
    let m = ReachabilityVerdict::Blocked.user_message().unwrap();
    assert!(m.contains("firewall or censorship"));
    assert!(ReachabilityVerdict::Reachable.user_message().is_none());
}

#[skuld::test(name = "reachability_tests::plain_ws_reset_is_blocked")]
async fn plain_ws_reset_is_blocked() {
    let a = accept_then_reset().await;
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("path=/x"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Blocked
    );
}
#[skuld::test(name = "reachability_tests::plain_ws_answered_is_reachable")]
async fn plain_ws_answered_is_reachable() {
    let a = accept_then_answer().await;
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("path=/x"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Reachable
    );
}
#[skuld::test(name = "reachability_tests::tls_ws_bytes_back_is_reachable")]
async fn tls_ws_bytes_back_is_reachable() {
    let a = accept_then_answer().await;
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Reachable
    );
}
#[skuld::test(name = "reachability_tests::tls_ws_reset_is_blocked")]
async fn tls_ws_reset_is_blocked() {
    let a = accept_then_reset().await;
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Blocked
    );
}
#[skuld::test(name = "reachability_tests::closed_port_is_refused_or_timeout")]
async fn closed_port_is_refused_or_timeout() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    let v = probe_server_reachability(&a.ip().to_string(), a.port(), None, None, &CancellationToken::new()).await;
    // Non-Windows kernels RST a closed port (TcpRefused); Windows GitHub runners
    // drop inbound SYNs to closed ephemeral loopback ports → TcpTimeout. Both are
    // correct "port is closed" verdicts. Mirrors server_test_tests.rs preflight.
    if cfg!(target_os = "windows") {
        assert!(
            matches!(v, ReachabilityVerdict::TcpRefused | ReachabilityVerdict::TcpTimeout),
            "expected TcpRefused or TcpTimeout on Windows, got {v:?}"
        );
    } else {
        assert!(
            matches!(v, ReachabilityVerdict::TcpRefused),
            "expected TcpRefused, got {v:?}"
        );
    }
}
#[skuld::test(name = "reachability_tests::bogus_host_is_dns_failed")]
async fn bogus_host_is_dns_failed() {
    assert_eq!(
        probe_server_reachability("no-such-host.invalid", 443, None, None, &CancellationToken::new()).await,
        ReachabilityVerdict::DnsFailed
    );
}

// QUIC probe (quinn) ==================================================================================================

// Fixture: a quinn server endpoint with a self-signed cert + `h3` ALPN that
// accepts connections and immediately drops them. The handshake still
// completes (the client sees a peer response), so the probe reports Reachable.
// `bind` selects the family (`127.0.0.1:0` v4 / `[::1]:0` v6). Returns the bound
// UDP address; the endpoint is kept alive by the spawned task owning it.
async fn spawn_quinn_server(bind: &str) -> SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let key_pair = rcgen::KeyPair::generate().expect("rcgen key generation");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("rcgen accepts localhost as a subject name")
        .self_signed(&key_pair)
        .expect("rcgen self-sign");
    let cert_der = CertificateDer::from(cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Explicit ring provider: the workspace rustls is built with
    // `default-features = false`, so there is no installed process-level
    // default `CryptoProvider` for `ServerConfig::builder()` to pick up.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports default versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single-cert server config");
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic server config"),
    ));

    let endpoint = quinn::Endpoint::server(server_config, bind.parse().unwrap()).expect("quinn server endpoint");
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await; // complete the handshake, then drop
            });
        }
    });
    addr
}

#[skuld::test(name = "reachability_tests::quic_silent_udp_is_blocked")]
async fn quic_silent_udp_is_blocked() {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(); // bound, never answers QUIC
    let a = s.local_addr().unwrap();
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("mode=quic;host=h"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Blocked
    );
}
#[skuld::test(name = "reachability_tests::quic_server_is_reachable")]
async fn quic_server_is_reachable() {
    let a = spawn_quinn_server("127.0.0.1:0").await; // rcgen self-signed quinn endpoint that accepts+ignores
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("mode=quic;host=localhost"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Reachable
    );
}
#[skuld::test(name = "reachability_tests::quic_server_v6_is_reachable")]
async fn quic_server_v6_is_reachable() {
    let a = spawn_quinn_server("[::1]:0").await; // IPv6 quinn endpoint — the v4-only-endpoint bug (#580) never probed this
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("mode=quic;host=localhost"),
            &CancellationToken::new()
        )
        .await,
        ReachabilityVerdict::Reachable
    );
}
#[skuld::test(name = "reachability_tests::cancel_against_silent_endpoint_is_inconclusive")]
async fn cancel_against_silent_endpoint_is_inconclusive() {
    // A bound-but-never-answering UDP socket is a black hole: the QUIC probe
    // would otherwise sit until QUIC_DEADLINE. Signalling the token first must
    // short-circuit to Inconclusive via the `cancel.cancelled()` select-arm.
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("mode=quic;host=h"),
            &cancel
        )
        .await,
        ReachabilityVerdict::Inconclusive
    );
}
