//! Out-of-band server reachability probe — distinguishes a network-blocked /
//! reset server from a credential/config failure.
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{lookup_host, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::debug;

// Per-phase budgets bound the total while preserving the connect-vs-first-flight
// verdict split: a connect timeout stays `TcpTimeout` (a closed-port SYN-drop),
// a first-flight no-response stays `Blocked` (a real block). One outer timeout
// would conflate them. Non-QUIC worst case ≈ CONNECT_DEADLINE + FIRSTFLIGHT_DEADLINE = 6s.
const CONNECT_DEADLINE: Duration = Duration::from_secs(3); // DNS resolve + TCP connect
const FIRSTFLIGHT_DEADLINE: Duration = Duration::from_secs(3); // TLS/HTTP first-flight read
const QUIC_DEADLINE: Duration = Duration::from_secs(6); // whole quinn connect

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityVerdict {
    Reachable,
    DnsFailed,
    TcpRefused,
    TcpTimeout,
    Blocked,
    Inconclusive,
}

impl ReachabilityVerdict {
    /// Host/IP-free toast text; `None` means "do not override the existing reason".
    pub fn user_message(&self) -> Option<&'static str> {
        match self {
            ReachabilityVerdict::Blocked => Some(hole_common::protocol::NETWORK_BLOCKED_MESSAGE),
            ReachabilityVerdict::TcpRefused => Some("The server refused the connection."),
            ReachabilityVerdict::TcpTimeout => Some("The server did not respond (connection timed out)."),
            _ => None,
        }
    }
}

enum ProbeTransport {
    TlsWs { sni: String },
    PlainWs { host: String, path: String },
    Quic { sni: String },
    Raw,
}

fn classify_transport(plugin: Option<&str>, plugin_opts: Option<&str>, server_host: &str) -> ProbeTransport {
    if plugin.is_none() {
        return ProbeTransport::Raw;
    }
    let opts = plugin_opts.map(garter::parse_plugin_options).unwrap_or_default();
    let get = |k: &str| opts.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
    let has = |k: &str| opts.iter().any(|(kk, _)| kk == k);
    let sni = get("host").unwrap_or_else(|| server_host.to_string());
    if get("mode").as_deref() == Some("quic") {
        return ProbeTransport::Quic { sni };
    }
    if has("tls") {
        return ProbeTransport::TlsWs { sni };
    }
    ProbeTransport::PlainWs {
        host: sni,
        path: get("path").unwrap_or_else(|| "/".into()),
    }
}

pub async fn probe_server_reachability(
    host: &str,
    port: u16,
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
    cancel: &CancellationToken,
) -> ReachabilityVerdict {
    let transport = classify_transport(plugin, plugin_opts, host);
    let v = tokio::select! {
        _ = cancel.cancelled() => ReachabilityVerdict::Inconclusive,
        v = probe_inner(host, port, &transport) => v,
    };
    debug!(host, port, ?v, "reachability probe");
    v
}

async fn probe_inner(host: &str, port: u16, transport: &ProbeTransport) -> ReachabilityVerdict {
    if let ProbeTransport::Quic { sni } = transport {
        return probe_quic(host, port, sni).await;
    }
    // Bound DNS resolve + TCP connect together so the slow-DNS case stays inside
    // CONNECT_DEADLINE.
    let stream = match tokio::time::timeout(CONNECT_DEADLINE, connect_tcp(host, port)).await {
        Err(_) => return ReachabilityVerdict::TcpTimeout, // connect-phase deadline elapsed
        Ok(Err(v)) => return v,                           // DnsFailed / TcpRefused / TcpTimeout
        Ok(Ok(s)) => s,
    };
    match transport {
        ProbeTransport::Raw => ReachabilityVerdict::Reachable,
        ProbeTransport::PlainWs { host, path } => first_flight_http(stream, host, path).await,
        ProbeTransport::TlsWs { sni } => first_flight_tls(stream, sni).await,
        ProbeTransport::Quic { .. } => unreachable!(),
    }
}

/// Resolve (if `host` is not a literal IP) then TCP-connect. `Err` carries the
/// terminal verdict (`DnsFailed`/`TcpRefused`/`TcpTimeout`); the caller bounds
/// the whole thing with `CONNECT_DEADLINE`.
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, ReachabilityVerdict> {
    if host.parse::<IpAddr>().is_err() {
        let resolved = match lookup_host((host, port)).await {
            Ok(mut it) => it.next().is_some(),
            Err(_) => false,
        };
        if !resolved {
            return Err(ReachabilityVerdict::DnsFailed);
        }
    }
    match TcpStream::connect((host, port)).await {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Err(ReachabilityVerdict::TcpRefused),
        Err(_) => Err(ReachabilityVerdict::TcpTimeout),
    }
}

/// Send the WS-upgrade GET; any bytes back ⇒ Reachable; zero bytes (reset / timeout
/// / clean EOF / write error) ⇒ Blocked.
async fn first_flight_http(mut s: TcpStream, host: &str, path: &str) -> ReachabilityVerdict {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return ReachabilityVerdict::Blocked;
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(FIRSTFLIGHT_DEADLINE, s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ReachabilityVerdict::Reachable,
        _ => ReachabilityVerdict::Blocked, // Ok(Ok(0)) clean EOF, Ok(Err) reset, Err timeout
    }
}

/// Drive a no-verify TLS handshake; handshake completes OR any server byte arrives
/// ⇒ Reachable; reset / timeout / clean-EOF with zero bytes ⇒ Blocked.
async fn first_flight_tls(stream: TcpStream, sni: &str) -> ReachabilityVerdict {
    use rustls::pki_types::ServerName;
    let saw = Arc::new(AtomicBool::new(false));
    let sniffed = ByteSniff {
        inner: stream,
        saw: saw.clone(),
    };
    // `ServerName::try_from(String)` parses a DNS name and falls back to an IP
    // literal, so a manual IP arm would be dead.
    let name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => {
            debug!(%e, sni, "reachability probe: unparseable SNI");
            return ReachabilityVerdict::Inconclusive;
        }
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(no_verify_tls_config(vec![b"http/1.1".to_vec()])));
    match tokio::time::timeout(FIRSTFLIGHT_DEADLINE, connector.connect(name, sniffed)).await {
        Ok(Ok(_)) => ReachabilityVerdict::Reachable,
        _ if saw.load(Ordering::SeqCst) => ReachabilityVerdict::Reachable,
        _ => ReachabilityVerdict::Blocked,
    }
}

/// No-verify rustls client config (ring provider), used by the TLS probe.
/// `alpn` lets the QUIC probe request `h3` instead of `http/1.1`.
pub(crate) fn no_verify_tls_config(alpn: Vec<Vec<u8>>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports default versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    cfg
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer,
        _i: &[rustls::pki_types::CertificateDer],
        _s: &rustls::pki_types::ServerName,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Flips `saw` when any non-empty read completes, so the TLS probe can tell
/// "server answered" from "reset before any byte".
struct ByteSniff<S> {
    inner: S,
    saw: Arc<AtomicBool>,
}
impl<S: AsyncRead + Unpin> AsyncRead for ByteSniff<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let pre = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            if buf.filled().len() > pre {
                self.saw.store(true, Ordering::SeqCst);
            }
        }
        r
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ByteSniff<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Drive a no-verify QUIC handshake. Any peer response (handshake or a peer-origin
/// `ConnectionError`) ⇒ Reachable; a local-only failure ⇒ Inconclusive; timeout /
/// silence ⇒ Blocked. The match arms below enumerate each variant.
async fn probe_quic(host: &str, port: u16, sni: &str) -> ReachabilityVerdict {
    use quinn::{ClientConfig, ConnectionError, Endpoint};
    let addr = match lookup_host((host, port)).await {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return ReachabilityVerdict::DnsFailed,
        },
        Err(_) => return ReachabilityVerdict::DnsFailed,
    };
    // Bind the endpoint to the remote's family: quinn rejects a v6 remote on a v4
    // endpoint, and a wildcard-v6 socket isn't reliably dual-stack on Windows.
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let mut ep = match Endpoint::client(bind.parse().unwrap()) {
        Ok(e) => e,
        Err(e) => {
            debug!(%e, "quic probe: endpoint bind failed");
            return ReachabilityVerdict::Inconclusive;
        }
    };
    // QUIC needs TLS 1.3 (the default protocol versions include it) + h3 ALPN.
    let tls = no_verify_tls_config(vec![b"h3".to_vec()]);
    let qcc = match quinn::crypto::rustls::QuicClientConfig::try_from(tls) {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "quic probe: client config failed");
            return ReachabilityVerdict::Inconclusive;
        }
    };
    ep.set_default_client_config(ClientConfig::new(Arc::new(qcc)));
    let connecting = match ep.connect(addr, sni) {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "quic probe: connect setup failed");
            return ReachabilityVerdict::Inconclusive;
        }
    };
    // `Drop` owns endpoint teardown; no explicit `ep.close()` on any exit.
    match tokio::time::timeout(QUIC_DEADLINE, connecting).await {
        Ok(Ok(_)) => ReachabilityVerdict::Reachable, // handshake completed
        Ok(Err(ConnectionError::TimedOut)) => ReachabilityVerdict::Blocked, // no response
        Ok(Err(ConnectionError::LocallyClosed | ConnectionError::CidsExhausted)) => ReachabilityVerdict::Inconclusive, // local-only failure
        Ok(Err(_)) => ReachabilityVerdict::Reachable, // VersionMismatch/TransportError/(Application|Connection)Closed/Reset: peer answered
        Err(_) => ReachabilityVerdict::Blocked,       // outer deadline elapsed
    }
}

#[cfg(test)]
#[path = "reachability_tests.rs"]
mod reachability_tests;
