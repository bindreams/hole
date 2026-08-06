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
const CONNECT_DEADLINE: Duration = Duration::from_secs(3); // TCP connect (DNS resolve precedes it)
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

pub(crate) enum ProbeTransport {
    TlsWs { sni: String },
    PlainWs { host: String, path: String },
    Quic { sni: String },
    Raw,
}

/// Mirrors vendored v2ray-core's `websocket.Config::GetNormalizedPath`
/// (`crates/ex-ray/third_party/v2ray-core/transport/internet/websocket/config.go`)
/// byte for byte: this is what actually decides the WebSocket
/// request-target on the wire, applied unconditionally to whatever the
/// `path` SIP003 flag decoded to.
fn normalize_ws_path(path: String) -> String {
    if path.is_empty() {
        "/".into()
    } else if !path.starts_with('/') {
        format!("/{path}")
    } else {
        path
    }
}

pub(crate) fn classify_transport(
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
    server_host: &str,
) -> Result<ProbeTransport, garter::MalformedOptions> {
    if plugin.is_none() {
        return Ok(ProbeTransport::Raw);
    }
    // `split_plugin_options`, not `parse_plugin_options`: the latter maps a
    // bare key and an explicit `key=` to the same decoded `""`, but ex-ray's
    // own `Args.Get`/`main.go` do NOT treat them the same for `path` (see
    // below) — only `OptionSegment::raw` can tell bare from valued apart.
    let segments = plugin_opts
        .map(garter::split_plugin_options)
        .transpose()?
        .unwrap_or_default();
    let get = |k: &str| segments.iter().find(|s| s.key == k).map(|s| s.value.clone());
    let has = |k: &str| segments.iter().any(|s| s.key == k);
    // The probe's first-flight SNI/Host is the connect target (the DoH-resolved
    // IP — IP-SNI): a failure-only diagnostic must not emit the domain in
    // cleartext, and the real tunnel hides it via ECH, so a domain-SNI probe
    // would test a path the client never uses.
    let sni = server_host.to_string();
    if get("mode").as_deref() == Some("quic") {
        return Ok(ProbeTransport::Quic { sni });
    }
    if has("tls") {
        return Ok(ProbeTransport::TlsWs { sni });
    }
    Ok(ProbeTransport::PlainWs {
        host: sni,
        // Mirrors what ex-ray actually puts on the wire, not a plausible
        // guess. Two layers: (1) the flag value itself — an ABSENT `path`
        // key uses the flag default "/"; a BARE `path` key (no `=`) decodes
        // as "1" (`Args.Add` stores "1" for a no-equals option, args.go +
        // main.go:70); an explicit `path=` decodes as "" — then (2)
        // `normalize_ws_path` (above) applies vendored v2ray-core's own
        // `GetNormalizedPath` rule. Skipping layer 2 would probe a path
        // ex-ray never requests — for `path=` specifically, an unnormalized
        // "" is a syntactically invalid empty request-target, not merely a
        // different one — misreading a routed server as network-blocked.
        path: normalize_ws_path(match segments.iter().find(|s| s.key == "path") {
            None => "/".into(),
            Some(s) if !s.raw.contains('=') => "1".to_string(),
            Some(s) => s.value.clone(),
        }),
    })
}

pub async fn probe_server_reachability(
    host: &str,
    port: u16,
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
    cancel: &CancellationToken,
) -> ReachabilityVerdict {
    // A malformed options string means the transport can't be classified,
    // and guessing wrong in either direction (TCP vs UDP) produces an
    // actively false confident verdict — unlike `server_endpoint_is_udp`'s
    // preflight-skip decision, there is no safe default transport to probe
    // with here, so this best-effort diagnostic reports Inconclusive.
    //
    // Every current caller already validates `plugin_opts` before reaching
    // here, so this path is not exercised today. Left as a graceful
    // `Result`, not an assertion: this function's whole existence is a
    // best-effort diagnostic, and if the two validators
    // (`inject_plugin_directives` and `classify_transport`, independent
    // call sites both wrapping `garter::split_plugin_options`) ever
    // silently diverge, Inconclusive is the correct degraded behavior
    // here, not a panic.
    let transport = match classify_transport(plugin, plugin_opts, host) {
        Ok(t) => t,
        Err(e) => {
            debug!(%e, "malformed SS_PLUGIN_OPTIONS in reachability probe");
            return ReachabilityVerdict::Inconclusive;
        }
    };
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
    let stream = match resolve_and_connect(host, port, CONNECT_DEADLINE).await {
        ConnectResult::Connected(s) => s,
        ConnectResult::DnsFailed => return ReachabilityVerdict::DnsFailed,
        ConnectResult::Refused => return ReachabilityVerdict::TcpRefused,
        ConnectResult::Timeout => return ReachabilityVerdict::TcpTimeout,
    };
    match transport {
        ProbeTransport::Raw => ReachabilityVerdict::Reachable,
        ProbeTransport::PlainWs { host, path } => first_flight_http(stream, host, path).await,
        ProbeTransport::TlsWs { sni } => first_flight_tls(stream, sni).await,
        ProbeTransport::Quic { .. } => unreachable!(),
    }
}

/// Outcome of [`resolve_and_connect`], shared by the reachability probe and the
/// server-test preflight so both classify a connect the same way.
pub(crate) enum ConnectResult {
    Connected(TcpStream),
    DnsFailed,
    Refused,
    Timeout,
}

/// Resolve (when `host` is not a literal IP) then TCP-connect within `deadline`.
/// A resolve miss is [`ConnectResult::DnsFailed`]; a `ConnectionRefused` is
/// [`ConnectResult::Refused`]; an elapsed `deadline` or any other connect error
/// is [`ConnectResult::Timeout`]; success carries the stream.
pub(crate) async fn resolve_and_connect(host: &str, port: u16, deadline: Duration) -> ConnectResult {
    if host.parse::<IpAddr>().is_err() {
        let resolved = match lookup_host((host, port)).await {
            Ok(mut it) => it.next().is_some(),
            Err(_) => false,
        };
        if !resolved {
            return ConnectResult::DnsFailed;
        }
    }
    match tokio::time::timeout(deadline, TcpStream::connect((host, port))).await {
        Err(_) => ConnectResult::Timeout,
        Ok(Ok(s)) => ConnectResult::Connected(s),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => ConnectResult::Refused,
        Ok(Err(_)) => ConnectResult::Timeout,
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
    // QUIC needs TLS 1.3 + h3 ALPN.
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
    // `Drop` owns endpoint teardown.
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
