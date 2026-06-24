//! Out-of-band server reachability probe — distinguishes a network-blocked /
//! reset server from a credential/config failure. See bindreams/hole#580.
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

pub const PROBE_DEADLINE: Duration = Duration::from_secs(6);

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
            ReachabilityVerdict::Blocked => Some(
                "The network is blocking the connection to this server — the handshake was \
                 reset or got no response. This usually means a firewall or censorship; \
                 try a different server.",
            ),
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
    deadline: Duration,
    cancel: &CancellationToken,
) -> ReachabilityVerdict {
    let transport = classify_transport(plugin, plugin_opts, host);
    let v = tokio::select! {
        _ = cancel.cancelled() => ReachabilityVerdict::Inconclusive,
        v = probe_inner(host, port, &transport, deadline) => v,
    };
    debug!(host, port, ?v, "reachability probe"); // full detail to bridge.log; toast gets only user_message()
    v
}

async fn probe_inner(host: &str, port: u16, transport: &ProbeTransport, deadline: Duration) -> ReachabilityVerdict {
    if let ProbeTransport::Quic { sni } = transport {
        return probe_quic(host, port, sni, deadline).await; // Task 2
    }
    if host.parse::<IpAddr>().is_err() {
        let resolved = match lookup_host((host, port)).await {
            Ok(mut it) => it.next().is_some(),
            Err(_) => false,
        };
        if !resolved {
            return ReachabilityVerdict::DnsFailed;
        }
    }
    let stream = match tokio::time::timeout(deadline, TcpStream::connect((host, port))).await {
        Err(_) => return ReachabilityVerdict::TcpTimeout,
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => return ReachabilityVerdict::TcpRefused,
        Ok(Err(_)) => return ReachabilityVerdict::TcpTimeout,
        Ok(Ok(s)) => s,
    };
    match transport {
        ProbeTransport::Raw => ReachabilityVerdict::Reachable,
        ProbeTransport::PlainWs { host, path } => first_flight_http(stream, host, path, deadline).await,
        ProbeTransport::TlsWs { sni } => first_flight_tls(stream, sni, deadline).await,
        ProbeTransport::Quic { .. } => unreachable!(),
    }
}

/// Send the WS-upgrade GET; any bytes back ⇒ Reachable; zero bytes (reset / timeout
/// / clean EOF / write error) ⇒ Blocked.
async fn first_flight_http(mut s: TcpStream, host: &str, path: &str, deadline: Duration) -> ReachabilityVerdict {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return ReachabilityVerdict::Blocked;
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(deadline, s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ReachabilityVerdict::Reachable,
        _ => ReachabilityVerdict::Blocked, // Ok(Ok(0)) clean EOF, Ok(Err) reset, Err timeout
    }
}

/// Drive a no-verify TLS handshake; handshake completes OR any server byte arrives
/// ⇒ Reachable; reset / timeout / clean-EOF with zero bytes ⇒ Blocked.
async fn first_flight_tls(stream: TcpStream, sni: &str, deadline: Duration) -> ReachabilityVerdict {
    use rustls::pki_types::ServerName;
    let saw = Arc::new(AtomicBool::new(false));
    let sniffed = ByteSniff {
        inner: stream,
        saw: saw.clone(),
    };
    let name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(_) => match sni.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => return ReachabilityVerdict::Inconclusive,
        },
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(no_verify_tls_config(vec![b"http/1.1".to_vec()])));
    match tokio::time::timeout(deadline, connector.connect(name, sniffed)).await {
        Ok(Ok(_)) => ReachabilityVerdict::Reachable,
        _ if saw.load(Ordering::SeqCst) => ReachabilityVerdict::Reachable,
        _ => ReachabilityVerdict::Blocked,
    }
}

/// No-verify rustls client config (ring provider), used by the TLS probe.
/// `alpn` lets the QUIC probe (Task 2) request `h3` instead of `http/1.1`.
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

// Temporary stub so Task 1 compiles; Task 2 replaces it with a real quinn probe.
async fn probe_quic(_: &str, _: u16, _: &str, _: Duration) -> ReachabilityVerdict {
    ReachabilityVerdict::Inconclusive
}

#[cfg(test)]
#[path = "reachability_tests.rs"]
mod reachability_tests;
