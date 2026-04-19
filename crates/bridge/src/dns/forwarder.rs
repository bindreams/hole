//! `DnsForwarder` — pure-bytes DNS forwarding over one of four upstream
//! transports. Preserves the client's transaction ID so it can serve as a
//! drop-in forwarder for both `LocalDnsServer` (sub-step e) and
//! `LocalDnsEndpoint` (sub-step f).
//!
//! Serving strategy: walk `DnsConfig.servers` in order, try each with the
//! configured `DnsProtocol`, return the first successful reply. Return a
//! synthesized SERVFAIL if every server fails.
//!
//! IPv6 server entries are skipped (with a deduplicated WARN) when the
//! upstream interface has no IPv6 connectivity — matches the spec in the
//! plan.

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hole_common::config::{DnsConfig, DnsProtocol};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::dns::connector::UpstreamConnector;
use crate::dns::providers;

/// Upstream port for plain DNS (RFC 1035) and DoT (RFC 7858).
const DNS_PORT_PLAIN: u16 = 53;
const DNS_PORT_TLS: u16 = 853;
/// DoH typically runs on 443 (RFC 8484 §3).
const DNS_PORT_HTTPS: u16 = 443;

/// Per-upstream attempt timeout. Shorter than the OS default TCP timeout
/// so a dead server doesn't stall the whole forward loop.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum reply size we'll buffer (bytes). DNS messages cap around 65535
/// but we cap even tighter — DoH servers never return more than ~8KB in
/// practice, and this prevents a malicious upstream from flooding RAM.
const MAX_REPLY_SIZE: usize = 16 * 1024;

/// SERVFAIL rcode per RFC 1035 §4.1.1.
const RCODE_SERVFAIL: u8 = 2;

// Public API ==========================================================================================================

pub struct DnsForwarder {
    config: DnsConfig,
    connector: Arc<dyn UpstreamConnector>,
    tls_config: Arc<ClientConfig>,
    ipv6_bypass_available: bool,
    /// Dedup state for per-server WARN log lines. Held in a `std::Mutex`
    /// (never across an `await`) — each forward() call either hits or
    /// misses the set and moves on.
    logged_servers: Mutex<HashSet<IpAddr>>,
}

impl DnsForwarder {
    /// Construct a forwarder. `ipv6_bypass_available` reflects whether the
    /// upstream interface has IPv6 connectivity — matches the value used
    /// by the `InterfaceEndpoint` cascade in `hole_router`.
    pub fn new(config: DnsConfig, connector: Arc<dyn UpstreamConnector>, ipv6_bypass_available: bool) -> Self {
        let tls_config = Arc::new(build_tls_config());
        Self {
            config,
            connector,
            tls_config,
            ipv6_bypass_available,
            logged_servers: Mutex::new(HashSet::new()),
        }
    }

    /// Forward a wire-format DNS query. Returns wire-format reply bytes.
    /// Never errors — on total failure returns a synthesized SERVFAIL so
    /// the caller can always write a reply back.
    pub async fn forward(&self, query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return synthesize_servfail(query);
        }

        for &server in &self.config.servers {
            if server.is_ipv6() && !self.ipv6_bypass_available {
                self.log_once(server, "skipping IPv6 upstream (no IPv6 bypass available)");
                continue;
            }

            match self.forward_one(server, query).await {
                Ok(reply) => return reply,
                Err(e) => {
                    self.log_once(server, &format!("upstream failed: {e}"));
                }
            }
        }

        synthesize_servfail(query)
    }

    async fn forward_one(&self, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let fut = async {
            match self.config.protocol {
                DnsProtocol::PlainUdp => self.forward_udp(server, query).await,
                DnsProtocol::PlainTcp => self.forward_tcp(server, query).await,
                DnsProtocol::Tls => self.forward_tls(server, query).await,
                DnsProtocol::Https => self.forward_https(server, query).await,
            }
        };
        match timeout(UPSTREAM_TIMEOUT, fut).await {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "upstream timeout")),
        }
    }

    fn log_once(&self, server: IpAddr, msg: &str) {
        let mut set = self.logged_servers.lock().expect("poisoned");
        if set.insert(server) {
            tracing::warn!(%server, protocol = ?self.config.protocol, "{msg}");
        }
    }
}

// Transport: plain UDP ================================================================================================

impl DnsForwarder {
    async fn forward_udp(&self, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let target = SocketAddr::new(server, DNS_PORT_PLAIN);
        let socket = self.connector.connect_udp(target).await?;
        socket.send(query).await?;
        let mut buf = vec![0u8; MAX_REPLY_SIZE];
        let n = socket.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }
}

// Transport: plain TCP ================================================================================================

impl DnsForwarder {
    async fn forward_tcp(&self, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let target = SocketAddr::new(server, DNS_PORT_PLAIN);
        let stream = self.connector.connect_tcp(target).await?;
        exchange_tcp_framed(stream, query).await
    }
}

// Transport: DoT (TLS over TCP) =======================================================================================

impl DnsForwarder {
    async fn forward_tls(&self, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let target = SocketAddr::new(server, DNS_PORT_TLS);
        let stream = self.connector.connect_tcp(target).await?;
        let server_name = tls_server_name_for(server)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let tls = connector.connect(server_name, stream).await?;
        exchange_tcp_framed(tls, query).await
    }
}

// Transport: DoH (HTTP/1.1 over TLS) ==================================================================================

impl DnsForwarder {
    async fn forward_https(&self, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let target = SocketAddr::new(server, DNS_PORT_HTTPS);
        let (server_name, path_and_host) = https_target_for(server)?;
        let stream = self.connector.connect_tcp(target).await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let mut tls = connector.connect(server_name, stream).await?;

        let (host, path) = path_and_host;
        let mut req = Vec::with_capacity(256 + query.len());
        write!(
            req,
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: hole-bridge/dns-forwarder\r\n\
             Accept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n",
            len = query.len()
        )
        .unwrap();
        req.extend_from_slice(query);

        tls.write_all(&req).await?;
        tls.flush().await?;

        let mut resp = Vec::with_capacity(4096);
        // Cap reads so a misbehaving server can't OOM us.
        tls.take((MAX_REPLY_SIZE * 4) as u64).read_to_end(&mut resp).await?;

        parse_http_dns_response(&resp)
    }
}

// Helpers =============================================================================================================

/// Send `query` prefixed with its 16-bit big-endian length, read the
/// same-shaped reply. Used by both plain TCP and DoT transports.
async fn exchange_tcp_framed<S>(mut stream: S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let len = u16::try_from(query.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too large"))?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    if reply_len > MAX_REPLY_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply too large"));
    }
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// Select the TLS `ServerName` for a given upstream IP. Known providers
/// use their hostname (so DNS-validated certs work); unknown IPs fall back
/// to IP-SAN verification.
fn tls_server_name_for(server: IpAddr) -> io::Result<ServerName<'static>> {
    if let Some(p) = providers::lookup(server) {
        ServerName::try_from(p.tls_dns_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid SNI: {e}")))
    } else {
        Ok(ServerName::IpAddress(server.into()))
    }
}

/// Return `(ServerName, (Host-header, Path))` for a DoH request to
/// `server`. Host + path come from the known-provider table, or from the
/// literal IP + `/dns-query` path for unknown servers.
fn https_target_for(server: IpAddr) -> io::Result<(ServerName<'static>, (String, String))> {
    if let Some(p) = providers::lookup(server) {
        let url = p.doh_url;
        let (host, path) = split_https_url(url)?;
        let name = ServerName::try_from(host.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid SNI: {e}")))?
            .to_owned();
        Ok((name, (host, path)))
    } else {
        let host = match server {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        Ok((ServerName::IpAddress(server.into()), (host, "/dns-query".into())))
    }
}

fn split_https_url(url: &str) -> io::Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "doh url missing https://"))?;
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h.to_string(), format!("/{p}")))
        .unwrap_or_else(|| (rest.to_string(), "/".to_string()));
    Ok((host, path))
}

fn build_tls_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Use the explicit `ring` provider. rustls 0.23 removed the implicit
    // global default; builder() panics when multiple/zero crypto providers
    // are feature-enabled and none is globally installed. We feature-gate
    // `ring` via workspace deps, so pass it directly.
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // DoH requires ALPN "h2" per RFC 8484, but we send HTTP/1.1 so list
    // "http/1.1" first. Some providers (notably Google) reject unknown ALPN
    // lists — http/1.1 is universally accepted.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Parse a minimal HTTP/1.1 response: `HTTP/1.1 200 ...\r\n` + headers +
/// `\r\n\r\n` + body. Requires Content-Length (chunked encoding not
/// supported — every DoH server we talk to emits a discrete fixed-length
/// reply).
fn parse_http_dns_response(resp: &[u8]) -> io::Result<Vec<u8>> {
    let body_sep =
        find_double_crlf(resp).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header/body separator"))?;
    let head = &resp[..body_sep];
    let body = &resp[body_sep + 4..];

    let head_str =
        std::str::from_utf8(head).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 response head"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let _ver = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status code"))?;
    if code != "200" {
        return Err(io::Error::other(format!("non-200 DoH response: {status_line}")));
    }

    let mut content_length: Option<usize> = None;
    let mut content_type: Option<&str> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "content-length" => content_length = v.parse().ok(),
                "content-type" => content_type = Some(v),
                _ => {}
            }
        }
    }

    if let Some(ct) = content_type {
        if !ct.eq_ignore_ascii_case("application/dns-message") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected Content-Type: {ct}"),
            ));
        }
    }

    let n = content_length.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
    if n > MAX_REPLY_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply too large"));
    }
    if body.len() < n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short DoH body"));
    }
    Ok(body[..n].to_vec())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    const NEEDLE: &[u8] = b"\r\n\r\n";
    buf.windows(NEEDLE.len()).position(|w| w == NEEDLE)
}

/// Build a SERVFAIL response from an incoming query. Preserves the
/// transaction ID, question section, and QDCOUNT; zeros all
/// answer/authority/additional counts; sets QR=1, RA=1, RCODE=2.
pub fn synthesize_servfail(query: &[u8]) -> Vec<u8> {
    // DNS header is 12 bytes: ID(2) | flags(2) | QDCOUNT(2) | ANCOUNT(2) |
    // NSCOUNT(2) | ARCOUNT(2). If the query is shorter than that, we can
    // still emit a minimal SERVFAIL header.
    let mut reply = Vec::with_capacity(query.len().max(12));
    // Preserve transaction ID (first 2 bytes) when present.
    if query.len() >= 2 {
        reply.extend_from_slice(&query[..2]);
    } else {
        reply.extend_from_slice(&[0, 0]);
    }
    // Flags: QR=1, OPCODE mirrored, AA=0, TC=0, RD mirrored, RA=1,
    // Z=0, RCODE=2 (SERVFAIL).
    let (opcode_rd, _) = if query.len() >= 4 {
        (query[2] & 0b0111_1001, query[3])
    } else {
        (0, 0)
    };
    // Byte 2: QR(1) OPCODE(4) AA(1) TC(1) RD(1)
    reply.push(0b1000_0000 | opcode_rd);
    // Byte 3: RA(1) Z(3) RCODE(4)
    reply.push(0b1000_0000 | (RCODE_SERVFAIL & 0x0F));
    // QDCOUNT preserved when present, else 0.
    let qdcount = if query.len() >= 6 { [query[4], query[5]] } else { [0, 0] };
    reply.extend_from_slice(&qdcount);
    // Zero ANCOUNT / NSCOUNT / ARCOUNT.
    reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // Copy question section if present (everything after the 12-byte
    // header up to the end of question, identified by the first 0 label +
    // 4 bytes of qtype/qclass). Safe fallback: copy the rest of the query
    // verbatim if we can't find the question terminator.
    if query.len() > 12 {
        if let Some(qend) = question_end(&query[12..]) {
            reply.extend_from_slice(&query[12..12 + qend]);
        }
    }
    reply
}

/// Find the end of the first question section relative to the question
/// start. Returns `None` on malformed input.
fn question_end(q: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        let len = *q.get(i)? as usize;
        if len == 0 {
            // The 0-byte label-terminator, followed by qtype(2) + qclass(2).
            return Some(i + 1 + 4);
        }
        if len & 0xC0 != 0 {
            // Compression pointer in a QNAME isn't valid per RFC 1035,
            // but tolerate it: the pointer is 2 bytes total.
            return Some(i + 2 + 4);
        }
        i += 1 + len;
        if i >= q.len() {
            return None;
        }
    }
}

#[cfg(test)]
#[path = "forwarder_tests.rs"]
mod forwarder_tests;
