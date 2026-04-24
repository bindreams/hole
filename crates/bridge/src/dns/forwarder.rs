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

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hole_common::config::{DnsConfig, DnsProtocol};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::dns::connector::{StreamCounters, UpstreamConnector};
use crate::dns::providers;

// Typed errors ========================================================================================================

/// Which layer of the upstream stack emitted the error. Lets #248
/// observation distinguish SOCKS5-layer failures from TLS handshake
/// failures from mid-stream I/O EOFs from outer-budget timeout
/// cancellation — all of which previously surfaced as a bare `io::Error`
/// with message `"tls handshake eof"` or similar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamLayer {
    /// TCP or UDP connect. For `Socks5Connector`, this includes the
    /// SOCKS5 handshake+CONNECT — those errors come back wrapped inside
    /// an `io::Error`; the source chain reveals the SOCKS5-specific
    /// message. `DirectConnector` failures hit here as
    /// `ConnectionRefused` / timeouts.
    Connect,
    /// TLS handshake (DoT / DoH).
    Tls,
    /// HTTP response parsing (DoH).
    Http,
    /// Post-handshake read / write on the upstream stream.
    Io,
    /// Outer `UPSTREAM_TIMEOUT` budget fired. Distinct from `Io` so
    /// observers can tell "inner future completed with error at 2573ms"
    /// from "outer timer cancelled the future at exactly 3000ms" —
    /// different root causes, different fixes. Ref #248.
    Timeout,
}

impl UpstreamLayer {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Io => "io",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for UpstreamLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Tagged upstream failure: `{ layer, source, elapsed_ms }` plus optional
/// diagnostic context captured at the point of failure. `io::Error` is
/// `!Clone`, so `UpstreamErr` cannot be `Clone` — consumed once on the
/// log path.
#[derive(Debug)]
pub struct UpstreamErr {
    pub layer: UpstreamLayer,
    pub source: io::Error,
    /// Wall-clock from `forward_one`'s `Instant::now()` to error emission.
    /// Bounded above by [`UPSTREAM_TIMEOUT`].
    pub elapsed_ms: u64,
    /// Time from `forward_one` start to return of `connector.connect_tcp`.
    /// `Some` whenever the TCP/SOCKS5-level connection completed
    /// (Tls/Io/Http failures); `None` when we errored at `Connect` or
    /// `Timeout` fired before connect completed.
    pub socks5_ms: Option<u64>,
    /// Time spent inside `tokio_rustls::TlsConnector::connect(...)`.
    /// `Some` on `Tls`/`Io`/`Http` layers; `None` otherwise.
    pub tls_ms: Option<u64>,
    /// Raw bytes written to / read from the underlying TCP stream,
    /// observed by [`crate::dns::connector::CountingStream`]. `None` when
    /// connect failed (no stream existed). Post-SOCKS5 byte counts —
    /// what a DoH server would see.
    pub tcp_wrote: Option<u64>,
    pub tcp_read: Option<u64>,
    /// First `io::Error::raw_os_error()` found walking
    /// `std::error::Error::source()` from `source`. Distinguishes FIN
    /// (graceful close, `None` on Windows since FIN surfaces as `Ok(0)`
    /// with no errno) from RST (`WSAECONNRESET=10054`) and friends.
    pub os_errno: Option<i32>,
}

impl UpstreamErr {
    pub fn new(layer: UpstreamLayer, source: io::Error) -> Self {
        let os_errno = first_os_errno(&source);
        Self {
            layer,
            source,
            elapsed_ms: 0,
            socks5_ms: None,
            tls_ms: None,
            tcp_wrote: None,
            tcp_read: None,
            os_errno,
        }
    }

    fn with_socks5_ms(mut self, ms: u64) -> Self {
        self.socks5_ms = Some(ms);
        self
    }

    fn with_tls_ms(mut self, ms: u64) -> Self {
        self.tls_ms = Some(ms);
        self
    }

    fn with_counters(mut self, c: &StreamCounters) -> Self {
        self.tcp_read = Some(c.read());
        self.tcp_wrote = Some(c.written());
        self
    }
}

/// Walk `std::error::Error::source()` and join the chain with ` -> `.
/// Used as the `caused_by=...` log field so Phase 2 sees the inner
/// io::ErrorKind (e.g. `ConnectionRefused`, `UnexpectedEof`) instead of
/// just the outer message.
fn format_error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = format!("{e}");
    let mut current = e.source();
    while let Some(c) = current {
        s.push_str(&format!(" -> {c}"));
        current = c.source();
    }
    s
}

/// Walk `std::error::Error::source()` looking for the first
/// `io::Error::raw_os_error()` value. Needed because tokio-rustls wraps
/// its own `tls handshake eof` around a synthesized inner `io::Error`
/// that has no errno — but if the root is a real socket error
/// (`WSAECONNRESET` on Windows) it's further down the chain.
///
/// Special-cases `io::Error`: its `Error::source()` impl skips the
/// Custom-wrapper and delegates to the *inner* error's `source()`,
/// which would hide the inner `io::Error` entirely. Use `get_ref()` to
/// descend through nested `io::Error` directly.
fn first_os_errno(e: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<io::Error>() {
            if let Some(errno) = io_err.raw_os_error() {
                return Some(errno);
            }
            if let Some(inner) = io_err.get_ref() {
                current = Some(inner);
                continue;
            }
        }
        current = err.source();
    }
    None
}

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

// Log throttle ========================================================================================================

/// Max full log lines per server before suppressing.
const LOG_FULL_LIMIT: u32 = 3;
/// Minimum interval between summary lines per server.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Per-server state for log-first-N-then-summarize. Replaces the previous
/// per-server dedup-forever `log_once` on the upstream-failure path, which
/// hid all but the first failure per server IP and blocked Phase-2
/// observation of #248.
///
/// - First [`LOG_FULL_LIMIT`] failures per server are logged in full.
/// - After that, a rolling summary line `upstream failed (N suppressed
///   since first, window=Xs)` is emitted at most every
///   [`SUMMARY_INTERVAL`], driven lazily by the next failure event.
///
/// Summary is lazy-not-timer: if failures stop, the residual suppressed
/// count never gets flushed — acceptable tradeoff for avoiding a
/// background task, and consistent with "the error was transient" being
/// a valid outcome.
#[derive(Debug)]
struct ThrottleState {
    logged: u32,
    suppressed: u32,
    first_at: Instant,
    last_summary_at: Instant,
}

impl ThrottleState {
    fn new(now: Instant) -> Self {
        Self {
            logged: 0,
            suppressed: 0,
            first_at: now,
            last_summary_at: now,
        }
    }
}

/// Outcome of consulting the throttle for a new failure. Returned from
/// the mutex-scoped decision function so the tracing macro invocation
/// happens *outside* the lock (keeps the critical section short and
/// avoids any surprise reentrancy).
enum ThrottleDecision {
    /// Emit the full log line, first/second/... occurrence.
    LogFull,
    /// Suppress; nothing to emit.
    Suppress,
    /// Suppress the current failure itself, but emit the rolling
    /// summary line with the counts snapshot from the prior window.
    SuppressAndSummary {
        suppressed_count: u32,
        window_elapsed: Duration,
    },
}

// Public API ==========================================================================================================

pub struct DnsForwarder {
    config: DnsConfig,
    connector: Arc<dyn UpstreamConnector>,
    tls_config: Arc<ClientConfig>,
    ipv6_bypass_available: bool,
    /// Per-server throttle state for upstream-failure logs. Held in a
    /// `std::Mutex` (never across an `await`) — each forward() call
    /// either hits or misses the map and moves on.
    failure_throttle: Mutex<HashMap<IpAddr, ThrottleState>>,
    /// Per-server set for the config-static IPv6-skip log. Separate
    /// from [`Self::failure_throttle`] because the IPv6-skip condition
    /// cannot change without a reconfigure; log-first-1-forever is
    /// correct there.
    ipv6_skip_logged: Mutex<HashSet<IpAddr>>,
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
            failure_throttle: Mutex::new(HashMap::new()),
            ipv6_skip_logged: Mutex::new(HashSet::new()),
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
                self.log_ipv6_skip_once(server);
                continue;
            }

            let target = SocketAddr::new(server, default_port(self.config.protocol));
            match self.forward_one(target, query).await {
                Ok(reply) => return reply,
                Err(e) => self.log_upstream_failure(server, &e),
            }
        }

        synthesize_servfail(query)
    }

    /// Single-attempt forward against `target`. Callers build `target`
    /// from the config'd server plus the protocol's well-known port;
    /// the test-only `forward_with_ports` builds it from an ephemeral
    /// port so stubs don't need privilege to bind 53/853/443.
    async fn forward_one(&self, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamErr> {
        let started = Instant::now();
        let fut = async {
            match self.config.protocol {
                DnsProtocol::PlainUdp => self.forward_udp(target, query).await,
                DnsProtocol::PlainTcp => self.forward_tcp(target, query).await,
                DnsProtocol::Tls => self.forward_tls(target, query).await,
                DnsProtocol::Https => self.forward_https(target, query).await,
            }
        };
        let result = match timeout(UPSTREAM_TIMEOUT, fut).await {
            Ok(res) => res,
            Err(_) => Err(UpstreamErr::new(
                UpstreamLayer::Timeout,
                io::Error::new(io::ErrorKind::TimedOut, "upstream timeout"),
            )),
        };
        result.map_err(|mut e| {
            e.elapsed_ms = started.elapsed().as_millis() as u64;
            e
        })
    }

    /// Log a config-static server-skip message exactly once per server
    /// IP. Used only for the IPv6-no-bypass case where the condition
    /// cannot change without a reconfigure, so a rolling summary would
    /// be noise.
    fn log_ipv6_skip_once(&self, server: IpAddr) {
        let mut set = self.ipv6_skip_logged.lock().expect("poisoned");
        if set.insert(server) {
            tracing::warn!(
                %server,
                protocol = ?self.config.protocol,
                "skipping IPv6 upstream (no IPv6 bypass available)"
            );
        }
    }

    /// Log an upstream failure with the typed layer tag + elapsed + source
    /// chain + optional per-layer diagnostic context. Per-server
    /// log-first-N-then-summarize throttle; see [`ThrottleState`].
    fn log_upstream_failure(&self, server: IpAddr, e: &UpstreamErr) {
        let decision = {
            let mut map = self.failure_throttle.lock().expect("poisoned");
            let now = Instant::now();
            let state = map.entry(server).or_insert_with(|| ThrottleState::new(now));

            if state.logged < LOG_FULL_LIMIT {
                state.logged += 1;
                ThrottleDecision::LogFull
            } else {
                state.suppressed += 1;
                let since_summary = now.duration_since(state.last_summary_at);
                if since_summary >= SUMMARY_INTERVAL {
                    let count = state.suppressed;
                    let window = now.duration_since(state.first_at);
                    state.suppressed = 0;
                    state.last_summary_at = now;
                    ThrottleDecision::SuppressAndSummary {
                        suppressed_count: count,
                        window_elapsed: window,
                    }
                } else {
                    ThrottleDecision::Suppress
                }
            }
        };

        match decision {
            ThrottleDecision::LogFull => {
                tracing::warn!(
                    %server,
                    protocol = ?self.config.protocol,
                    layer = %e.layer,
                    elapsed_ms = e.elapsed_ms,
                    budget_ms = UPSTREAM_TIMEOUT.as_millis() as u64,
                    socks5_ms = ?e.socks5_ms,
                    tls_ms = ?e.tls_ms,
                    tcp_wrote = ?e.tcp_wrote,
                    tcp_read = ?e.tcp_read,
                    os_errno = ?e.os_errno,
                    caused_by = %format_error_chain(&e.source),
                    "upstream failed"
                );
            }
            ThrottleDecision::Suppress => {}
            ThrottleDecision::SuppressAndSummary {
                suppressed_count,
                window_elapsed,
            } => {
                tracing::warn!(
                    %server,
                    protocol = ?self.config.protocol,
                    suppressed = suppressed_count,
                    window_s = window_elapsed.as_secs(),
                    "upstream failed (summary — full logging resumed at next interval)"
                );
            }
        }
    }
}

/// Well-known port per protocol. Split out so `forward_with_ports` (test
/// helper) can reuse the mapping.
fn default_port(protocol: DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::PlainUdp | DnsProtocol::PlainTcp => DNS_PORT_PLAIN,
        DnsProtocol::Tls => DNS_PORT_TLS,
        DnsProtocol::Https => DNS_PORT_HTTPS,
    }
}

// Transport: plain UDP ================================================================================================

impl DnsForwarder {
    async fn forward_udp(&self, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamErr> {
        let socket = self
            .connector
            .connect_udp(target)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Connect, e))?;
        socket
            .send(query)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Io, e))?;
        let mut buf = vec![0u8; MAX_REPLY_SIZE];
        let n = socket
            .recv(&mut buf)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Io, e))?;
        buf.truncate(n);
        Ok(buf)
    }
}

// Transport: plain TCP ================================================================================================

impl DnsForwarder {
    async fn forward_tcp(&self, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamErr> {
        let socks5_start = Instant::now();
        let connected = self
            .connector
            .connect_tcp(target)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Connect, e))?;
        let socks5_ms = socks5_start.elapsed().as_millis() as u64;
        let (stream, counters) = connected.into_parts();
        exchange_tcp_framed(stream, query).await.map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Io, e)
                .with_socks5_ms(socks5_ms)
                .with_counters(&counters)
        })
    }
}

// Transport: DoT (TLS over TCP) =======================================================================================

impl DnsForwarder {
    async fn forward_tls(&self, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamErr> {
        let socks5_start = Instant::now();
        let connected = self
            .connector
            .connect_tcp(target)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Connect, e))?;
        let socks5_ms = socks5_start.elapsed().as_millis() as u64;
        let (stream, counters) = connected.into_parts();

        let server_name = tls_server_name_for(target.ip()).map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Tls, e)
                .with_socks5_ms(socks5_ms)
                .with_counters(&counters)
        })?;
        let tls_start = Instant::now();
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let tls = tls_connector.connect(server_name, stream).await.map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Tls, e)
                .with_socks5_ms(socks5_ms)
                .with_tls_ms(tls_start.elapsed().as_millis() as u64)
                .with_counters(&counters)
        })?;
        let tls_ms = tls_start.elapsed().as_millis() as u64;
        exchange_tcp_framed(tls, query).await.map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Io, e)
                .with_socks5_ms(socks5_ms)
                .with_tls_ms(tls_ms)
                .with_counters(&counters)
        })
    }
}

// Transport: DoH (HTTP/1.1 over TLS) ==================================================================================

impl DnsForwarder {
    async fn forward_https(&self, target: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamErr> {
        let (server_name, path_and_host) =
            https_target_for(target.ip()).map_err(|e| UpstreamErr::new(UpstreamLayer::Http, e))?;

        let socks5_start = Instant::now();
        let connected = self
            .connector
            .connect_tcp(target)
            .await
            .map_err(|e| UpstreamErr::new(UpstreamLayer::Connect, e))?;
        let socks5_ms = socks5_start.elapsed().as_millis() as u64;
        let (stream, counters) = connected.into_parts();

        let tls_start = Instant::now();
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let mut tls = tls_connector.connect(server_name, stream).await.map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Tls, e)
                .with_socks5_ms(socks5_ms)
                .with_tls_ms(tls_start.elapsed().as_millis() as u64)
                .with_counters(&counters)
        })?;
        let tls_ms = tls_start.elapsed().as_millis() as u64;

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

        let io_err = |e: io::Error| {
            UpstreamErr::new(UpstreamLayer::Io, e)
                .with_socks5_ms(socks5_ms)
                .with_tls_ms(tls_ms)
                .with_counters(&counters)
        };
        tls.write_all(&req).await.map_err(io_err)?;
        tls.flush().await.map_err(io_err)?;

        let mut resp = Vec::with_capacity(4096);
        // Cap reads so a misbehaving server can't OOM us.
        tls.take((MAX_REPLY_SIZE * 4) as u64)
            .read_to_end(&mut resp)
            .await
            .map_err(io_err)?;

        parse_http_dns_response(&resp).map_err(|e| {
            UpstreamErr::new(UpstreamLayer::Http, e)
                .with_socks5_ms(socks5_ms)
                .with_tls_ms(tls_ms)
                .with_counters(&counters)
        })
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
