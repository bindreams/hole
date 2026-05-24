//! [`LocalDnsServer`] — binds loopback `<ip>:53` UDP+TCP and forwards
//! every incoming query through a shared [`DnsForwarder`]. Hand-rolled
//! instead of using `hickory-server` because the forwarder's I/O is pure
//! bytes-in/bytes-out — no zone database, no authority records, no
//! response caching. A `RequestHandler` wrapper would add serialization
//! overhead and conceptual weight for no gain.
//!
//! Loopback bind ladder (per plan "Loopback bind-fallback ladder"):
//!
//! 1. `127.0.0.1:53` — the conventional default
//! 2. `127.53.0.1:53 .. 127.53.0.254:53` — Hole-dedicated /24 sweep
//! 3. Bind fails loudly
//!
//! UDP and TCP must bind *together* on the same IP (if UDP succeeds but
//! TCP fails on an IP, both are released and the ladder moves on — this
//! avoids a split-brain state where system DNS clients might only reach
//! one transport).
//!
//! Ephemeral-port callers of [`LocalDnsServer::bind`] (port 0, used by
//! tests) delegate to [`hole_common::port_alloc::bind_ephemeral`] to
//! absorb the Windows-specific bind race where the OS's independent
//! TCP/UDP excluded-port-range tables disagree. Fixed-port callers
//! ([`LocalDnsServer::bind_ladder`] with port 53) bypass the wrapper:
//! retrying a fixed port in place is futile because the excluded-range
//! state doesn't change per-attempt, so the ladder's "move to the next
//! IP" is the correct escape instead.
//!
//! Each candidate's bind is followed by a UDP loopback self-test
//! ([`SelfTestProbe`]); on probe failure the ladder advances to the next
//! candidate. The probe catches inbound-routing hijacks (Windows ICS /
//! LSP / WFP shims, macOS NKE / PF / kernel firewalls) that the bind
//! syscall cannot detect. See bindreams/hole#398.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hole_common::port_alloc::{self, Protocols};
use hole_common::retry::is_bind_race;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::dns::forwarder::DnsForwarder;

/// DNS port. Both UDP and TCP use 53 per RFC 1035.
const DNS_PORT: u16 = 53;

/// Maximum inbound DNS message (both UDP and TCP). DNS over UDP is
/// capped at 512 bytes (or EDNS0's max_udp_payload) but we accept up to
/// `MAX_INBOUND_MESSAGE` — in practice the OS DNS client caps queries well
/// below this.
const MAX_INBOUND_MESSAGE: usize = 4 * 1024;

/// A loopback DNS server. Dropping the server aborts both listener tasks.
pub struct LocalDnsServer {
    addr: SocketAddr,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
}

impl LocalDnsServer {
    /// Bind a specific address (UDP + TCP). Used by tests to inject an
    /// ephemeral port; production code uses [`bind_ladder`].
    ///
    /// Binds UDP first, then TCP on the same (possibly ephemeral) port —
    /// passing `port = 0` would otherwise hand the two sockets distinct
    /// OS-assigned ports, which callers never want: system DNS clients
    /// need UDP and TCP on the same address.
    ///
    /// When `addr.port() == 0` the bind is delegated to
    /// [`hole_common::port_alloc::bind_ephemeral`], which absorbs the
    /// Windows `WSAEACCES` race where the OS's independent TCP/UDP
    /// excluded-port-range tables reject a freshly-allocated port on
    /// the paired transport. Fixed-port callers skip the wrapper —
    /// retry in place is futile (state doesn't change per-attempt),
    /// and the `bind_ladder` walker is the correct escape.
    pub async fn bind(addr: SocketAddr, forwarder: Arc<DnsForwarder>) -> io::Result<Self> {
        if addr.port() == 0 {
            let ip = addr.ip();
            let (_, server) = port_alloc::bind_ephemeral(ip, Protocols::TCP | Protocols::UDP, |port| {
                let forwarder = Arc::clone(&forwarder);
                async move { Self::bind_once(SocketAddr::new(ip, port), forwarder).await }
            })
            .await?;
            Ok(server)
        } else {
            Self::bind_once(addr, forwarder).await
        }
    }

    /// Single-shot bind of a UDP + TCP pair on `addr`. No retry — the
    /// caller decides whether to retry on a fresh port (`bind` with port
    /// 0) or walk a ladder (`bind_ladder` with fixed port 53).
    ///
    /// Wraps [`Self::bind_once_with_probe`] with the production
    /// [`DefaultProbe`]. Tests reach the with-probe variant directly to
    /// inject a `SelfTestProbe` mock.
    async fn bind_once(addr: SocketAddr, forwarder: Arc<DnsForwarder>) -> io::Result<Self> {
        Self::bind_once_with_probe(addr, forwarder, &DefaultProbe).await
    }

    /// `bind_once`'s impl, parameterized over a [`SelfTestProbe`]. The
    /// probe runs after the UDP+TCP bind succeeds and BEFORE the listener
    /// tasks are spawned — the probe must hold exclusive ownership of the
    /// freshly-bound `UdpSocket` for its duration, otherwise the spawned
    /// loop would race with the probe's `recv_from` and false-negative.
    ///
    /// Private to `server.rs`; child `mod server_tests` reaches it via
    /// `use super::*` (Rust privacy lets child modules see parent
    /// privates).
    async fn bind_once_with_probe<P: SelfTestProbe>(
        addr: SocketAddr,
        forwarder: Arc<DnsForwarder>,
        probe: &P,
    ) -> io::Result<Self> {
        let udp = bind_udp_socket(addr).await?;
        let actual_addr = udp.local_addr()?;
        let tcp = bind_tcp_listener(actual_addr).await?;

        // Probe before spawning the loop — see SelfTestProbe doc.
        probe.probe(&udp).await?;

        let fwd_udp = Arc::clone(&forwarder);
        let udp_task = tokio::spawn(async move { run_udp_loop(udp, fwd_udp).await });

        let fwd_tcp = forwarder;
        let tcp_task = tokio::spawn(async move { run_tcp_loop(tcp, fwd_tcp).await });

        Ok(Self {
            addr: actual_addr,
            udp_task,
            tcp_task,
        })
    }

    /// Bind `<ip>:53` via the fallback ladder. Tries `127.0.0.1` first,
    /// then `127.53.0.1..=127.53.0.254`, returning the first IP where BOTH
    /// UDP and TCP bind succeeds. Returns an explicit error when the whole
    /// ladder is exhausted.
    pub async fn bind_ladder(forwarder: Arc<DnsForwarder>) -> io::Result<Self> {
        let candidates = ladder_candidates();
        let preferred = candidates[0];
        let mut last_err: Option<io::Error> = None;
        for addr in candidates {
            match Self::bind(addr, Arc::clone(&forwarder)).await {
                Ok(srv) => return Ok(srv),
                Err(e) => {
                    // First candidate (`127.0.0.1:53`) failure is the user-visible
                    // signature of a wildcard :53 holder (ICS / Pi-hole / Acrylic /
                    // dnscrypt-proxy) or a loopback hijack caught by the self-test;
                    // surface it at `info!` so users without bridge-debug logging
                    // still see the cause when the ladder lands on `127.53.0.X`.
                    // Other candidates stay at `debug!` to avoid log spam (255-element
                    // ladder).
                    let preferred_failure_known =
                        is_bind_race(&e) || e.get_ref().is_some_and(|inner| inner.is::<SelfTestError>());
                    if addr == preferred && preferred_failure_known {
                        tracing::info!(
                            %addr,
                            error = %e,
                            "loopback :53 unavailable — wildcard holder (Internet Connection Sharing, \
                             Pi-hole, dnscrypt-proxy) or LSP/loopback hijack suspected; advancing ladder"
                        );
                    } else {
                        tracing::debug!(%addr, error = %e, "LocalDnsServer bind candidate failed");
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(io::Error::other(format!(
            "LocalDnsServer could not bind any :53 loopback; last error: {}. \
             Disable DNS forwarder in settings, or stop the conflicting service \
             (Pi-hole, Acrylic, Docker Desktop, dnscrypt-proxy).",
            last_err.expect("ladder non-empty")
        )))
    }

    /// Address the server is actually bound to. Differs from the
    /// requested address when the caller used [`bind_ladder`] or the OS
    /// substituted an ephemeral port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        // Aborting the tasks closes the underlying sockets via Drop,
        // which releases the loopback port + interrupts pending
        // recv_from/accept calls so in-flight clients get immediate EOF.
        self.udp_task.abort();
        self.tcp_task.abort();
    }
}

// Loop bodies =========================================================================================================

async fn run_udp_loop(socket: UdpSocket, forwarder: Arc<DnsForwarder>) {
    let socket = Arc::new(socket);
    loop {
        let mut buf = vec![0u8; MAX_INBOUND_MESSAGE];
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // If the socket was closed (server dropped), recv_from
                // returns an error and we exit. Any other error is worth
                // logging but not fatal to the loop.
                tracing::debug!(error = %e, "LocalDnsServer UDP recv_from error; ending loop");
                return;
            }
        };
        buf.truncate(n);
        let socket = Arc::clone(&socket);
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move {
            let reply = forwarder.forward(&buf).await;
            if let Err(e) = socket.send_to(&reply, peer).await {
                tracing::debug!(error = %e, %peer, "LocalDnsServer UDP send_to error");
            }
        });
    }
}

async fn run_tcp_loop(listener: TcpListener, forwarder: Arc<DnsForwarder>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "LocalDnsServer TCP accept error; ending loop");
                return;
            }
        };
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, forwarder).await {
                tracing::debug!(error = %e, %peer, "LocalDnsServer TCP connection error");
            }
        });
    }
}

async fn handle_tcp_connection(mut stream: TcpStream, forwarder: Arc<DnsForwarder>) -> io::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            // A clean close at message boundary is expected when the
            // client finished its queries.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_be_bytes(len_buf) as usize;
        if n > MAX_INBOUND_MESSAGE {
            return Err(io::Error::other("DNS query too large"));
        }
        let mut query = vec![0u8; n];
        stream.read_exact(&mut query).await?;

        let reply = forwarder.forward(&query).await;
        let reply_len = u16::try_from(reply.len()).map_err(|_| io::Error::other("reply too large"))?;
        stream.write_all(&reply_len.to_be_bytes()).await?;
        stream.write_all(&reply).await?;
    }
}

// Ladder ==============================================================================================================

/// Build the list of candidate addresses in priority order. The ladder
/// lives in one spot so tests can assert its contents.
pub(super) fn ladder_candidates() -> Vec<SocketAddr> {
    let mut v = Vec::with_capacity(1 + 254);
    v.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT));
    for host in 1..=254u8 {
        v.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 53, 0, host)), DNS_PORT));
    }
    v
}

// Listener factories ==================================================================================================
//
// Windows: build via `socket2` so we can flip `SO_EXCLUSIVEADDRUSE` before
// `bind`. **This is forward-looking defense, not a fix for the #398
// production bug.** Per MSDN's documented Winsock matrix,
// `SO_EXCLUSIVEADDRUSE` on a specific-address bind does NOT refuse
// coexistence with a pre-existing `SO_REUSEADDR` wildcard holder on
// `0.0.0.0:P` — they target different addresses, so the kernel allows
// both. The #398 production bug (ICS / `svchost` wins inbound routing on
// `127.0.0.1:53` despite Hole's specific bind succeeding) is caused by
// ICS-specific kernel-level routing override and is defended by the
// post-bind self-test below. `SO_EXCLUSIVEADDRUSE` here prevents a
// FUTURE process from using `SO_REUSEADDR` to steal traffic from Hole's
// already-bound listener (the symmetric case MSDN does document).
//
// `socket2 0.6` exposes no `set_exclusive_address_use` wrapper; use the
// `windows` crate's `setsockopt` directly, mirroring
// `crates/garter/src/chain_tests.rs::hold_wildcard_exclusive`.

#[cfg(target_os = "windows")]
async fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    set_exclusive_address_use(&s)?;
    s.bind(&addr.into())?;
    s.set_nonblocking(true)?;
    let std: std::net::UdpSocket = s.into();
    UdpSocket::from_std(std)
}

#[cfg(target_os = "windows")]
async fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    set_exclusive_address_use(&s)?;
    s.bind(&addr.into())?;
    s.listen(128)?;
    s.set_nonblocking(true)?;
    let std: std::net::TcpListener = s.into();
    TcpListener::from_std(std)
}

#[cfg(target_os = "windows")]
fn set_exclusive_address_use(s: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};
    let raw = SOCKET(s.as_raw_socket() as usize);
    let enable = 1i32.to_ne_bytes();
    // SAFETY: `raw` is a valid Winsock socket owned by `s`; `&enable` is
    // a live `[u8; 4]` on this stack frame. Matches the precedent at
    // `crates/garter/src/chain_tests.rs:69-72`.
    let rc = unsafe { setsockopt(raw, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&enable)) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// macOS / BSD: `SO_EXCLUSIVEADDRUSE` is a Win32 concept and has no
// direct equivalent. `SO_REUSEPORT` semantics there require both
// sockets to set the flag (so the wildcard-holder-vs-specific-bind
// hijack does not form), and `bind` returns `EADDRINUSE` on the
// conflicting case. The post-bind self-test still runs on macOS as
// defense against NKE / PF / kernel-firewall loopback hijacks that
// `bind` cannot detect.

#[cfg(not(target_os = "windows"))]
async fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

#[cfg(not(target_os = "windows"))]
async fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

// Self-test ===========================================================================================================
//
// Defense-in-depth gate that runs after `bind_once_with_probe`'s UDP+TCP
// bind succeeds and before the listener loop spawns. Catches loopback
// hijacks that the bind syscall does not see: Windows LSP/WFP shims that
// silently consume datagrams without ever userspace-binding the port;
// macOS NKEs / PF rules / kernel firewalls (LuLu, Little Snitch) doing
// the same. Without this gate, `LocalDnsServer` would commit a poisoned
// binding on `127.0.0.1:53` and the user's DNS would silently fail.

/// Post-bind verification that the freshly-bound UDP socket actually
/// receives our own datagrams (i.e., we own the loopback route for this
/// addr). Returning `Err` causes `bind_once_with_probe` to drop the
/// socket and propagate, so `bind_ladder` walks to the next candidate.
///
/// **Ordering contract:** invoked on a freshly-bound socket that has NO
/// reader yet. The probe holds exclusive ownership of the socket for the
/// duration of `probe()` and MUST consume every datagram it sends before
/// returning `Ok`. After `Ok`, the caller spawns the listener loop on
/// the same socket.
#[async_trait]
trait SelfTestProbe: Send + Sync {
    async fn probe(&self, socket: &UdpSocket) -> io::Result<()>;
}

/// Production [`SelfTestProbe`]. Performs the loopback sentinel
/// round-trip; runs on both Windows and macOS for defense-in-depth.
struct DefaultProbe;

#[async_trait]
impl SelfTestProbe for DefaultProbe {
    async fn probe(&self, socket: &UdpSocket) -> io::Result<()> {
        loopback_udp_self_test(socket).await
    }
}

/// Typed marker for self-test failures. `bind_ladder` downcasts the inner
/// `io::Error` source via `e.get_ref().is::<SelfTestError>()` to decide
/// whether to surface the first-candidate failure at `info!` vs `debug!`.
/// Substring matching on the error message would be fragile against any
/// future wording change in the self-test diagnostic.
#[derive(Debug)]
struct SelfTestError(String);

impl std::fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SelfTestError {}

fn self_test_error(message: impl Into<String>) -> io::Error {
    io::Error::other(SelfTestError(message.into()))
}

/// 4-byte magic prefix identifying our sentinel datagrams. Real DNS
/// payloads never start with these bytes (DNS byte 0 is the
/// transaction-id high byte, which is random; the chance of collision
/// is ~1/2^32 per inbound query, and even on collision the remaining
/// discriminator fields filter it).
const SENTINEL_MAGIC: [u8; 4] = *b"HOLE";
/// Total sentinel payload size: 4 magic + 4 must-be-zero + 8 nonce.
const SENTINEL_LEN: usize = 16;
/// Maximum probe attempts. Retry exists ONLY to absorb a racing inbound
/// real-DNS query during cold start (vanishingly unlikely since system
/// DNS is rewritten *after* `LocalDnsServer` binds). On full timeout
/// (no recv) we fail immediately — a hijacker will sink every retry the
/// same way, so retrying gains nothing.
const SENTINEL_MAX_ATTEMPTS: u8 = 3;
/// Per-attempt recv timeout. Loopback UDP RTT to ourselves is
/// microseconds in the healthy path; 600ms is the failure-bound surfaced
/// to a human, NOT a sleep-then-check.
///
/// CLAUDE.md "no sync via time" exception class: **external event with
/// graceful failure bound** — the round-trip travels through the kernel
/// UDP stack, which a hijacker (LSP/WFP shim, `SO_REUSEADDR` wildcard
/// service) can silently consume. There is no in-process primitive to
/// ask "did the kernel route my packet to me or to someone else"; only
/// a bounded probe can tell. The 600ms cap surfaces as a hint in
/// `bind_ladder`'s `info!` log when the ladder advances.
const SENTINEL_RECV_TIMEOUT: Duration = Duration::from_millis(600);

async fn loopback_udp_self_test(socket: &UdpSocket) -> io::Result<()> {
    let target = socket.local_addr()?;
    let mut last_mismatch: Option<String> = None;
    for attempt in 0..SENTINEL_MAX_ATTEMPTS {
        let sentinel = build_sentinel(attempt);
        socket.send_to(&sentinel, target).await?;

        let mut buf = [0u8; 64];
        match tokio::time::timeout(SENTINEL_RECV_TIMEOUT, socket.recv_from(&mut buf)).await {
            Err(_elapsed) => {
                // Timeout — no datagram arrived within budget. Hijacker
                // sink: do not retry, a second attempt sinks the same way.
                return Err(self_test_error(format!(
                    "LocalDnsServer self-test: {}ms timeout — likely wildcard :{} holder \
                     or LSP loopback hijack consumed sentinel datagram",
                    SENTINEL_RECV_TIMEOUT.as_millis(),
                    target.port()
                )));
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok((n, peer))) => {
                if discriminator_matches(&buf, n, &sentinel, peer, target) {
                    return Ok(());
                }
                // Mismatch: somebody else's datagram landed here (a real
                // DNS query racing into our recv during cold start, or a
                // stale sentinel from a previous attempt). Retry with a
                // fresh nonce, up to SENTINEL_MAX_ATTEMPTS.
                tracing::debug!(
                    ?peer, %target, n,
                    "LocalDnsServer self-test: discarded non-matching datagram, retrying"
                );
                last_mismatch = Some(format!("self-test: received {n} unrelated bytes from {peer}"));
            }
        }
    }
    Err(self_test_error(format!(
        "LocalDnsServer self-test failed after {SENTINEL_MAX_ATTEMPTS} attempts (mismatch class): {}",
        last_mismatch.expect("at least one attempt ran")
    )))
}

/// Returns `true` iff `buf[..n]` matches `sentinel` byte-for-byte AND
/// `peer == target`. All 5 discriminator conditions in one place.
fn discriminator_matches(
    buf: &[u8],
    n: usize,
    sentinel: &[u8; SENTINEL_LEN],
    peer: SocketAddr,
    target: SocketAddr,
) -> bool {
    n == SENTINEL_LEN && &buf[..SENTINEL_LEN] == sentinel.as_slice() && peer == target
}

/// Build a 16-byte sentinel for the given attempt index. Magic + zero +
/// nonce; the nonce mixes wall-clock nanos and the attempt index so each
/// retry's nonce is distinct from the previous one even on the same
/// socket (avoids stale-sentinel false positives).
fn build_sentinel(attempt: u8) -> [u8; SENTINEL_LEN] {
    let mut out = [0u8; SENTINEL_LEN];
    out[..4].copy_from_slice(&SENTINEL_MAGIC);
    // out[4..8] stays zero. Discriminator validates this implicitly via
    // byte-equality with `sentinel`.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let nonce = nanos.rotate_left((attempt as u32) * 8) ^ ((attempt as u64) << 56);
    out[8..16].copy_from_slice(&nonce.to_le_bytes());
    out
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;
