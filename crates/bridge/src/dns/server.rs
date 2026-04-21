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

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

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
    pub async fn bind(addr: SocketAddr, forwarder: Arc<DnsForwarder>) -> io::Result<Self> {
        Self::bind_once(addr, forwarder).await
    }

    /// Single-shot bind of a UDP + TCP pair on `addr`. No retry — the
    /// caller decides whether to retry on a fresh port (`bind` with port
    /// 0) or walk a ladder (`bind_ladder` with fixed port 53).
    async fn bind_once(addr: SocketAddr, forwarder: Arc<DnsForwarder>) -> io::Result<Self> {
        let udp = UdpSocket::bind(addr).await?;
        let actual_addr = udp.local_addr()?;
        let tcp = TcpListener::bind(actual_addr).await?;

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
        let mut last_err: Option<io::Error> = None;
        for addr in candidates {
            match Self::bind(addr, Arc::clone(&forwarder)).await {
                Ok(srv) => return Ok(srv),
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "LocalDnsServer bind candidate failed");
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

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;
