//! The [`Router`] trait — caller-supplied per-connection policy.
//!
//! The engine routes inbound flows from the TUN to a single shared
//! `Router` impl. The trait is deliberately shape-agnostic: for each TCP
//! connection the engine hands the Router a byte stream + 5-tuple, and
//! for each UDP flow a [`UdpFlow`] handle + 5-tuple. What the Router does
//! with that is its business — splice into a SOCKS5 upstream, open a
//! direct bypass socket, filter, block, anything.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use super::tcp_flow::TcpFlow;
use super::udp_flow::UdpFlow;

/// 5-tuple metadata for an accepted TCP connection. Passed to
/// [`Router::route_tcp`] alongside the flow's byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpMeta {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// 5-tuple metadata for a UDP flow. Passed to [`Router::route_udp`]
/// alongside the flow handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMeta {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Per-flow dispatch policy. The engine invokes one of these methods for
/// every inbound TCP connection or UDP flow it sees on the TUN.
///
/// The engine clones an `Arc<dyn Router>` into each spawned handler task,
/// so impls must be `Send + Sync + 'static` and reasonably cheap to share.
/// Router state (filter rules, DNS caches, upstream config) typically
/// lives behind `Arc`/`ArcSwap` so handlers can read it lock-free.
///
/// Return values: `io::Result<()>` is logged at `debug!` on `Err`. The
/// engine does not retry — the Router owns its own dispatch lifecycle.
#[async_trait]
pub trait Router: Send + Sync + 'static {
    /// Handle a newly-accepted TCP connection.
    ///
    /// The flow is an `AsyncRead + AsyncWrite` with an extra
    /// [`TcpFlow::peek`] for sniffing the first bytes (SNI, HTTP Host).
    /// Dropping the flow causes the underlying smoltcp socket to emit RST.
    async fn route_tcp(&self, meta: TcpMeta, flow: TcpFlow) -> io::Result<()>;

    /// Handle a new UDP flow (first datagram seen for this 5-tuple).
    ///
    /// The flow's `recv()` returns `None` when the engine's idle-sweep
    /// evicts the flow. The idiom is `while let Some(pkt) = flow.recv().await`.
    async fn route_udp(&self, meta: UdpMeta, flow: UdpFlow) -> io::Result<()>;
}
