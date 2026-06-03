//! `Endpoint` — hole-bridge's per-flow outbound transport abstraction.
//!
//! An `Endpoint` is "a way to materialize a flow's 5-tuple into a real
//! outbound I/O resource." The trait is deliberately L3-shaped: it takes
//! a `SocketAddr` and carries bytes to that destination. Higher-layer
//! concerns (name recovery, policy) live in [`crate::hole_router`].
//!
//! See [`crate::hole_router`] for the role→mechanism wiring (Proxy →
//! [`Socks5Endpoint`], Bypass → [`InterfaceEndpoint`], Block →
//! [`BlockEndpoint`]) and the full cascade. Tests can wire any mechanism
//! to any slot via `MockEndpoint`.
//!
//! ## UDP-drop privacy invariant
//!
//! UDP flows that resolve to `Proxy` but can't be proxied (TCP-only
//! plugin, [`Endpoint::supports_udp`] is `false`) are dropped, not
//! bypassed — see [`crate::hole_router`] and [`BlockEndpoint`].

pub mod block;
pub mod interface;
pub mod local_dns;
pub mod socks5;

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tun_engine::{TcpFlow, UdpFlow};

pub use block::BlockEndpoint;
pub use interface::InterfaceEndpoint;
pub use local_dns::LocalDnsEndpoint;
pub use socks5::Socks5Endpoint;

/// A flow-carrying mechanism. Implementations take ownership of a flow
/// and drive it to completion at `dst`.
///
/// Capability accessors ([`supports_udp`], [`supports_ipv6_dst`]) MUST be
/// pure functions of `&self` and stable for the endpoint's lifetime. The
/// router's cascade caches on these values; a runtime-varying capability
/// would silently leak flows past the cascade's drop gates.
///
/// [`supports_udp`]: Endpoint::supports_udp
/// [`supports_ipv6_dst`]: Endpoint::supports_ipv6_dst
#[async_trait]
pub trait Endpoint: Send + Sync {
    /// Carry a TCP flow to `dst`. Returns when either end closes the
    /// stream. Implementations that drop the flow (BlockEndpoint) return
    /// `Ok(())` immediately — smoltcp emits an RST when the flow is
    /// dropped.
    async fn serve_tcp(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()>;

    /// Carry a UDP flow to `dst`. Returns when the flow's idle sweep
    /// evicts it or when the peer closes. Implementations that drop the
    /// flow return `Ok(())` immediately.
    async fn serve_udp(&self, flow: UdpFlow, dst: SocketAddr) -> io::Result<()>;

    /// Whether this endpoint can carry UDP end-to-end. Drives the router
    /// cascade's privacy invariant: `Proxy + UDP + !supports_udp()` is
    /// dropped, not cascaded.
    fn supports_udp(&self) -> bool;

    /// Whether this endpoint can reach an IPv6 destination. For
    /// `InterfaceEndpoint` this reflects whether the bound NIC has IPv6
    /// connectivity; for `Socks5Endpoint` it is always `true` because
    /// SOCKS5 carries IPv6 addresses via ATYP.
    fn supports_ipv6_dst(&self) -> bool;

    /// Short diagnostic label (e.g. `"socks5(ex-ray)"`, `"interface(#5)"`,
    /// `"block"`). Backed by the endpoint's own storage — no allocation
    /// per call.
    fn name(&self) -> &str;
}
