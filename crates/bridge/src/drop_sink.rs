//! `DropSink` — where the router records flows it refused to carry.
//!
//! A drop is not a dispatch. `HoleRouter::resolve_endpoint` returns a
//! drop reason rather than an [`Endpoint`](crate::endpoint::Endpoint),
//! and the router drops the flow itself; nothing serves it. The sink is
//! therefore the only trace a dropped flow leaves, which is why it is a
//! trait: production wires [`LoggingDropSink`], and tests wire a
//! recording sink whose records make the drop assertable — including the
//! UDP-drop privacy invariant.
//!
//! The three drop reasons ([`crate::hole_router`] holds the cascade):
//!
//! 1. `FilterAction::Block` — the user's rules asked to block.
//! 2. **Privacy invariant** — `FilterAction::Proxy` + UDP + the plugin
//!    cannot carry UDP. Falling back to the clear-text bypass would leak
//!    the flow outside the encrypted tunnel, violating the user's VPN
//!    guarantee. Do not 'fix' by cascading to `InterfaceEndpoint`.
//! 3. **Reachability** — `FilterAction::Bypass` + IPv6 destination +
//!    upstream interface has no IPv6.

pub mod block_log;
pub mod logging;

use std::net::SocketAddr;

pub use logging::LoggingDropSink;

/// Records why the cascade dropped a flow. One method per reason, so an
/// explicit rule block, the privacy drop and an unreachable destination
/// stay distinguishable to whatever is on the other side.
pub trait DropSink: Send + Sync {
    /// `FilterAction::Block` on a TCP flow. `domain` is the sniffed name
    /// when one was recovered.
    fn rule_block_tcp(&self, rule_index: u32, dst: SocketAddr, domain: Option<&str>);

    /// `FilterAction::Block` on a UDP flow. UDP has no peek, so no domain.
    fn rule_block_udp(&self, rule_index: u32, dst: SocketAddr);

    /// The privacy drop: `FilterAction::Proxy` + UDP + a TCP-only plugin.
    /// `plugin` is the configured plugin name, for diagnostic context.
    fn udp_proxy_unavailable(&self, rule_index: u32, dst: SocketAddr, plugin: Option<&str>);

    /// `FilterAction::Bypass` to an IPv6 destination the upstream
    /// interface cannot reach. `l4` is `"tcp"` or `"udp"`.
    fn ipv6_bypass_unreachable(&self, rule_index: u32, dst: SocketAddr, l4: &'static str);
}
