//! `EngineConfig` — tunable knobs for [`Engine::build`](super::Engine::build).

use std::sync::Arc;
use std::time::Duration;

use tun_engine_macros::freeze;

use super::dns::DnsInterceptor;

/// Runtime tunables for an `Engine`.
///
/// All fields have sensible defaults matched to typical tun2socks usage.
/// Override via the `Engine::build(..., |c| { c.field = ... })` closure.
#[freeze]
pub struct EngineConfig {
    /// Maximum concurrent TCP connections. Connections past the limit are
    /// refused with a TCP reset before the handshake completes, until an
    /// existing connection drops.
    pub max_connections: usize,

    /// Maximum concurrent calls to [`TcpFlow::peek`](super::TcpFlow::peek)
    /// across all flows.
    pub max_sniffers: usize,

    /// smoltcp TCP socket receive buffer (per socket, bytes).
    pub tcp_rx_buf_size: usize,
    /// smoltcp TCP socket transmit buffer (per socket, bytes).
    pub tcp_tx_buf_size: usize,

    /// How often an admitted TCP connection with nothing else to send probes
    /// its client while idle.
    ///
    /// A quarter of [`tcp_peer_timeout`](Self::tcp_peer_timeout), so a client
    /// that is merely quiet answers three probes before the bound is reached,
    /// and only a client that has stopped answering altogether trips it.
    pub tcp_keep_alive_interval: Duration,
    /// How long an admitted TCP connection tolerates silence from its client
    /// before it is reset and its slot reclaimed.
    ///
    /// This bounds an external event — a client process that may never speak
    /// again — not anything inside the engine. Without it, a connection stalled
    /// in `SynReceived`, `FinWait2` or `CloseWait` holds its entry, both buffers
    /// and its connection slot for the life of the process, and
    /// `max_connections` such connections wedge the tunnel for all new TCP.
    ///
    /// The default is RFC 5382 REQ-5's floor for a *transitory* connection —
    /// one partially open or closing, exactly those states — below which a
    /// stack may not abandon one. A quiet but live connection is not held to
    /// it: the keep-alive probe answers on its behalf.
    pub tcp_peer_timeout: Duration,

    /// Interval at which the driver polls smoltcp outside of TUN reads.
    /// Needed because handler-to-driver data arrives via mpsc and would
    /// otherwise wait for an unrelated TUN packet to wake the driver.
    pub poll_interval: Duration,

    /// Interval at which the driver sweeps idle UDP flows.
    pub idle_sweep_interval: Duration,
    /// UDP flow idle timeout — flows with no activity for this long are
    /// evicted on the next sweep.
    pub udp_flow_idle_timeout: Duration,

    /// Optional hook for port-53 UDP DNS interception. When set, the
    /// engine short-circuits port-53 UDP through the interceptor instead
    /// of dispatching to `Router::route_udp`. A `None` return from the
    /// interceptor causes the datagram to flow through to the Router
    /// normally.
    pub dns_interceptor: Option<Arc<dyn DnsInterceptor>>,
}

impl Default for MutEngineConfig {
    fn default() -> Self {
        Self {
            max_connections: 4096,
            max_sniffers: 1024,
            tcp_rx_buf_size: 65536,
            tcp_tx_buf_size: 65536,
            tcp_keep_alive_interval: Duration::from_secs(60),
            tcp_peer_timeout: Duration::from_secs(240),
            poll_interval: Duration::from_millis(1),
            idle_sweep_interval: Duration::from_secs(5),
            udp_flow_idle_timeout: Duration::from_secs(30),
            dns_interceptor: None,
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
