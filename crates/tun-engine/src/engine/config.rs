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
    /// Maximum concurrent TCP connections. Additional connections are
    /// accepted at the smoltcp layer and then aborted until an existing
    /// connection drops.
    pub max_connections: usize,

    /// Maximum concurrent calls to [`TcpFlow::peek`](super::TcpFlow::peek)
    /// across all flows.
    pub max_sniffers: usize,

    /// smoltcp TCP socket receive buffer (per socket, bytes).
    pub tcp_rx_buf_size: usize,
    /// smoltcp TCP socket transmit buffer (per socket, bytes).
    pub tcp_tx_buf_size: usize,

    /// smoltcp UDP receive metadata slots for the DNS-intercept socket.
    pub udp_rx_meta_slots: usize,
    /// smoltcp UDP receive payload size for the DNS-intercept socket (bytes).
    pub udp_rx_payload_size: usize,
    /// smoltcp UDP transmit metadata slots for the DNS-intercept socket.
    pub udp_tx_meta_slots: usize,
    /// smoltcp UDP transmit payload size for the DNS-intercept socket (bytes).
    pub udp_tx_payload_size: usize,

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
            udp_rx_meta_slots: 32,
            udp_rx_payload_size: 8192,
            udp_tx_meta_slots: 32,
            udp_tx_payload_size: 8192,
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
