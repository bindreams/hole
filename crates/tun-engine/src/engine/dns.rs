//! Optional DNS-interceptor hook for port-53 UDP hijacking.
//!
//! Port 53 is special: callers implementing domain-based filtering often
//! want to answer DNS queries with synthetic IPs so the TCP/UDP flow that
//! follows can be recognised and routed by domain. Rather than force every
//! consumer to reimplement packet construction and the smoltcp UDP
//! short-circuit, the engine exposes this hook: it serves port-53 UDP
//! inside smoltcp and delegates the actual DNS logic to the caller via
//! [`DnsInterceptor::intercept`].

use async_trait::async_trait;

/// Optional DNS-interceptor hook, set via `EngineConfig::dns_interceptor`.
///
/// For each inbound UDP datagram destined for port 53, the engine calls
/// `intercept(request)`:
///
/// - `Some(reply)` → the engine emits `reply` as the UDP response and does
///   not forward the request to the Router. The bytes are injected via
///   smoltcp's UDP socket so the kernel sees a normal DNS reply.
/// - `None` → the engine passes the datagram through to `Router::route_udp`
///   like any other UDP flow.
#[async_trait]
pub trait DnsInterceptor: Send + Sync + 'static {
    async fn intercept(&self, request: &[u8]) -> Option<Vec<u8>>;
}
