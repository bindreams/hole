//! Optional DNS-interceptor hook for port-53 UDP hijacking.
//!
//! Port 53 is special: callers implementing domain-based filtering often
//! want to answer DNS queries with synthetic IPs so the TCP/UDP flow that
//! follows can be recognised and routed by domain. Rather than force every
//! consumer to reimplement packet construction, the engine exposes this
//! hook: it intercepts port-53 UDP datagrams off the TUN before smoltcp
//! sees them and delegates the actual DNS logic to the caller via
//! [`DnsInterceptor::intercept`].

use async_trait::async_trait;

/// Optional DNS-interceptor hook, set via `EngineConfig::dns_interceptor`.
///
/// For each inbound UDP datagram destined for port 53, the engine calls
/// `intercept(request)`:
///
/// - `Some(reply)` → the engine builds a raw IP+UDP reply packet (5-tuple
///   swapped, checksummed) and writes it straight to the TUN so the kernel
///   sees a normal DNS reply, without forwarding the request to the Router.
/// - `None` → the engine passes the datagram through to `Router::route_udp`
///   like any other UDP flow.
#[async_trait]
pub trait DnsInterceptor: Send + Sync + 'static {
    async fn intercept(&self, request: &[u8]) -> Option<Vec<u8>>;
}
