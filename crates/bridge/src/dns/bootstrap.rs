//! DoH bootstrap resolver: resolve the proxy server's hostname to an IP over
//! DoH using the user's configured `dns.servers`, BEFORE the tunnel exists —
//! so the OS resolver is never consulted for the proxy endpoint.
//!
//! Reuses the in-tunnel DoH machinery (`DnsForwarder` + `DirectConnector`):
//! same TLS config, same provider SNI table, same DoH POST framing — but a
//! DIRECT connector (the SOCKS5 tunnel is not up at bootstrap time).
//!
//! Query build/parse goes through `hickory-proto` (the crate the in-TUN
//! `LocalDnsEndpoint` path already links) rather than hand-rolling wire format.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hole_common::config::{DnsConfig, DnsProtocol};

use crate::dns::connector::DirectConnector;
use crate::dns::forwarder::DnsForwarder;

/// Typed bootstrap-resolution failure. `Display` strings are PII-FREE by
/// construction — no hostname, no filesystem path — so the
/// `ProxyError::DohBootstrap` that wraps this is safe to surface verbatim to a
/// toast (the hostname lands in `bridge.log` via the call-site WARN).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BootstrapError {
    /// The hostname is not a valid DNS name (bad label length / encoding).
    #[error("server hostname is not a valid DNS name")]
    InvalidName,
    /// No configured DoH resolver returned a usable A/AAAA answer.
    #[error("could not resolve the proxy server address via secure DNS")]
    NoAnswer,
}

/// Build an A-record query for `name` with transaction id `tx_id`.
pub fn build_a_query(name: &str, tx_id: u16) -> Result<Vec<u8>, BootstrapError> {
    build_query(name, tx_id, RecordType::A)
}

/// Build an AAAA-record query for `name` with transaction id `tx_id`.
pub fn build_aaaa_query(name: &str, tx_id: u16) -> Result<Vec<u8>, BootstrapError> {
    build_query(name, tx_id, RecordType::AAAA)
}

fn build_query(name: &str, tx_id: u16, rtype: RecordType) -> Result<Vec<u8>, BootstrapError> {
    let name = Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).map_err(|_| BootstrapError::InvalidName)?;
    // 3-arg `new`; header fields are pub on Metadata, set via `msg.metadata.*`.
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rtype));
    msg.to_vec().map_err(|_| BootstrapError::InvalidName)
}

/// Extract every A / AAAA address from a wire-format DNS reply. Returns an
/// empty Vec on any parse failure or an answerless reply — callers treat
/// "empty" as "this resolver did not answer".
pub fn parse_addrs(reply: &[u8]) -> Vec<IpAddr> {
    let Ok(msg) = Message::from_vec(reply) else {
        return Vec::new();
    };
    // `record.data` is the pub RData field; `RData::ip_addr()` yields
    // Some(IpAddr) for A/AAAA, None otherwise — no variant match needed.
    msg.answers.iter().filter_map(|rec| rec.data.ip_addr()).collect()
}

// Resolver ============================================================================================================

/// One DoH round-trip seam, mockable in tests. The production impl runs the
/// query through a `DnsForwarder` pinned to one resolver IP over a DIRECT
/// connector (tunnel not up). `doh_url` is the provider URL for `server`; the
/// `DnsForwarder` derives the same URL/SNI internally from its provider table,
/// so the arg exists for the trait's mock symmetry and logging — production
/// TLS verification is unchanged.
#[async_trait]
pub trait DohQuerier: Send + Sync {
    /// Return the wire-format reply, or `None` if this resolver did not answer
    /// (connect/TLS/HTTP failure or a SERVFAIL/answerless reply). Never errors.
    async fn query(&self, doh_url: &str, server: IpAddr, wire: &[u8]) -> Option<Vec<u8>>;
}

/// Production querier: a `DnsForwarder` over a `DirectConnector`, restricted to
/// a single resolver per call. `forward()` is infallible-by-design (returns
/// SERVFAIL bytes on total failure); a SERVFAIL/answerless reply parses to an
/// empty address list, which `resolve_via_doh_with` treats as "no answer".
struct ForwarderQuerier;

#[async_trait]
impl DohQuerier for ForwarderQuerier {
    async fn query(&self, _doh_url: &str, server: IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
        // One-server config so the forwarder targets exactly this resolver over
        // DoH. ipv6_bypass_available=true: bootstrap runs before the tunnel, on
        // the host's real stack, so do not suppress IPv6 resolvers.
        let cfg = DnsConfig {
            enabled: true,
            servers: vec![server],
            protocol: DnsProtocol::Https,
            allow_insecure_bootstrap: false,
        };
        let fwd = DnsForwarder::new(cfg, Arc::new(DirectConnector), true);
        Some(fwd.forward(wire).await)
    }
}

/// Resolve `host` to an IP over the configured DoH `dns.servers`. See the task
/// interface for the fail-closed / `allow_insecure_bootstrap` contract.
pub async fn resolve_via_doh(host: &str, dns: &DnsConfig) -> Result<IpAddr, BootstrapError> {
    resolve_via_doh_with(host, dns, Arc::new(ForwarderQuerier)).await
}

/// `resolve_via_doh` with an injected querier (test seam).
pub async fn resolve_via_doh_with(
    host: &str,
    dns: &DnsConfig,
    querier: Arc<dyn DohQuerier>,
) -> Result<IpAddr, BootstrapError> {
    // A literal IP needs no resolution — return as-is.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Fixed tx ids: DoH carries the query over an authenticated TLS channel, so
    // transport security — not the 16-bit id — is what defeats off-path spoofing.
    // Build both queries once: a builder failure is an InvalidName (malformed
    // hostname), surfaced as-is rather than masked as NoAnswer by the loop.
    let a_query = build_a_query(host, 0x0001)?;
    let aaaa_query = build_aaaa_query(host, 0x0002)?;

    let mut v6_fallback: Option<IpAddr> = None;
    for &server in &dns.servers {
        let url = hole_common::doh_url(server);
        if let Some(reply) = querier.query(&url, server, &a_query).await {
            if let Some(ip) = parse_addrs(&reply).into_iter().find(IpAddr::is_ipv4) {
                return Ok(ip); // IPv4 preferred for bypass-route compatibility.
            }
        }
        if v6_fallback.is_none() {
            if let Some(reply) = querier.query(&url, server, &aaaa_query).await {
                v6_fallback = parse_addrs(&reply).into_iter().find(IpAddr::is_ipv6);
            }
        }
    }

    if let Some(ip) = v6_fallback {
        return Ok(ip);
    }

    // Fail-closed: no configured resolver answered.
    if !dns.allow_insecure_bootstrap {
        return Err(BootstrapError::NoAnswer);
    }

    // Opt-in insecure fallback: the OS resolver. Prefer IPv4, same as above.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|_| BootstrapError::NoAnswer)?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or(BootstrapError::NoAnswer)
}

/// Format a resolved IP as the `server_host` handed to the plugin chain /
/// bypass. garter recombines it as `format!("{host}:{port}")`
/// (chain.rs:227), so an IPv6 literal MUST be bracketed or the recombined
/// string is an unparseable `addr:port`. V4 is returned plain.
pub fn handoff_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod bootstrap_tests;
