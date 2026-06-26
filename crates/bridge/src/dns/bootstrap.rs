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

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

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

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod bootstrap_tests;
