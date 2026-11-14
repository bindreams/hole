//! Connection-level domain sniffer.
//!
//! When the dispatcher accepts a new TCP connection it peeks the start of the
//! payload and asks the sniffer to extract a destination domain. The sniffer
//! tries TLS SNI first, then the HTTP Host header. If neither matches, the
//! connection falls through to IP-only matching.
//!
//! This is the only name-recovery mechanism: QUIC/UDP and non-TLS, non-HTTP
//! TCP are matched on IP only.
//!
//! Both submodules are pure functions over a `&[u8]` buffer.

pub mod http_host;
pub mod tls_sni;

/// Peek at the start of a TCP connection's payload and try to extract
/// a destination domain. Returns `Some(domain)` on success, `None` if
/// neither sniffer recognizes the bytes.
pub fn peek(buf: &[u8]) -> Option<String> {
    if let Some(sni) = tls_sni::extract_sni(buf) {
        return Some(sni);
    }
    if let Some(host) = http_host::extract_host(buf) {
        return Some(host);
    }
    None
}

#[cfg(test)]
#[path = "sniffer_tests.rs"]
mod sniffer_tests;
