//! Connection-level domain sniffer.
//!
//! When the dispatcher (Plans 2/3) accepts a new TCP connection and
//! the fake DNS reverse lookup misses, it peeks the first ~2 KiB of
//! payload and asks the sniffer to extract a domain. The sniffer
//! tries TLS SNI first (covers ~all HTTPS/DoH/DoT/SMTPS/IMAPS), then
//! HTTP Host header (covers plaintext HTTP). If neither matches, the
//! connection falls through to IP-only matching.
//!
//! Both submodules are pure functions over a `&[u8]` buffer. Tests
//! exercise them with static fixtures of real ClientHellos and HTTP
//! requests.

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
