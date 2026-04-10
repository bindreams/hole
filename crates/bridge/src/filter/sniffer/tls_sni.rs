//! TLS Server Name Indication (SNI) extraction.
//!
//! Walks the TLS plaintext record at the head of the buffer, finds
//! the ClientHello handshake message, parses its extensions, and
//! returns the first hostname from the `server_name` extension.
//!
//! Limitations (deferred to v2):
//! - Fragmented ClientHellos that span multiple TLS records are
//!   reported as `None`. The pre-encryption ClientHello is normally
//!   small enough to fit in a single record.
//! - Encrypted Client Hello (ECH / draft-ietf-tls-esni) is reported
//!   as `None`.

use tls_parser::{parse_tls_extensions, parse_tls_plaintext, SNIType, TlsExtension, TlsMessage, TlsMessageHandshake};

/// Try to extract the SNI hostname from the start of a TCP payload.
/// Returns `None` if the buffer doesn't begin with a parseable TLS
/// ClientHello, or if no SNI extension is present.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let (_, plaintext) = parse_tls_plaintext(buf).ok()?;
    for msg in plaintext.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            return extract_sni_from_extensions(ch.ext?);
        }
    }
    None
}

fn extract_sni_from_extensions(ext_bytes: &[u8]) -> Option<String> {
    let (_, extensions) = parse_tls_extensions(ext_bytes).ok()?;
    for ext in extensions {
        if let TlsExtension::SNI(names) = ext {
            for (sni_type, name_bytes) in names {
                // SNIType::HostName is the only currently-defined type
                // (RFC 6066). Skip anything else.
                if sni_type == SNIType::HostName {
                    if let Ok(s) = std::str::from_utf8(name_bytes) {
                        if !s.is_empty() {
                            return Some(s.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "tls_sni_tests.rs"]
mod tls_sni_tests;
