// The TLS record builders below are deliberately written as
// `Vec::new()` followed by `push`/`extend_from_slice` so each header
// field is on its own line and matches the wire format step by step.
// `vec![...]` would obscure the structure for no real benefit.
#![allow(clippy::vec_init_then_push)]

use super::*;

// ClientHello builder =================================================================================================

/// Build a minimal valid TLS 1.2 ClientHello record carrying a single
/// SNI hostname. The structure follows RFC 5246 §7.4.1.2 plus
/// RFC 6066 §3 for the SNI extension. This is just enough to satisfy
/// `tls-parser`'s `parse_tls_plaintext` and reach the SNI extraction
/// path.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension data (server_name_list).
    let mut sni_ext_data = Vec::new();
    let server_name_list_len = (1 + 2 + sni_len) as u16;
    sni_ext_data.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_ext_data.push(0x00); // NameType.HostName
    sni_ext_data.extend_from_slice(&(sni_len as u16).to_be_bytes());
    sni_ext_data.extend_from_slice(sni_bytes);

    // SNI extension wrapper (type + length + data).
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000_u16.to_be_bytes()); // ExtensionType.server_name
    sni_ext.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_ext_data);

    // Extensions block (just the SNI extension).
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // ClientHello body.
    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]); // ProtocolVersion: TLS 1.2
    client_hello.extend_from_slice(&[0u8; 32]); // Random
    client_hello.push(0x00); // session_id length = 0
    client_hello.extend_from_slice(&0x0002_u16.to_be_bytes()); // cipher_suites length
    client_hello.extend_from_slice(&[0x00, 0x35]); // TLS_RSA_WITH_AES_256_CBC_SHA
    client_hello.push(0x01); // compression_methods length
    client_hello.push(0x00); // null compression
    client_hello.extend_from_slice(&extensions);

    // Handshake header (msg_type + 24-bit length).
    let body_len = client_hello.len();
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&client_hello);

    // TLS plaintext record header.
    let record_len = handshake.len();
    let mut record = Vec::new();
    record.push(0x16); // ContentType.handshake
    record.push(0x03); // legacy_record_version major
    record.push(0x01); // legacy_record_version minor (1.0 by convention)
    record.push(((record_len >> 8) & 0xff) as u8);
    record.push((record_len & 0xff) as u8);
    record.extend_from_slice(&handshake);

    record
}

/// Build a ClientHello record with no extensions. Used to test the
/// "no SNI present" case.
fn build_client_hello_no_extensions() -> Vec<u8> {
    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]);
    client_hello.extend_from_slice(&[0u8; 32]);
    client_hello.push(0x00);
    client_hello.extend_from_slice(&0x0002_u16.to_be_bytes());
    client_hello.extend_from_slice(&[0x00, 0x35]);
    client_hello.push(0x01);
    client_hello.push(0x00);
    // No extensions block at all (TLS 1.2 allows the field to be omitted).

    let body_len = client_hello.len();
    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&client_hello);

    let record_len = handshake.len();
    let mut record = Vec::new();
    record.push(0x16);
    record.push(0x03);
    record.push(0x01);
    record.push(((record_len >> 8) & 0xff) as u8);
    record.push((record_len & 0xff) as u8);
    record.extend_from_slice(&handshake);

    record
}

// Positive cases ======================================================================================================

#[skuld::test]
fn extracts_sni_from_minimal_client_hello() {
    let bytes = build_client_hello("example.com");
    assert_eq!(extract_sni(&bytes).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_sni_lowercases_uppercase_hostname() {
    let bytes = build_client_hello("Example.COM");
    assert_eq!(extract_sni(&bytes).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_sni_with_subdomain() {
    let bytes = build_client_hello("api.v2.example.com");
    assert_eq!(extract_sni(&bytes).as_deref(), Some("api.v2.example.com"));
}

#[skuld::test]
fn extracts_sni_with_trailing_extra_bytes() {
    // `parse_tls_plaintext` consumes one record; trailing bytes are
    // returned as the unconsumed remainder. We don't care.
    let mut bytes = build_client_hello("trailing.test");
    bytes.extend_from_slice(&[0xab, 0xcd, 0xef]);
    assert_eq!(extract_sni(&bytes).as_deref(), Some("trailing.test"));
}

// Negative cases ======================================================================================================

#[skuld::test]
fn returns_none_for_empty_buffer() {
    assert_eq!(extract_sni(b""), None);
}

#[skuld::test]
fn returns_none_for_garbage_bytes() {
    let bytes = [0xff_u8; 64];
    assert_eq!(extract_sni(&bytes), None);
}

#[skuld::test]
fn returns_none_for_non_handshake_record() {
    // Application data record (type 0x17) — should not match.
    let payload = [0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
    assert_eq!(extract_sni(&payload), None);
}

#[skuld::test]
fn returns_none_for_truncated_record() {
    let bytes = build_client_hello("example.com");
    let truncated = &bytes[..bytes.len() / 2];
    assert_eq!(extract_sni(truncated), None);
}

#[skuld::test]
fn returns_none_when_no_extensions() {
    let bytes = build_client_hello_no_extensions();
    assert_eq!(extract_sni(&bytes), None);
}

#[skuld::test]
fn returns_none_for_one_byte_buffer() {
    assert_eq!(extract_sni(&[0x16]), None);
}
