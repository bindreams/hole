//! Cross-sniffer tests: verify the entry point dispatches to the
//! right sub-sniffer and returns the first match. Per-sniffer
//! coverage lives in `sniffer/{tls_sni,http_host}_tests.rs`.

// The ClientHello builder below is deliberately step-by-step (see
// the matching note in `tls_sni_tests.rs`).
#![allow(clippy::vec_init_then_push)]

use super::*;

#[skuld::test]
fn peek_returns_none_for_empty_buffer() {
    assert_eq!(peek(b""), None);
}

#[skuld::test]
fn peek_returns_none_for_garbage() {
    let bytes = [0xff_u8; 64];
    assert_eq!(peek(&bytes), None);
}

#[skuld::test]
fn peek_extracts_http_host() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(peek(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn peek_extracts_tls_sni() {
    // Minimal TLS 1.2 ClientHello with SNI = "tls.example.com",
    // built using the same approach as `tls_sni_tests::build_client_hello`.
    let sni = "tls.example.com";
    let bytes = build_client_hello(sni);
    assert_eq!(peek(&bytes).as_deref(), Some(sni));
}

// Local copy of the ClientHello builder so this test file is
// self-contained (the one in `tls_sni_tests.rs` is private to that
// test module).
fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    let mut sni_ext_data = Vec::new();
    let server_name_list_len = (1 + 2 + sni_len) as u16;
    sni_ext_data.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_ext_data.push(0x00);
    sni_ext_data.extend_from_slice(&(sni_len as u16).to_be_bytes());
    sni_ext_data.extend_from_slice(sni_bytes);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000_u16.to_be_bytes());
    sni_ext.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_ext_data);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]);
    client_hello.extend_from_slice(&[0u8; 32]);
    client_hello.push(0x00);
    client_hello.extend_from_slice(&0x0002_u16.to_be_bytes());
    client_hello.extend_from_slice(&[0x00, 0x35]);
    client_hello.push(0x01);
    client_hello.push(0x00);
    client_hello.extend_from_slice(&extensions);

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
