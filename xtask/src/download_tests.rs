use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;

/// One-connection-per-response HTTP server writing `responses` (raw bytes, head
/// included) in order. Returns the URL and a count of the requests served.
fn serve(responses: Vec<Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            // The peer may have given up on a refused or truncated exchange.
            let _ = stream.write_all(&response);
        }
    });
    (url, served)
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A response that promises 100 bytes and delivers `body`, then closes.
fn truncated(body: &[u8]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".to_vec();
    out.extend_from_slice(body);
    out
}

fn status(code: u16) -> Vec<u8> {
    format!("HTTP/1.1 {code} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

#[skuld::test]
fn keeps_fetching_past_truncated_bodies_until_the_pinned_hash_arrives() {
    let (url, served) = serve(vec![
        truncated(b"trunc"),
        truncated(b"truncated again"),
        ok(b"the artifact"),
    ]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 3);
}

#[skuld::test]
fn a_complete_body_with_the_wrong_hash_is_not_retried() {
    let (url, served) = serve(vec![ok(b"not the artifact"), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(format!("{err:#}").contains("hash mismatch"), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn a_client_error_status_is_not_retried() {
    let (url, served) = serve(vec![status(404), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(format!("{err:#}").contains("404"), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn a_server_error_status_is_retried() {
    let (url, served) = serve(vec![status(503), ok(b"the artifact")]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 2);
}

#[skuld::test]
fn a_body_over_the_size_limit_is_not_retried() {
    let (url, served) = serve(vec![ok(b"0123456789"), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 4, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(crate::retry::is_permanent(&err), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}
