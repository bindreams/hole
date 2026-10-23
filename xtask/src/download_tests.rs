use std::io::{Read, Write};
use std::net::TcpListener;

use super::*;

/// One-connection-per-response HTTP server answering `bodies` in order.
fn serve(bodies: Vec<&'static [u8]>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for body in bodies {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        }
    });
    url
}

#[skuld::test]
fn keeps_fetching_past_wrong_bodies_until_the_pinned_hash_arrives() {
    // The first two bodies stand in for a truncated download.
    let url = serve(vec![b"trunc", b"truncated again", b"the artifact"]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
}
