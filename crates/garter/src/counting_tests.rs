use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

/// Round-trip a known payload through a CountingStream pair and assert
/// the counters match. Runs in its own one-shot tokio runtime so the
/// test doesn't entangle with skuld's scheduler.
#[skuld::test]
async fn counts_bytes_roundtripped() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
        s.flush().await.unwrap();
    });

    let raw = TcpStream::connect(addr).await.unwrap();
    let mut counted = CountingStream::new(raw);
    let counters = counted.counters();

    counted.write_all(b"hello").await.unwrap();
    counted.flush().await.unwrap();
    let mut buf = [0u8; 5];
    counted.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, b"hello");
    assert_eq!(counters.written(), 5);
    assert_eq!(counters.read(), 5);
    assert!(counters.first_read_at().is_some(), "first_read_at set after first byte");

    server.await.unwrap();
}

#[skuld::test]
async fn first_read_at_is_none_when_no_bytes_arrive() {
    // Server accepts but immediately closes without writing anything.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        drop(s);
    });

    let raw = TcpStream::connect(addr).await.unwrap();
    let mut counted = CountingStream::new(raw);
    let counters = counted.counters();

    let mut buf = [0u8; 4];
    // Reading from a peer-closed stream returns Ok(0) (EOF) on first read.
    let n = counted.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
    assert_eq!(counters.read(), 0);
    assert!(
        counters.first_read_at().is_none(),
        "first_read_at must remain None when no non-zero read ever happened"
    );

    server.await.unwrap();
}

#[skuld::test]
async fn first_read_at_does_not_update_after_first_set() {
    // Two separate writes from the server; counter must reflect the FIRST one's time.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"a").await.unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        s.write_all(b"b").await.unwrap();
        s.flush().await.unwrap();
    });

    let raw = TcpStream::connect(addr).await.unwrap();
    let mut counted = CountingStream::new(raw);
    let counters = counted.counters();

    let mut buf = [0u8; 1];
    counted.read_exact(&mut buf).await.unwrap();
    let first_at = counters.first_read_at().expect("first_read_at set after byte 1");
    counted.read_exact(&mut buf).await.unwrap();
    let still = counters.first_read_at().expect("first_read_at survives byte 2");
    assert_eq!(first_at, still, "first_read_at should not update on subsequent reads");
    assert_eq!(counters.read(), 2);

    server.await.unwrap();
}
