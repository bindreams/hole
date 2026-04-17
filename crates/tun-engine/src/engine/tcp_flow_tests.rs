use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use super::TcpFlow;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn sem() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(1024))
}

// AsyncRead / AsyncWrite ==============================================================================================

#[skuld::test]
fn read_receives_data_from_driver() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"hello".to_vec()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    });
}

#[skuld::test]
fn write_sends_data_to_driver() {
    rt().block_on(async {
        let (mut stream, _driver_tx, mut driver_rx) = TcpFlow::new(sem());
        stream.write_all(b"world").await.unwrap();

        let data = driver_rx.recv().await.unwrap();
        assert_eq!(data, b"world");
    });
}

#[skuld::test]
fn partial_read_buffers_remainder() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"abcdef".to_vec()).await.unwrap();

        // Read only 3 bytes — the remaining 3 should be buffered internally.
        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"abc");

        // Second read should return the buffered remainder.
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"def");
    });
}

#[skuld::test]
fn read_returns_eof_when_channel_closed() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        drop(driver_tx);

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    });
}

#[skuld::test]
fn shutdown_closes_write_channel() {
    rt().block_on(async {
        let (mut stream, _driver_tx, mut driver_rx) = TcpFlow::new(sem());
        stream.shutdown().await.unwrap();

        // The driver_rx should see channel closure.
        assert!(driver_rx.recv().await.is_none());
    });
}

// peek ================================================================================================================

#[skuld::test]
fn peek_returns_available_bytes() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"GET / HTTP/1.1\r\n".to_vec()).await.unwrap();

        let peeked = stream.peek(16, Duration::from_millis(100)).await.unwrap();
        assert_eq!(peeked, b"GET / HTTP/1.1\r\n");
    });
}

#[skuld::test]
fn peek_does_not_consume_bytes_for_read() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"abcdef".to_vec()).await.unwrap();

        let peeked = stream.peek(6, Duration::from_millis(100)).await.unwrap();
        assert_eq!(peeked, b"abcdef");

        // Subsequent read() must still see the peeked bytes.
        let mut buf = [0u8; 6];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf[..n], b"abcdef");
    });
}

#[skuld::test]
fn peek_times_out_returning_partial_bytes() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        // Only 3 bytes arrive — ask for 10 with a short timeout.
        driver_tx.send(b"abc".to_vec()).await.unwrap();

        let peeked = stream.peek(10, Duration::from_millis(50)).await.unwrap();
        assert_eq!(peeked, b"abc");
    });
}

#[skuld::test]
fn peek_is_idempotent() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"abc".to_vec()).await.unwrap();

        let a = stream.peek(3, Duration::from_millis(100)).await.unwrap().to_vec();
        let b = stream.peek(3, Duration::from_millis(100)).await.unwrap().to_vec();
        assert_eq!(a, b);
        assert_eq!(a, b"abc");
    });
}

#[skuld::test]
fn peek_extends_buffer_on_subsequent_call() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"abc".to_vec()).await.unwrap();

        let first = stream.peek(3, Duration::from_millis(100)).await.unwrap().to_vec();
        assert_eq!(first, b"abc");

        // More data arrives — a second peek with a larger `n` sees both.
        driver_tx.send(b"def".to_vec()).await.unwrap();
        let second = stream.peek(6, Duration::from_millis(100)).await.unwrap().to_vec();
        assert_eq!(second, b"abcdef");
    });
}

#[skuld::test]
fn peek_on_closed_channel_returns_what_is_buffered() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = TcpFlow::new(sem());
        driver_tx.send(b"xy".to_vec()).await.unwrap();
        drop(driver_tx);

        let peeked = stream.peek(100, Duration::from_millis(100)).await.unwrap();
        assert_eq!(peeked, b"xy");
    });
}
