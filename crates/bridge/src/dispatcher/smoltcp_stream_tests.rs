use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::SmoltcpStream;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

#[skuld::test]
fn read_receives_data_from_driver() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = SmoltcpStream::new();
        driver_tx.send(b"hello".to_vec()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    });
}

#[skuld::test]
fn write_sends_data_to_driver() {
    rt().block_on(async {
        let (mut stream, _driver_tx, mut driver_rx) = SmoltcpStream::new();
        stream.write_all(b"world").await.unwrap();

        let data = driver_rx.recv().await.unwrap();
        assert_eq!(data, b"world");
    });
}

#[skuld::test]
fn partial_read_buffers_remainder() {
    rt().block_on(async {
        let (mut stream, driver_tx, _driver_rx) = SmoltcpStream::new();
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
        let (mut stream, driver_tx, _driver_rx) = SmoltcpStream::new();
        drop(driver_tx);

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    });
}

#[skuld::test]
fn shutdown_closes_write_channel() {
    rt().block_on(async {
        let (mut stream, _driver_tx, mut driver_rx) = SmoltcpStream::new();
        stream.shutdown().await.unwrap();

        // The driver_rx should see channel closure.
        assert!(driver_rx.recv().await.is_none());
    });
}
