use super::*;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-sock-test-{}-{suffix}.sock", std::process::id()))
}

#[skuld::test]
fn bind_and_accept() {
    rt().block_on(async {
        let path = test_socket_path("bind-accept");
        let listener = LocalListener::bind(&path).unwrap();

        let client_handle = tokio::spawn({
            let path = path.clone();
            async move {
                let mut stream = LocalStream::connect(&path).await.unwrap();
                stream.write_all(b"hello").await.unwrap();
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"world");
            }
        });

        let mut server_stream = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        server_stream.write_all(b"world").await.unwrap();

        client_handle.await.unwrap();

        // Cleanup
        let _ = std::fs::remove_file(&path);
    });
}

#[skuld::test]
fn stale_socket_cleanup() {
    let path = test_socket_path("stale");

    // Create a regular file at the path (simulates stale socket)
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, "stale").unwrap();
    assert!(path.exists());

    // Binding should succeed (removes the stale file first)
    rt().block_on(async {
        let _listener = LocalListener::bind(&path).unwrap();
        // The socket file now exists (created by bind)
        assert!(path.exists());
    });

    // Cleanup
    let _ = std::fs::remove_file(&path);
}

#[skuld::test]
fn connect_nonexistent_fails() {
    rt().block_on(async {
        let path = test_socket_path("nonexistent");
        let _ = std::fs::remove_file(&path); // Ensure it doesn't exist
        let result = LocalStream::connect(&path).await;
        assert!(result.is_err());
    });
}
