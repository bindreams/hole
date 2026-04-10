use super::*;

#[skuld::test]
#[ignore] // Requires network — run manually with `cargo test -- --ignored`
fn bypass_socket_connects_to_loopback() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // interface_index=1 is typically the loopback on both Windows and macOS.
        let (connect_result, _accept) = tokio::join!(create_bypass_tcp(addr.ip(), addr.port(), 1), listener.accept());
        assert!(
            connect_result.is_ok(),
            "bypass connect failed: {:?}",
            connect_result.err()
        );
    });
}
