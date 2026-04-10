use super::*;
use std::net::Ipv4Addr;

#[skuld::test]
fn socks5_connect_refuses_when_no_server() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(socks5_connect(1, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80, None));

    assert!(result.is_err(), "expected error when no SOCKS5 server is listening");
}
