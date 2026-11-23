use super::*;
use crate::sentinel::start_fake_sentinel;
use crate::util::rt;
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The loopback interface as the library names it on this platform: the adapter's friendly name on Windows, the
/// device name elsewhere.
#[cfg(windows)]
const LOOPBACK_INTERFACE: &str = "Loopback Pseudo-Interface 1";
#[cfg(target_os = "linux")]
const LOOPBACK_INTERFACE: &str = "lo";
#[cfg(target_os = "macos")]
const LOOPBACK_INTERFACE: &str = "lo0";

const NO_SUCH_INTERFACE: &str = "no-such-interface-for-the-plugin-e2e-test";

/// Ask `server` to relay a `HEAD /` to a fresh sentinel on loopback; whether an `HTTP` reply came back.
///
/// A server whose dial to the sentinel fails closes the client's connection, which reads as end of input: no wait on
/// a clock decides this.
async fn relays_to_a_sentinel(server: SocketAddr) -> bool {
    let (sentinel, _task) = start_fake_sentinel(b"HTTP/1.0 200 OK\r\n\r\n".to_vec()).await;
    let svr_cfg = ServerConfig::new(server, TEST_PASSWORD, TEST_METHOD).unwrap();
    let ctx: SharedContext = Context::new_shared(shadowsocks::config::ServerType::Local);
    let mut stream = ProxyClientStream::connect(ctx, &svr_cfg, Address::SocketAddress(sentinel))
        .await
        .expect("the client reaches the server itself");
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
    let mut reply = Vec::new();
    // An error here is the same answer as end of input: the server closed on a failed dial, by FIN or by RST.
    let _ = stream.read_to_end(&mut reply).await;
    reply.starts_with(b"HTTP")
}

#[skuld::test]
fn the_server_dials_through_the_interface_it_is_given() {
    rt().block_on(async {
        let (plain, _plain) = start_real_ss_server(TEST_METHOD, TEST_PASSWORD).await;
        assert!(
            relays_to_a_sentinel(plain).await,
            "control: a server given no interface relays to a loopback target"
        );

        let (named, _named) = start_real_ss_server_via(TEST_METHOD, TEST_PASSWORD, Some(LOOPBACK_INTERFACE)).await;
        assert!(
            relays_to_a_sentinel(named).await,
            "a server told to dial out of {LOOPBACK_INTERFACE:?} relays to a target on that interface"
        );

        // An interface the machine does not have cannot carry the dial; only an applied setting can fail it.
        let (bogus, _bogus) = start_real_ss_server_via(TEST_METHOD, TEST_PASSWORD, Some(NO_SUCH_INTERFACE)).await;
        assert!(
            !relays_to_a_sentinel(bogus).await,
            "a server told to dial out of {NO_SUCH_INTERFACE:?} still relayed: the setting did not reach its dials"
        );
    });
}
