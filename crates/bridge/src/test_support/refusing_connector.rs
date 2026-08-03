//! An `UpstreamConnector` that refuses, for tests that need a connect-layer
//! failure from the DNS forwarder.

use std::io;
use std::net::SocketAddr;

use crate::dns::connector::{ConnectedStream, DirectConnector, UpstreamConnector, UpstreamUdp};

/// Refuses `connect_tcp` / `connect_udp` with `ConnectionRefused`.
///
/// Deliberately used INSTEAD of a real closed socket. "Connect to a port
/// nothing is listening on" has no portable failure shape, so it cannot pin an
/// exact failure layer: macOS black-holes connects to a bound-but-unlistened
/// socket (the attempt runs to the full budget and reports `layer=timeout`
/// rather than `layer=connect`), and GitHub's Windows runners drop SYNs to
/// closed ephemeral loopback ports (see `server_test_tests.rs`). A released
/// ephemeral port is also re-bindable by a concurrent test.
///
/// `UpstreamConnector` is the codebase's seam for exactly this: the OS socket
/// is not what these tests are about — the classification and logging of a
/// connect-layer failure is.
#[derive(Debug)]
pub(crate) struct RefusingConnector {
    /// Addresses to refuse. Empty = refuse everything; otherwise anything not
    /// listed is dialled for real, so a test can pair a refused primary with a
    /// live secondary.
    refuse: Vec<SocketAddr>,
}

impl RefusingConnector {
    /// Refuse every target.
    pub(crate) fn all() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { refuse: Vec::new() })
    }

    /// Refuse only `refuse`; dial anything else for real.
    pub(crate) fn only(refuse: Vec<SocketAddr>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { refuse })
    }

    fn refuses(&self, target: SocketAddr) -> bool {
        self.refuse.is_empty() || self.refuse.contains(&target)
    }
}

#[async_trait::async_trait]
impl UpstreamConnector for RefusingConnector {
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream> {
        if self.refuses(target) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refusing connector"));
        }
        DirectConnector.connect_tcp(target).await
    }

    async fn connect_udp(&self, target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        if self.refuses(target) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refusing connector"));
        }
        DirectConnector.connect_udp(target).await
    }
}
