//! A [`Router`] double that records every dispatched flow instead of acting
//! on it, so a test can drive the driver over a real wire and assert on
//! dispatch without a proxy, a bypass socket, or any of a consumer's own
//! cascade.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::engine::{Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta};

/// One flow the router dispatched.
///
/// Holds `release`: firing it (or dropping it) is what lets `route_tcp`/
/// `route_udp` return, which drops the flow and — for TCP — releases the
/// connection's permit. A test that never touches `release` for a given
/// dispatch is deliberately holding that flow open for the rest of the
/// test.
pub enum Dispatch {
    Tcp {
        meta: TcpMeta,
        flow: TcpFlow,
        release: oneshot::Sender<()>,
    },
    Udp {
        meta: UdpMeta,
        flow: UdpFlow,
        release: oneshot::Sender<()>,
    },
}

struct RecordingRouter {
    tx: mpsc::Sender<Dispatch>,
}

#[async_trait]
impl Router for RecordingRouter {
    async fn route_tcp(&self, meta: TcpMeta, flow: TcpFlow) -> io::Result<()> {
        let (release, released) = oneshot::channel();
        self.tx
            .send(Dispatch::Tcp { meta, flow, release })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test dropped the Dispatch receiver"))?;
        let _ = released.await;
        Ok(())
    }

    async fn route_udp(&self, meta: UdpMeta, flow: UdpFlow) -> io::Result<()> {
        let (release, released) = oneshot::channel();
        self.tx
            .send(Dispatch::Udp { meta, flow, release })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test dropped the Dispatch receiver"))?;
        let _ = released.await;
        Ok(())
    }
}

/// A [`Router`] that reports every dispatched flow on the returned channel.
pub fn recording_router() -> (Arc<dyn Router>, mpsc::Receiver<Dispatch>) {
    let (tx, rx) = mpsc::channel(64);
    (Arc::new(RecordingRouter { tx }), rx)
}
