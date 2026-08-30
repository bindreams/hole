//! An in-memory TUN device, so `Engine::from_io` can be driven without an OS
//! device.
//!
//! ## Framing contract
//!
//! One `poll_read` on the [`SimTun`] side yields exactly one packet injected
//! via [`SimWire::inject`]; one `write_all` on that side enqueues exactly one
//! egress packet, retrievable via [`SimWire::next_egress`]. This mirrors what
//! [`Engine::from_io`](crate::Engine::from_io) documents about a real
//! device.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Which direction a packet crossed the wire, as seen by a [`WireTap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Injected by the peer, read by the engine.
    ToEngine,
    /// Written by the engine, retrieved by the peer.
    FromEngine,
}

enum Ingress {
    Packet(Vec<u8>),
    Err(io::ErrorKind),
}

/// Build a connected [`SimTun`]/[`SimWire`] pair. `capacity` bounds both
/// directions' queues.
pub fn packet_pair(capacity: usize) -> (SimTun, SimWire) {
    let (ingress_tx, ingress_rx) = mpsc::channel(capacity);
    let (egress_tx, egress_rx) = mpsc::channel(capacity);
    let tun = SimTun {
        ingress_rx,
        egress_tx: PollSender::new(egress_tx),
    };
    let wire = SimWire {
        ingress_tx,
        egress_rx,
        tap: None,
    };
    (tun, wire)
}

/// The engine-facing end of the pair — an `AsyncRead + AsyncWrite` standing
/// in for `tun::AsyncDevice`. See the module doc for the framing contract.
pub struct SimTun {
    ingress_rx: mpsc::Receiver<Ingress>,
    egress_tx: PollSender<Vec<u8>>,
}

impl AsyncRead for SimTun {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.ingress_rx.poll_recv(cx) {
            Poll::Ready(Some(Ingress::Packet(pkt))) => {
                assert!(
                    pkt.len() <= buf.remaining(),
                    "SimTun read buffer too small for queued packet: buffer={} packet={}",
                    buf.remaining(),
                    pkt.len()
                );
                buf.put_slice(&pkt);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ingress::Err(kind))) => Poll::Ready(Err(io::Error::from(kind))),
            // The `SimWire` was dropped: EOF, matching a real TUN read
            // returning `Ok(0)`. `ReadBuf` starts with nothing filled, so a
            // bare `Ok(())` here IS that `Ok(0)`.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SimTun {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.egress_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let pkt = buf.to_vec();
                let len = pkt.len();
                self.egress_tx
                    .send_item(pkt)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SimWire dropped"))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "SimWire dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.egress_tx.close();
        Poll::Ready(Ok(()))
    }
}

/// The test/peer-facing end of the pair.
pub struct SimWire {
    ingress_tx: mpsc::Sender<Ingress>,
    egress_rx: mpsc::Receiver<Vec<u8>>,
    tap: Option<mpsc::UnboundedSender<(Direction, Vec<u8>)>>,
}

impl SimWire {
    /// Inject a packet as if it arrived from the network. Backpressures like
    /// a real device once `capacity` packets are queued.
    pub async fn inject(&self, packet: Vec<u8>) {
        if let Some(tap) = &self.tap {
            let _ = tap.send((Direction::ToEngine, packet.clone()));
        }
        self.ingress_tx
            .send(Ingress::Packet(packet))
            .await
            .expect("SimWire::inject after the engine already exited: SimTun's ingress channel is closed");
    }

    /// Wait for the engine's next egress packet.
    pub async fn next_egress(&mut self) -> Option<Vec<u8>> {
        let pkt = self.egress_rx.recv().await;
        if let (Some(tap), Some(pkt)) = (&self.tap, &pkt) {
            let _ = tap.send((Direction::FromEngine, pkt.clone()));
        }
        pkt
    }

    /// Non-blocking form of [`Self::next_egress`], for asserting a channel
    /// is empty at a happens-after edge.
    pub fn try_next_egress(&mut self) -> Option<Vec<u8>> {
        let pkt = self.egress_rx.try_recv().ok();
        if let (Some(tap), Some(pkt)) = (&self.tap, &pkt) {
            let _ = tap.send((Direction::FromEngine, pkt.clone()));
        }
        pkt
    }

    /// Queue an `Err` of `kind` as the next thing the engine reads, ahead of
    /// anything injected after this call — what a real device surfaces on
    /// failure.
    pub fn fail_next_read(&self, kind: io::ErrorKind) {
        match self.ingress_tx.try_send(Ingress::Err(kind)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                panic!("fail_next_read: ingress queue full — grow packet_pair's capacity")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                panic!("fail_next_read after the engine already exited: SimTun's ingress channel is closed")
            }
        }
    }

    /// Observe every packet crossing the wire in either direction from this
    /// point on. Install before handing the wire to something that takes it
    /// by value — that is the only way to keep observing packets once
    /// ownership moves. Unbounded: a tap is a test double with no consumer
    /// to backpressure, so a bound would only trade a hang for a silent drop.
    pub fn tap(&mut self) -> WireTap {
        let (tx, rx) = mpsc::unbounded_channel();
        self.tap = Some(tx);
        WireTap { rx }
    }
}

/// A cloned view of every packet crossing a [`SimWire`], installed via
/// [`SimWire::tap`].
pub struct WireTap {
    rx: mpsc::UnboundedReceiver<(Direction, Vec<u8>)>,
}

impl WireTap {
    pub async fn next(&mut self) -> Option<(Direction, Vec<u8>)> {
        self.rx.recv().await
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
