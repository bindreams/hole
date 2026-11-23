//! What [`drive_connection`] promises the code that asks it for substreams: a substream that was asked for and
//! written to has reached the peer, whatever else the connection is doing.
//!
//! Every party runs on one single-threaded executor, over an in-memory pipe, with no tokio runtime and no clock. The
//! executor is run until no task is woken. A driver that fails to poll the connection after creating a substream
//! leaves that substream's first frame unsent, and nothing wakes it until an unrelated event (inbound data, another
//! open, yamux's own ping about ten seconds later), so a test that polled the driver again unprompted, or waited on a
//! timer, would send the frame itself and could not see the defect.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use futures::executor::LocalPool;
use futures::task::LocalSpawnExt as _;
use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use crate::yamux::{drive_connection, open_stream, OpenStreamReply, StreamTag, TransportLivenessTap};

/// What the peer read from one accepted substream: the tag byte and the payload byte.
type Received = Rc<RefCell<Vec<[u8; 2]>>>;

/// A client connection driven by [`drive_connection`] and a peer connection driven by the same function, as the
/// galoshes server drives its half, joined by an in-memory pipe. The peer records what each accepted substream
/// delivered.
struct Rig {
    pool: LocalPool,
    open_tx: mpsc::Sender<OpenStreamReply>,
    received: Received,
}

impl Rig {
    fn new() -> Self {
        let pool = LocalPool::new();
        let spawner = pool.spawner();
        let (client_io, peer_io) = tokio::io::duplex(256 * 1024);

        let tapped = TransportLivenessTap::new(client_io.compat(), Arc::new(AtomicU64::new(0)));
        let client = yamux::Connection::new(tapped, yamux::Config::default(), yamux::Mode::Client);
        let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (inbound_tx, client_inbound_rx) = mpsc::channel::<yamux::Stream>(32);
        spawner
            .spawn_local(async move {
                // Held so that the channel stays open, as the session's receiver keeps it in production.
                let _client_inbound_rx = client_inbound_rx;
                drive_connection(client, open_rx, inbound_tx).await;
            })
            .unwrap();

        let peer = yamux::Connection::new(peer_io.compat(), yamux::Config::default(), yamux::Mode::Server);
        let (peer_open_tx, peer_open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (peer_inbound_tx, mut peer_inbound_rx) = mpsc::channel::<yamux::Stream>(64);
        let received = Received::default();
        let sink = Rc::clone(&received);
        let accept_spawner = spawner.clone();
        spawner
            .spawn_local(async move {
                // The server half never opens substreams; it holds the sender, as `serve_underlying` does.
                let _peer_open_tx = peer_open_tx;
                drive_connection(peer, peer_open_rx, peer_inbound_tx).await;
            })
            .unwrap();
        spawner
            .spawn_local(async move {
                while let Some(mut stream) = peer_inbound_rx.recv().await {
                    let sink = Rc::clone(&sink);
                    accept_spawner
                        .spawn_local(async move {
                            let mut bytes = [0u8; 2];
                            if stream.read_exact(&mut bytes).await.is_ok() {
                                sink.borrow_mut().push(bytes);
                            }
                        })
                        .unwrap();
                }
            })
            .unwrap();

        Self {
            pool,
            open_tx,
            received,
        }
    }

    /// Ask the driver for a substream and write `payload` on it, then keep it open.
    fn open_and_write(&self, payload: u8) {
        let open_tx = self.open_tx.clone();
        self.pool
            .spawner()
            .spawn_local(async move {
                let mut stream = open_stream(&open_tx).await.expect("the driver opened the substream");
                stream.write_all(&[StreamTag::Tcp.to_byte(), payload]).await.unwrap();
                stream.flush().await.unwrap();
                std::future::pending::<()>().await;
            })
            .unwrap();
    }

    fn received(&self) -> Vec<[u8; 2]> {
        self.received.borrow().clone()
    }
}

#[skuld::test]
fn a_substream_opened_beside_an_idle_one_reaches_the_peer_without_another_wake() {
    let mut rig = Rig::new();
    let tcp = StreamTag::Tcp.to_byte();

    rig.open_and_write(b'a');
    rig.pool.run_until_stalled();
    assert_eq!(
        rig.received(),
        vec![[tcp, b'a']],
        "precondition: the first substream reached the peer and the connection then went quiet"
    );

    rig.open_and_write(b'b');
    rig.pool.run_until_stalled();
    assert_eq!(
        rig.received(),
        vec![[tcp, b'a'], [tcp, b'b']],
        "the second substream, asked for and written to while the first is open, must reach the peer \
         before anything else happens on the connection"
    );
}
