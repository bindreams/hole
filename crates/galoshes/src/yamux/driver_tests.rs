//! A substream that was asked for and written to has reached the peer, whatever else the connection is doing. When the
//! connection ends, the driver finishes and its caller learns it.
//!
//! Everything runs on one single-threaded executor over an in-memory pipe, run until no task is woken. A test that
//! polled the driver unprompted, or waited on a timer, would send the frame itself and hide a missed poll.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use futures::executor::LocalPool;
use futures::task::LocalSpawnExt as _;
use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use crate::yamux::{drive_connection, open_stream, OpenStreamReply, StreamTag, TransportLivenessTap};

/// What the peer read from one accepted substream: the tag byte and the payload byte.
type Received = Rc<RefCell<Vec<[u8; 2]>>>;

/// The error an open request was answered with, once it was answered.
type OpenError = Rc<RefCell<Option<yamux::ConnectionError>>>;

/// A client connection driven by [`drive_connection`], joined by an in-memory pipe to a peer connection driven the
/// same way, or to an idle pipe end.
struct Rig {
    pool: LocalPool,
    open_tx: mpsc::Sender<OpenStreamReply>,
    received: Received,
    /// Set when the client's driver future has finished.
    driver_done: Rc<Cell<bool>>,
    /// Set when the client's inbound channel reports closed.
    inbound_closed: Rc<Cell<bool>>,
    /// The far end of a peerless rig's pipe, kept open so that the client's own failure is the only event.
    _idle_peer_io: Option<DuplexStream>,
}

impl Rig {
    fn new() -> Self {
        let (client_io, peer_io) = tokio::io::duplex(256 * 1024);
        let mut rig = Self::client_half(client_io, yamux::Config::default());
        rig.spawn_peer(peer_io);
        rig
    }

    /// A client with `config` whose far pipe end is held open and never read: a refused open then cannot be followed
    /// by a wake from a peer that noticed the connection ending.
    fn without_peer(config: yamux::Config) -> Self {
        let (client_io, peer_io) = tokio::io::duplex(256 * 1024);
        let mut rig = Self::client_half(client_io, config);
        rig._idle_peer_io = Some(peer_io);
        rig
    }

    fn client_half(client_io: DuplexStream, config: yamux::Config) -> Self {
        let pool = LocalPool::new();
        let spawner = pool.spawner();

        let tapped = TransportLivenessTap::new(client_io.compat(), Arc::new(AtomicU64::new(0)));
        let client = yamux::Connection::new(tapped, config, yamux::Mode::Client);
        let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(32);
        let driver_done = Rc::new(Cell::new(false));
        let done = Rc::clone(&driver_done);
        spawner
            .spawn_local(async move {
                drive_connection(client, open_rx, inbound_tx).await;
                done.set(true);
            })
            .unwrap();
        let inbound_closed = Rc::new(Cell::new(false));
        let closed = Rc::clone(&inbound_closed);
        spawner
            .spawn_local(async move {
                while inbound_rx.recv().await.is_some() {}
                closed.set(true);
            })
            .unwrap();

        Self {
            pool,
            open_tx,
            received: Received::default(),
            driver_done,
            inbound_closed,
            _idle_peer_io: None,
        }
    }

    /// Drive `peer_io` as the galoshes server drives its half, recording what each accepted substream delivers.
    fn spawn_peer(&mut self, peer_io: DuplexStream) {
        let spawner = self.pool.spawner();
        let peer = yamux::Connection::new(peer_io.compat(), yamux::Config::default(), yamux::Mode::Server);
        let (peer_open_tx, peer_open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (peer_inbound_tx, mut peer_inbound_rx) = mpsc::channel::<yamux::Stream>(64);
        let sink = Rc::clone(&self.received);
        let accept_spawner = spawner.clone();
        spawner
            .spawn_local(async move {
                // The server half never opens substreams; it holds the sender to keep the channel open.
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
    }

    /// Open a substream, write `payload`, and hold it open.
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

    /// Ask the driver for a substream it cannot open; the error it answers with lands in the returned cell.
    fn open_expecting_refusal(&self) -> OpenError {
        let answer = OpenError::default();
        let slot = Rc::clone(&answer);
        let open_tx = self.open_tx.clone();
        self.pool
            .spawner()
            .spawn_local(async move {
                let Err(error) = open_stream(&open_tx).await else {
                    panic!("the open was not refused");
                };
                *slot.borrow_mut() = Some(error);
            })
            .unwrap();
        answer
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

#[skuld::test]
fn a_refused_open_ends_the_connection_and_the_driver_tells_its_caller() {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(1);
    let mut rig = Rig::without_peer(config);

    rig.open_and_write(b'a');
    rig.pool.run_until_stalled();
    assert!(
        !rig.driver_done.get() && !rig.inbound_closed.get(),
        "precondition: the first substream is open and the connection is alive"
    );

    let answer = rig.open_expecting_refusal();
    rig.pool.run_until_stalled();

    assert!(
        matches!(*answer.borrow(), Some(yamux::ConnectionError::TooManyStreams)),
        "the open request is answered with the refusal, got {:?}",
        answer.borrow()
    );
    assert!(
        rig.driver_done.get(),
        "yamux ends the connection on a refused open, so the driver must finish"
    );
    assert!(
        rig.inbound_closed.get(),
        "the driver finished, so the inbound channel must report closed"
    );
}
