use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use super::keepalive::{
    keepalive_cycle, open_probe, run_keepalive, Cadence, KeepaliveCycle, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT,
};
use crate::yamux::{drive_connection, OpenStreamReply, StreamTag, TransportLivenessTap, KEEPALIVE_NONCE_LEN};
use crate::yamux_tests::{capture_logs, echo_yamux_stream_body, open_test_stream};

/// How a stub peer treats the client's keepalive substream. Non-keepalive
/// substreams are always echoed, so a test can generate ordinary traffic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StubPeer {
    /// Echoes the nonce, like the production server.
    Echo,
    /// What a pre-keepalive galoshes server does: the tag is unknown, the
    /// handler errors, the substream is dropped — which yamux turns into a reset
    /// the client will read.
    RejectTag,
    /// Answers, but with bytes that are not the nonce.
    Corrupt,
    /// Reads the nonce and half-closes without answering: a graceful FIN, which
    /// the client's probe read sees as `Ok(0)`.
    FinWithoutEcho,
    /// Reads every nonce and never answers any of them, holding the substream
    /// open. Models a busy-but-alive peer whose probe stalls.
    StallProbe,
    /// A raw byte sink: reads and discards, never writes a single byte. NOT a
    /// yamux peer — a real `Connection` would answer yamux's own pings and so
    /// could not model a black hole.
    Blackhole,
}

/// A live yamux client whose transport is an in-process pipe to `peer`.
///
/// Both yamux peers ping on their driver's first poll, so the harness quiesces
/// before handing the client back: one `chatter` round trip. Frames are ordered,
/// so the pong is necessarily read before the echo; ten bytes are far below the
/// window-update threshold, so no trailing frame follows; and the substream is
/// dropped, whose reset the peer answers with nothing at all (its own stream is
/// already `Closed`, and `on_drop_stream` emits no frame for that state). After
/// it the connection is silent until a test touches it, and yamux's next ping is
/// 10 s of *real* time away — which a virtual clock never reaches. Without this,
/// the setup pong would land during a test's own cycle and make every `Answered`
/// verdict true regardless of what the stub peer did.
struct PipedClient {
    open_tx: mpsc::Sender<OpenStreamReply>,
    inbound_reads: Arc<AtomicU64>,
    /// The nonce of every keepalive probe the peer read.
    probes: mpsc::UnboundedReceiver<u64>,
    _client_driver: tokio::task::JoinHandle<()>,
    _client_inbound: mpsc::Receiver<yamux::Stream>,
    _peer: tokio::task::JoinHandle<()>,
}

impl PipedClient {
    /// The tap's current value — a cycle's `last_seen` starting point.
    fn seen(&self) -> u64 {
        self.inbound_reads.load(Ordering::Relaxed)
    }

    async fn cycle(&self, nonce: u64, last_seen: &mut u64) -> KeepaliveCycle {
        keepalive_cycle(&self.open_tx, nonce, &self.inbound_reads, last_seen, KEEPALIVE_TIMEOUT).await
    }
}

async fn piped_client(peer: StubPeer) -> PipedClient {
    piped_client_with_max_streams(peer, 512).await
}

/// `max_streams` is the substream budget available to the test. The quiesce
/// substream is dropped before the client is handed back, so it costs none of it.
async fn piped_client_with_max_streams(peer: StubPeer, max_streams: usize) -> PipedClient {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};

    let (client_io, peer_io) = tokio::io::duplex(256 * 1024);

    // `Blackhole` never answers, so it can neither be quiesced nor needs to be:
    // it sends nothing to quiesce away.
    let quiesces = peer != StubPeer::Blackhole;

    let mut config = ::yamux::Config::default();
    config.set_max_num_streams(max_streams);

    let inbound_reads = Arc::new(AtomicU64::new(0));
    let tapped = TransportLivenessTap::new(client_io.compat(), Arc::clone(&inbound_reads));
    let conn = ::yamux::Connection::new(tapped, config, ::yamux::Mode::Client);
    let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
    let (inbound_tx, client_inbound) = mpsc::channel::<yamux::Stream>(32);
    let client_driver = tokio::spawn(drive_connection(conn, open_rx, inbound_tx));

    let (probe_tx, probes) = mpsc::unbounded_channel::<u64>();
    let peer_task = tokio::spawn(async move {
        if peer == StubPeer::Blackhole {
            let mut sink = peer_io;
            let mut buf = [0u8; 4096];
            while matches!(tokio::io::AsyncReadExt::read(&mut sink, &mut buf).await, Ok(n) if n > 0) {}
            return;
        }

        let conn = ::yamux::Connection::new(peer_io.compat(), ::yamux::Config::default(), ::yamux::Mode::Server);
        let (_open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(32);
        tokio::spawn(drive_connection(conn, open_rx, inbound_tx));

        while let Some(mut stream) = inbound_rx.recv().await {
            let probe_tx = probe_tx.clone();
            tokio::spawn(async move {
                let mut tag = [0u8; 1];
                if stream.read_exact(&mut tag).await.is_err() {
                    return;
                }
                if tag[0] != StreamTag::Keepalive.to_byte() {
                    echo_yamux_stream_body(stream).await;
                    return;
                }
                if peer == StubPeer::RejectTag {
                    return;
                }
                let mut nonce = [0u8; KEEPALIVE_NONCE_LEN];
                while stream.read_exact(&mut nonce).await.is_ok() {
                    let _ = probe_tx.send(u64::from_be_bytes(nonce));
                    match peer {
                        StubPeer::StallProbe => continue,
                        StubPeer::FinWithoutEcho => {
                            let _ = stream.close().await;
                            return;
                        }
                        StubPeer::Corrupt => nonce.iter_mut().for_each(|b| *b ^= 0xFF),
                        _ => {}
                    }
                    if stream.write_all(&nonce).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    if quiesces {
        chatter(&open_tx).await;
    }

    PipedClient {
        open_tx,
        inbound_reads,
        probes,
        _client_driver: client_driver,
        _client_inbound: client_inbound,
        _peer: peer_task,
    }
}

/// Assert how much *virtual* time a path consumed, allowing tokio's timer wheel
/// one millisecond of rounding per `sleep` on it: `deadline_to_tick` rounds a
/// deadline up to the next whole millisecond, and `pause()` leaves a
/// sub-millisecond offset between the clock base and the driver's start time, so
/// an exact equality would fail on all but a measure-zero alignment.
fn assert_elapsed(started: tokio::time::Instant, expected: Duration, sleeps: u32) {
    let elapsed = tokio::time::Instant::now() - started;
    let slack = Duration::from_millis(u64::from(sleeps));
    assert!(
        (expected..=expected + slack).contains(&elapsed),
        "expected {expected:?} (+{slack:?} of timer-wheel rounding), got {elapsed:?}"
    );
}

/// Await the next `count` nonces read by the peer, in order. An in-runtime
/// rendezvous, so a paused clock only advances between cycles and never
/// mid-exchange.
async fn expect_probes(client: &mut PipedClient, count: usize) -> Vec<u64> {
    let mut nonces = Vec::with_capacity(count);
    for probe in 1..=count {
        nonces.push(
            client
                .probes
                .recv()
                .await
                .unwrap_or_else(|| panic!("probe {probe} never reached the peer")),
        );
    }
    nonces
}

/// One echoed round trip on an ordinary substream, generating inbound traffic.
/// Every step is a ready-task hand-off, so a paused clock cannot advance
/// mid-exchange. The substream is dropped when this returns — the peer answers
/// the resulting reset with nothing, and an unread substream left open would
/// wedge every later substream on this in-process pipe.
async fn chatter(open_tx: &mpsc::Sender<OpenStreamReply>) {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = open_test_stream(open_tx).await;
    stream.write_all(&[StreamTag::Tcp.to_byte()]).await.unwrap();
    stream.write_all(b"still here").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still here");
}

#[skuld::test]
async fn opening_a_probe_fails_when_the_substream_budget_is_exhausted() {
    // The `TooManyStreams` arm: a refused open must be reported, not pass
    // silently — the two open-failure arms are deliberately logged at different
    // levels, and this is the one that warns.
    let (writer, _g) = capture_logs();
    let client = piped_client_with_max_streams(StubPeer::Echo, 1).await;
    let _hog = open_test_stream(&client.open_tx).await;
    assert!(open_probe(&client.open_tx, 1).await.is_none());
    assert!(
        writer.snapshot().contains("failed to open the keepalive substream"),
        "a refused open must warn, not pass silently"
    );
}

#[skuld::test]
async fn opening_a_probe_fails_when_the_connection_is_gone() {
    let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(1);
    drop(open_rx);
    assert!(open_probe(&open_tx, 1).await.is_none());
}

#[skuld::test]
async fn opening_a_probe_tags_it_and_delivers_the_nonce() {
    let mut client = piped_client(StubPeer::Echo).await;
    assert!(
        open_probe(&client.open_tx, 7).await.is_some(),
        "a healthy connection must yield a probe substream"
    );
    assert_eq!(expect_probes(&mut client, 1).await, vec![7]);
}

#[skuld::test]
async fn a_cycle_skips_the_probe_while_the_transport_is_busy() {
    // A transport that delivered something has already answered the question a
    // probe asks, so the cycle sends nothing at all and never touches a timer.
    // The peer would stall any probe, so a probe reaching it could not be
    // mistaken for an answer.
    let mut client = piped_client(StubPeer::StallProbe).await;
    let mut last_seen = client.seen();
    client.inbound_reads.fetch_add(1, Ordering::Relaxed); // the transport spoke

    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Skipped);
    assert_eq!(last_seen, client.seen(), "a skip must re-baseline the sample");
    assert!(
        matches!(client.probes.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "a skipped cycle must not put a nonce on the wire"
    );
}

#[skuld::test]
async fn a_cycle_the_peer_echoes_is_not_fatal() {
    let mut client = piped_client(StubPeer::Echo).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    assert_eq!(client.cycle(4, &mut last_seen).await, KeepaliveCycle::Answered);
    assert_eq!(expect_probes(&mut client, 1).await, vec![4], "the cycle's own nonce");
    assert_eq!(last_seen, client.seen(), "an answer must re-baseline the sample");
}

#[skuld::test]
async fn a_cycle_a_peer_rejects_the_tag_on_is_not_fatal() {
    // An un-upgraded server. Its reset is inbound traffic, necessarily read off
    // the socket before the probe's own read can end, so the cycle is answered —
    // and the probe read reports the substream ending, which is what proves the
    // reset travelled the whole way rather than the verdict resting on some
    // other frame.
    let (writer, _g) = capture_logs();
    let client = piped_client(StubPeer::RejectTag).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Answered);
    assert!(
        writer.snapshot().contains("keepalive probe substream ended"),
        "the peer's rejection must have reached the probe's own read"
    );
}

#[skuld::test]
async fn a_cycle_a_peer_half_closes_is_not_fatal() {
    // A graceful FIN rather than a reset: the client's probe read sees `Ok(0)`
    // and the FIN frame itself is the liveness.
    let (writer, _g) = capture_logs();
    let mut client = piped_client(StubPeer::FinWithoutEcho).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Answered);
    assert_eq!(expect_probes(&mut client, 1).await, vec![1]);
    assert!(writer.snapshot().contains("keepalive probe substream ended"));
}

#[skuld::test]
async fn a_cycle_answered_with_garbage_is_not_fatal() {
    // The verdict is "did anything arrive", never "was it the nonce".
    let mut client = piped_client(StubPeer::Corrupt).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Answered);
    assert_eq!(expect_probes(&mut client, 1).await, vec![1]);
}

#[skuld::test]
async fn a_cycle_whose_probe_stalls_survives_on_other_traffic() {
    // The peer holds the probe substream open and answers nothing, so only
    // traffic elsewhere can save the cycle. `chatter` is pure ready-task work
    // over the duplex, so it lands before the paused clock can reach the
    // deadline.
    let client = piped_client(StubPeer::StallProbe).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    let (verdict, ()) = tokio::join!(client.cycle(1, &mut last_seen), chatter(&client.open_tx));
    assert_eq!(verdict, KeepaliveCycle::Answered);
}

#[skuld::test]
async fn a_cycle_nothing_answers_is_fatal_after_one_deadline() {
    // The peer swallows everything and answers nothing, with no reset and no
    // FIN. Only timers can make progress, so the paused clock advances
    // deterministically to the verdict — and to one deadline's worth of it,
    // which a stray extra sleep would break.
    let client = piped_client(StubPeer::Blackhole).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    let started = tokio::time::Instant::now();
    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Silent);
    assert_eq!(client.seen(), 0, "nothing came back — that silence is the verdict");
    assert_elapsed(started, KEEPALIVE_TIMEOUT, 1);
}

#[skuld::test]
async fn a_cycle_that_cannot_open_a_probe_still_waits_the_whole_deadline() {
    // A refused open plus a whole silent window is, at this layer,
    // observationally identical to a dead transport: substreams that delivered
    // nothing. Reconnecting is the fail-safe reading — but only after the full
    // window, never on the open failure alone.
    let client = piped_client_with_max_streams(StubPeer::Blackhole, 1).await;
    let _hog = open_test_stream(&client.open_tx).await;
    tokio::time::pause();
    let mut last_seen = client.seen();
    let started = tokio::time::Instant::now();
    assert_eq!(client.cycle(1, &mut last_seen).await, KeepaliveCycle::Silent);
    assert_elapsed(started, KEEPALIVE_TIMEOUT, 1);
}

#[skuld::test]
async fn keepalive_keeps_probing_a_healthy_peer_with_a_fresh_nonce_each_time() {
    // Three delivered probes prove the loop took the non-fatal path twice and
    // came back for more, which a fatal verdict would have prevented. Their
    // nonces must differ: a probe is meant to be distinguishable in the logs and
    // on the wire, which a constant would not be. They need not be consecutive —
    // a skipped cycle consumes a nonce without sending one.
    let mut client = piped_client(StubPeer::Echo).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(
        client.open_tx.clone(),
        Arc::clone(&client.inbound_reads),
        Cadence::default(),
    ));
    let nonces = expect_probes(&mut client, 3).await;
    assert!(
        nonces.windows(2).all(|w| w[0] < w[1]),
        "each cycle must carry its own nonce, got {nonces:?}"
    );
    assert!(!keepalive.is_finished(), "a healthy peer must never be declared dead");
    keepalive.abort();
}

#[skuld::test]
async fn keepalive_declares_a_silent_transport_dead() {
    // The loop's fatal exit at its fastest: a whole interval of silence before
    // the probe, then a whole deadline after it, and nothing else.
    let client = piped_client(StubPeer::Blackhole).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    run_keepalive(
        client.open_tx.clone(),
        Arc::clone(&client.inbound_reads),
        Cadence::default(),
    )
    .await;
    assert_elapsed(started, KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT, 2);
}

#[skuld::test]
async fn keepalive_declares_a_transport_dead_two_intervals_after_the_last_inbound_byte() {
    // The documented worst case, driven end to end: a byte lands just before a
    // cycle boundary, that cycle skips, and the next one runs a full deadline
    // before the verdict. `2 × INTERVAL + TIMEOUT`, which is the bound CLAUDE.md
    // and CONTRIBUTING.md state.
    let client = piped_client(StubPeer::Blackhole).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();

    let mut keepalive = Box::pin(run_keepalive(
        client.open_tx.clone(),
        Arc::clone(&client.inbound_reads),
        Cadence::default(),
    ));
    // One poll runs `run_keepalive` up to its baseline sample and parks it on the
    // first interval. The byte has to land after that: incremented earlier it
    // would be folded into the baseline and the cycle would probe instead of
    // skipping.
    assert!(futures::poll!(keepalive.as_mut()).is_pending());
    client.inbound_reads.fetch_add(1, Ordering::Relaxed);
    keepalive.await;

    assert_elapsed(started, 2 * KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT, 3);
}
