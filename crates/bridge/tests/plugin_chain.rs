//! What `start_plugin_chain` hands the child, and what comes back.
//!
//! An INTEGRATION test (not a lib module) on purpose: Cargo builds the
//! `test_plugin` helper `[[bin]]` before this target and injects
//! `CARGO_BIN_EXE_test_plugin`; a lib unit-test target gets neither.
//!
//! Determinism is stream ordering, never timing. `test_plugin` writes its
//! `SS_PLUGIN_OPTIONS` line to stdout before the sitrep `ready`, and garter's
//! sitrep stdout reader consumes that one pipe in order — so a chain that has
//! reported ready has already relayed the line.

// `CancellationToken::new` is the cancel-test harness root; module-level allow
// per clippy.toml's "Bridge cancellation contract" sanctioned-test-file
// exception.
#![allow(clippy::disallowed_methods)]

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

use std::path::PathBuf;

use hole_bridge::proxy::plugin::start_plugin_chain;
use tokio_util::sync::CancellationToken;

/// Path to the `test_plugin` fixture bin. The runtime env var wins (nextest
/// remaps it under `--archive-file`); the compile-time value covers plain
/// `cargo test`. Never invoke cargo here — a concurrent build's uplift
/// deletes+recreates `target/debug/<bin>`, racing this spawn.
fn test_plugin_path() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_test_plugin")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_test_plugin").to_string())
        .into()
}

/// Two properties in one spawn: the options Hole merges must arrive in the
/// child's real `SS_PLUGIN_OPTIONS` (not merely in the value handed to
/// `BinaryPlugin::new`), and whatever the child logs must reach the chain's
/// ring.
#[skuld::test]
async fn the_merged_options_reach_the_child_and_its_output_reaches_the_ring() {
    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        "v2ray-plugin",
        test_plugin_path().to_str().expect("utf-8 path"),
        Some("host=example.com;path=/foo"),
        "127.0.0.1",
        9,
        None,
        None,
        false,
        &cancel,
        None,
    )
    .await
    .expect("the stub plugin becomes ready");

    let lines = chain.log().recent();
    let echoed = lines
        .iter()
        .find(|l| l.contains("SS_PLUGIN_OPTIONS="))
        .unwrap_or_else(|| panic!("the child's output must reach the ring; got: {lines:?}"));
    assert!(
        echoed.contains("host=example.com;path=/foo;loglevel=debug"),
        "the merged options must reach the child verbatim; got: {echoed}"
    );

    cancel.cancel();
    drop(chain);
}

/// A plugin that loses its local-port race must report `bind_conflict`, the one
/// class `bind_ephemeral` retries on a fresh port. The stub injects the loss
/// through its options string (there is no environment seam), so the first
/// attempt reports the conflict and the retry binds for real.
#[skuld::test]
async fn a_bind_conflict_is_retried_on_a_fresh_port() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sentinel = dir.path().join("bind-once");
    let opts = format!("host=example.com;fail-bind-once={}", sentinel.display());

    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        "v2ray-plugin",
        test_plugin_path().to_str().expect("utf-8 path"),
        Some(&opts),
        "127.0.0.1",
        9,
        None,
        None,
        false,
        &cancel,
        None,
    )
    .await
    .expect("the conflict must be retried, not propagated");

    assert!(sentinel.exists(), "the first attempt must have taken the sentinel");
    // Two attempts fed one ring, so the losing attempt's output survives too.
    let lines = chain.log().recent();
    assert!(
        lines.iter().filter(|l| l.contains("SS_PLUGIN_OPTIONS=")).count() >= 2,
        "every attempt feeds the same ring; got: {lines:?}"
    );

    cancel.cancel();
    drop(chain);
}

/// Waits until the far end of `stream` is gone: EOF on a clean close, an error
/// on a reset (a killed process on Windows resets rather than closes). Whatever
/// the peer sent first is discarded.
async fn peer_is_gone(stream: &mut tokio::net::TcpStream) -> bool {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 16];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return true,
            Ok(_) => {}
        }
    }
}

/// The stream of the attempt that listens on `port`. An attempt that lost a bind
/// race dialed back too (with its own port), so the first stream accepted is not
/// necessarily the chain's plugin.
async fn accept_attempt_on(listener: &tokio::net::TcpListener, port: u16) -> tokio::net::TcpStream {
    use tokio::io::AsyncReadExt;
    loop {
        let (mut stream, _) = listener.accept().await.expect("a plugin dials back");
        let mut announced = [0u8; 2];
        if stream.read_exact(&mut announced).await.is_ok() && u16::from_be_bytes(announced) == port {
            return stream;
        }
    }
}

/// The chain lives as long as the session, not as long as the start that made
/// it. Cancelling the start token after the chain is ready must leave the
/// plugin running; ending the session (dropping the chain) must still stop it.
/// The first attempt loses a bind race, so the stream held is picked by port
/// and cannot be the dead attempt's.
#[skuld::test]
async fn a_cancel_of_the_start_after_the_chain_is_ready_leaves_the_chain_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sentinel = dir.path().join("bind-once");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let opts = format!(
        "host=example.com;fail-bind-once={};connect-back={}",
        sentinel.display(),
        listener.local_addr().expect("addr")
    );

    let start = CancellationToken::new();
    let chain = start_plugin_chain(
        "v2ray-plugin",
        test_plugin_path().to_str().expect("utf-8 path"),
        Some(&opts),
        "127.0.0.1",
        9,
        None,
        None,
        false,
        &start,
        None,
    )
    .await
    .expect("the stub plugin becomes ready");
    assert!(sentinel.exists(), "the first attempt must have lost its bind race");
    let mut held = accept_attempt_on(&listener, chain.local_addr().port()).await;

    start.cancel();

    assert!(
        !chain.is_cancelled(),
        "cancelling the start token must not cancel a ready chain"
    );
    assert!(chain.is_alive());

    drop(chain);
    assert!(
        peer_is_gone(&mut held).await,
        "dropping the chain (the session ending) must stop the plugin"
    );
}

/// The other half: a cancel DURING the start still stops the plugin it had
/// already spawned, and the start reports `Cancelled`.
#[skuld::test]
async fn a_cancel_during_the_start_stops_the_plugin_it_spawned() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let opts = format!(
        "host=example.com;never-ready;connect-back={}",
        listener.local_addr().expect("addr")
    );

    let start = CancellationToken::new();
    let starting = tokio::spawn({
        let start = start.clone();
        async move {
            start_plugin_chain(
                "v2ray-plugin",
                test_plugin_path().to_str().expect("utf-8 path"),
                Some(&opts),
                "127.0.0.1",
                9,
                None,
                None,
                false,
                &start,
                None,
            )
            .await
            .err()
        }
    });
    // The plugin has dialed back, so it is running and cannot be ready yet.
    let (mut held, _) = listener.accept().await.expect("the plugin dials back");

    start.cancel();

    let err = starting.await.expect("start task").expect("a cancelled start fails");
    assert!(matches!(err, hole_bridge::proxy::ProxyError::Cancelled), "got: {err:?}");
    assert!(
        peer_is_gone(&mut held).await,
        "a cancel during the start must stop the plugin"
    );
}

/// A start future dropped before it returns (the task around it aborted) must
/// not orphan the plugin it spawned.
#[skuld::test]
async fn dropping_the_start_future_stops_the_plugin_it_spawned() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let opts = format!(
        "host=example.com;never-ready;connect-back={}",
        listener.local_addr().expect("addr")
    );

    let start = CancellationToken::new();
    let plugin_path = test_plugin_path();
    let mut starting = Box::pin(start_plugin_chain(
        "v2ray-plugin",
        plugin_path.to_str().expect("utf-8 path"),
        Some(&opts),
        "127.0.0.1",
        9,
        None,
        None,
        false,
        &start,
        None,
    ));
    // The plugin has dialed back, so it is running and cannot be ready yet.
    let mut held = tokio::select! {
        biased;
        _ = &mut starting => panic!("a plugin that never readies cannot finish its start"),
        accepted = listener.accept() => accepted.expect("the plugin dials back").0,
    };

    drop(starting);

    assert!(
        peer_is_gone(&mut held).await,
        "dropping the start future must stop the plugin"
    );
}

/// A plugin that exits after it is ready ends the chain's task: the property
/// `check_health` reads through `is_alive`. Waits on the real condition, the
/// task having finished, after the plugin's end of the connection has closed.
#[skuld::test]
async fn a_plugin_that_exits_after_ready_ends_the_chain_task() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let opts = format!(
        "host=example.com;exit-after-ready;connect-back={}",
        listener.local_addr().expect("addr")
    );

    let start = CancellationToken::new();
    let chain = start_plugin_chain(
        "v2ray-plugin",
        test_plugin_path().to_str().expect("utf-8 path"),
        Some(&opts),
        "127.0.0.1",
        9,
        None,
        None,
        false,
        &start,
        None,
    )
    .await
    .expect("the stub plugin becomes ready before it exits");
    let mut held = accept_attempt_on(&listener, chain.local_addr().port()).await;

    assert!(peer_is_gone(&mut held).await, "the plugin exits after it is ready");
    while chain.is_alive() {
        tokio::task::yield_now().await;
    }
    assert!(
        !chain.is_cancelled(),
        "the chain ended because the plugin died, not because it was told to shut down"
    );
}

/// Capturing `MakeWriter` — the bridge's own `test_support::log_capture` is a
/// private module, unreachable from an integration target.
#[derive(Clone, Default)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("poisoned")).into_owned()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("poisoned").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A chain that never becomes ready is where the plugin's own words matter
/// most: `spawn_plugin_runner_at`'s "exited before becoming ready" and
/// readiness-timeout arms carry no detail of their own, and the failed attempt's
/// ring can never be reached from outside — `PluginChain` was never built. So
/// `start_plugin_chain` must report the ring itself before returning the error.
#[skuld::test]
async fn a_failed_chain_start_reports_the_plugin_ring() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );

    let cancel = CancellationToken::new();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let err = start_plugin_chain(
            "v2ray-plugin",
            "/nonexistent/plugin-binary",
            Some("host=example.com"),
            "127.0.0.1",
            9,
            None,
            None,
            false,
            &cancel,
            None,
        )
        .await
        .expect_err("a missing binary cannot become ready");
        assert!(format!("{err}").contains("plugin"), "got: {err}");
    }

    // The binary never ran, so the honest report is that it said nothing — the
    // branch proves the failure path consults the ring at all. What a plugin
    // that DID speak looks like is pinned by `plugin_log`'s own tests.
    let output = writer.snapshot();
    assert!(
        output.contains(hole_bridge::proxy::plugin_log::NO_PLUGIN_OUTPUT),
        "a failed chain start must report the plugin ring; got:\n{output}"
    );
}

/// A crash on STDERR (not stdout — the common shape for a Go panic under
/// `GOTRACEBACK=crash`) must reach `warn_recent`'s ring too, not just a
/// stdout crash. garter delivers a start failure only after the plugin's tree
/// is down and both output readers have finished (or hit their failure bound;
/// see `supervise_plugin`'s doc), so this is a real rendezvous for the
/// stdout-closed-before-ready case this test drives, not a scheduling bet.
#[skuld::test]
async fn a_crash_on_stderr_reaches_the_ring_before_the_chain_reports_failure() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );

    let cancel = CancellationToken::new();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let err = start_plugin_chain(
            "v2ray-plugin",
            test_plugin_path().to_str().expect("utf-8 path"),
            Some("host=example.com;fail-stderr-then-exit=fatal: injected crash on stderr"),
            "127.0.0.1",
            9,
            None,
            None,
            false,
            &cancel,
            None,
        )
        .await
        .expect_err("the stub exits before becoming ready");
        assert!(format!("{err}").contains("plugin"), "got: {err}");
    }

    let output = writer.snapshot();
    // Assert on output ONLY `warn_recent` can produce: garter's ordinary
    // stderr relay (`tracing::warn!(plugin = ..., "{line}")`) ALSO logs the
    // raw line independent of the ring, so a bare substring match on the
    // message can't tell "the ring held it" apart from "the relay logged it
    // regardless" — `warn_recent`'s header and its `"plugin: "` line prefix
    // can only come from a read that found something in the ring.
    assert!(
        output.contains(hole_bridge::proxy::plugin_log::PLUGIN_OUTPUT_HEADER),
        "warn_recent must have read a non-empty ring; got:\n{output}"
    );
    assert!(
        output.contains("plugin: fatal: injected crash on stderr"),
        "the child's stderr line must be IN THE RING by the time it is reported; got:\n{output}"
    );
    assert!(
        !output.contains(hole_bridge::proxy::plugin_log::NO_PLUGIN_OUTPUT),
        "got:\n{output}"
    );
}
