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

// `test_support` is private to the lib, so the integration target compiles the shared helpers itself.
#[path = "../src/test_support/log_capture.rs"]
mod log_capture;
#[allow(dead_code)] // this target uses a subset of the staging helpers
#[path = "../src/test_support/plugin_install.rs"]
mod plugin_install;

use std::path::PathBuf;

use hole_bridge::proxy::plugin::start_plugin_chain;
use hole_bridge::proxy::{BridgeExe, BundledPlugin, PluginSource};
use tokio_util::sync::CancellationToken;

/// An install dir holding a bridge exe and an `ex-ray` beside it, resolved the
/// way production resolves a bundled plugin.
struct Install {
    _dir: tempfile::TempDir,
    plugin: BundledPlugin,
}

/// Path to the `test_plugin` fixture bin. The runtime env var wins (nextest
/// remaps it under `--archive-file`); the compile-time value covers plain
/// `cargo test`. Never invoke cargo here — a concurrent build's uplift
/// deletes+recreates `target/debug/<bin>`, racing this spawn.
fn test_plugin_bin() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_test_plugin")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_test_plugin").to_string())
        .into()
}

/// `ex_ray` writes the install's `ex-ray`: the stub's bytes, or something that
/// cannot run.
fn install_with(ex_ray: impl FnOnce(&std::path::Path)) -> Install {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = plugin_install::install_with_ex_ray(dir.path(), ex_ray);
    let plugin = PluginSource::build_dir(BridgeExe::At(exe))
        .resolve("v2ray-plugin")
        .expect("the install holds ex-ray");
    Install { _dir: dir, plugin }
}

/// A working install: `ex-ray` is the stub plugin.
fn installed_stub() -> Install {
    install_with(|ex_ray| {
        std::fs::copy(test_plugin_bin(), ex_ray).expect("copy the stub plugin");
    })
}

/// Two properties in one spawn: the options Hole merges must arrive in the
/// child's real `SS_PLUGIN_OPTIONS` (not merely in the value handed to
/// `BinaryPlugin::new`), and whatever the child logs must reach the chain's
/// ring.
#[skuld::test]
async fn the_merged_options_reach_the_child_and_its_output_reaches_the_ring() {
    let install = installed_stub();
    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
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

    drop(chain);
}

/// The Windows lockdown permit is read off the chain, so the chain must report
/// the file it ran, not the file it was configured with by name.
#[skuld::test]
async fn the_chain_reports_the_file_it_was_spawned_from() {
    let install = installed_stub();
    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
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
    .expect("the stub plugin becomes ready");

    assert_eq!(chain.binary(), install.plugin.path());

    drop(chain);
}

/// A shipped plugin's transports come from its sitrep `ready`, not from a TCP
/// self-probe, which could only ever say TCP: the UDP-drop policy needs galoshes'
/// `tcp,udp`.
#[skuld::test]
async fn the_transports_are_the_ones_the_plugin_reports() {
    let install = installed_stub();
    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
        Some("host=example.com;report-udp"),
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

    assert_eq!(chain.transports(), garter::Transports::TCP | garter::Transports::UDP);

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

    let install = installed_stub();
    let cancel = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
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

/// `test_plugin`'s `LIVE_MARKER`: written once the plugin has bound its local
/// address, which only the attempt that becomes the chain does.
const LIVE_MARKER: u8 = b'L';

/// The `connect-back` stream of the plugin that bound its local address. An
/// attempt that lost a bind race dialed back too, so the first stream accepted
/// is not necessarily the chain's plugin; a loser's stream reaches EOF without
/// the marker and is skipped. Ports and arrival order identify nothing: a retry
/// may be handed the loser's port, and either attempt may connect first.
async fn accept_live_attempt(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
    use tokio::io::AsyncReadExt;
    loop {
        let (mut stream, _) = listener.accept().await.expect("a plugin dials back");
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_ok() && byte[0] == LIVE_MARKER {
            return stream;
        }
    }
}

/// Whether the far end of `stream` is demonstrably still there: nothing to read,
/// not even an EOF. An attempt that already exited has its EOF queued, so this is
/// what makes a dead stream picked by mistake fail an assertion instead of
/// satisfying "the plugin is gone" for free.
fn peer_is_still_there(stream: &tokio::net::TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(stream.try_read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

/// The chain lives as long as the session, not as long as the start that made
/// it. Cancelling the start token after the chain is ready must leave the
/// plugin running; ending the session (dropping the chain) must still stop it.
/// The first attempt loses a bind race, so the stream held is picked by the
/// live marker and cannot be the dead attempt's. This test goes red by assertion
/// only through `peer_is_still_there`; a leaked chain's plugin otherwise ends on
/// garter's own bounds, so "the plugin is gone" turns true a minute late.
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

    let install = installed_stub();
    let start = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
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
    let mut held = accept_live_attempt(&listener).await;

    start.cancel();

    assert!(
        !chain.is_cancelled(),
        "cancelling the start token must not cancel a ready chain"
    );
    assert!(chain.is_alive());
    assert!(
        peer_is_still_there(&held),
        "the plugin must keep running after the start token is cancelled"
    );

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

    let install = installed_stub();
    let start = CancellationToken::new();
    let starting = tokio::spawn({
        let start = start.clone();
        async move {
            start_plugin_chain(
                &install.plugin,
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
/// not orphan the plugin it spawned. Without the fix a leaked chain's plugin
/// still ends, on garter's own readiness bound, so this goes red only by taking
/// that long; the by-assertion guard is `plugin_tests`' `ChainTask` drop test.
#[skuld::test]
async fn dropping_the_start_future_stops_the_plugin_it_spawned() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let opts = format!(
        "host=example.com;never-ready;connect-back={}",
        listener.local_addr().expect("addr")
    );

    let start = CancellationToken::new();
    let install = installed_stub();
    let mut starting = Box::pin(start_plugin_chain(
        &install.plugin,
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

    let install = installed_stub();
    let start = CancellationToken::new();
    let chain = start_plugin_chain(
        &install.plugin,
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
    // A plain accept: the plugin exits right after its marker, and on Windows the exit can
    // reset the stream before the marker is read.
    let (mut held, _) = listener.accept().await.expect("the plugin dials back");

    assert!(peer_is_gone(&mut held).await, "the plugin exits after it is ready");
    while chain.is_alive() {
        tokio::task::yield_now().await;
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

    let writer = log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );

    // An `ex-ray` that cannot run: the spawn fails and the plugin says nothing.
    let install = install_with(|ex_ray| std::fs::write(ex_ray, b"not a program").expect("write"));
    let cancel = CancellationToken::new();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let err = start_plugin_chain(
            &install.plugin,
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
    let output = writer.snapshot_string();
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

    let writer = log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );

    let install = installed_stub();
    let cancel = CancellationToken::new();
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let err = start_plugin_chain(
            &install.plugin,
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

    let output = writer.snapshot_string();
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
