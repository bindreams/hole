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

use hole_bridge::proxy::config::{resolve_plugin_path_inner, BundledPlugin};
use hole_bridge::proxy::plugin::start_plugin_chain;
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
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let exe = dir.path().join(format!("hole{ext}"));
    std::fs::write(&exe, b"fake").expect("bridge exe");
    ex_ray(&dir.path().join(format!("ex-ray{ext}")));
    let plugin = resolve_plugin_path_inner("v2ray-plugin", Some(exe)).expect("the install holds ex-ray");
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

    cancel.cancel();
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

    cancel.cancel();
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

    cancel.cancel();
    drop(chain);
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
    let output = writer.snapshot();
    assert!(
        output.contains(hole_bridge::proxy::plugin_log::NO_PLUGIN_OUTPUT),
        "a failed chain start must report the plugin ring; got:\n{output}"
    );
}

/// A crash on STDERR (not stdout — the common shape for a Go panic under
/// `GOTRACEBACK=crash`) must reach `warn_recent`'s ring too, not just a
/// stdout crash. The sitrep stdout reader's readiness-failure path joins the
/// stderr reader (bounded, not indefinite — see
/// `spawn_sitrep_stdout_reader`'s doc in garter) before dropping the
/// readiness sender, so this is a real rendezvous for the "exited before
/// ready" case this test drives, not a scheduling bet.
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
