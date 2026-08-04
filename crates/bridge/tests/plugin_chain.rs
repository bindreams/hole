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
