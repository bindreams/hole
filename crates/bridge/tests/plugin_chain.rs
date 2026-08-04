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
/// deletes+recreates `target/debug/<bin>`, racing this spawn (#496).
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
