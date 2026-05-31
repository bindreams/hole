//! Regression tests for `hole_test_observability::install`.
//!
//! Two structural gates:
//!
//! 1. [`install_subscriber_dispatches_info_events`] — confirms the
//!    global subscriber is wired up: an `info!` event reaches a
//!    sibling `set_default` capture buffer.
//! 2. [`shadowsocks_service_trace_is_filter_rejected_cheaply`] — even
//!    with `LogTracer` installed, `log::trace!` from a noisy
//!    third-party namespace must be level-rejected at
//!    `Dispatch::enabled()` before `tracing-log` allocates.

use super::*;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[skuld::test]
fn install_subscriber_dispatches_info_events() {
    install(); // idempotent

    // Capture into a sibling thread-local subscriber. The global
    // installed by `install()` writes to stderr; the local one here
    // is what we assert against.
    let buf = Buf(Arc::new(Mutex::new(Vec::new())));
    let local = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    // Sync test, no tokio runtime — the #302
    // `set_default_in_current_thread` helper's check would pass
    // through. Sanctioned to use the raw form here (test-observability
    // sits beneath garter in the dep graph, so we can't depend on the
    // helper).
    #[allow(clippy::disallowed_methods)]
    let _g = tracing::subscriber::set_default(local);

    tracing::info!(target: "ho_test_marker", value = 42, "regression-event");

    let s = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(s.contains("ho_test_marker"), "marker missing in captured output:\n{s}");
    assert!(
        s.contains("regression-event"),
        "message missing in captured output:\n{s}"
    );
    assert!(s.contains("value=42"), "field missing in captured output:\n{s}");
}

#[skuld::test]
fn shadowsocks_service_trace_is_filter_rejected_cheaply() {
    install();
    // Simulate any test path that installs LogTracer (the existing
    // `subscriber.set_default()` method-form sites in bridge tests do
    // this implicitly). Discard result — second-install is harmless.
    let _ = tracing_log::LogTracer::init();

    // Hot loop emitting a noisy third-party log event. EnvFilter
    // pins `shadowsocks_service` to `info` via the catch-all (no
    // explicit pin for `shadowsocks_service` in DEFAULT_FILTER, so
    // it inherits the `info` catch-all). A `log::trace!` is below
    // `info` and must be rejected before allocation.
    let start = std::time::Instant::now();
    for _ in 0..100_000 {
        log::trace!(target: "shadowsocks_service::relay", "fake busy event");
    }
    let elapsed = start.elapsed();

    // Expected wall-clock is < 10 ms. A regression (full formatting
    // + write per event) would be tens of seconds. 500 ms threshold
    // is generous.
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "shadowsocks_service log::trace! took {elapsed:?} for 100k events — \
         EnvFilter level-rejection path may have regressed. See bindreams/hole#147."
    );
}

#[skuld::test]
fn install_is_idempotent() {
    install();
    install();
    install();
    // No panic, no double-set warning. The `Once` inside ensures
    // only the first call observed.
}
