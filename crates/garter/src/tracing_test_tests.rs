//! Regression tests for [`crate::tracing_test::set_default_in_current_thread`].
//!
//! Six scenarios:
//! 1. Multi-thread runtime → helper panics.
//! 2. Current-thread runtime → helper passes through and captures.
//! 3. Sync context (no runtime) → helper passes through and captures.
//! 4. Helper called *outside* `block_on` before entering a multi-thread
//!    runtime → silent passthrough. Documents the known limitation.
//! 5. Raw `set_default` + multi-thread + `tokio::spawn` synchronously
//!    confirmed to have run → spawned-task event is NOT captured.
//!    Demonstrates the bug the helper protects against (the issue's
//!    explicitly-requested regression test).
//! 6. Helper inside a current-thread `block_on` + `tokio::spawn` →
//!    spawned-task event IS captured. The "happy path" the helper enables.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

use crate::tracing_test::set_default_in_current_thread;

#[derive(Clone, Default)]
struct VecWriter(Arc<Mutex<Vec<u8>>>);

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn captured(writer: &VecWriter) -> String {
    String::from_utf8_lossy(&writer.0.lock().unwrap()).into_owned()
}

fn build_subscriber(writer: VecWriter) -> impl tracing::Subscriber + Send + Sync + 'static {
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_writer(writer).with_ansi(false))
}

#[skuld::test]
#[should_panic(expected = "multi-thread tokio runtime")]
fn helper_panics_on_multi_thread_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let writer = VecWriter::default();
        let _g = set_default_in_current_thread(build_subscriber(writer));
    });
}

#[skuld::test]
fn helper_passes_on_current_thread_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let writer = VecWriter::default();
        let _g = set_default_in_current_thread(build_subscriber(writer.clone()));
        tracing::info!("event_on_test_thread");
        assert!(
            captured(&writer).contains("event_on_test_thread"),
            "expected event captured; got:\n{}",
            captured(&writer),
        );
    });
}

#[skuld::test]
fn helper_passes_in_sync_context() {
    let writer = VecWriter::default();
    let _g = set_default_in_current_thread(build_subscriber(writer.clone()));
    tracing::info!("sync_event");
    assert!(
        captured(&writer).contains("sync_event"),
        "expected event captured; got:\n{}",
        captured(&writer),
    );
}

/// Documents the helper's known limitation: when called *outside*
/// `block_on`, `Handle::try_current()` returns `Err` and the helper
/// silently passes. A multi-thread `block_on` started afterwards
/// would then spawn-leak events; the helper provides no protection
/// at this position. The module docstring requires callers to put
/// `set_default_in_current_thread` *inside* `block_on`.
#[skuld::test]
fn helper_silently_passes_when_called_before_block_on() {
    let writer = VecWriter::default();
    // No panic here even though the next `block_on` is multi-thread.
    let _g = set_default_in_current_thread(build_subscriber(writer.clone()));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tracing::info!("from_spawned_task");
            let _ = tx.send(());
        });
        rx.await.unwrap();
    });

    assert!(
        !captured(&writer).contains("from_spawned_task"),
        "limitation regression: helper called before block_on cannot protect; \
         spawned event must be lost as expected for documentation purposes",
    );
}

/// Issue #302 explicitly requests this regression: demonstrate that
/// the raw `set_default` + multi-thread runtime + `tokio::spawn`
/// combination drops the spawned-task event. The oneshot channel
/// synchronously confirms the spawned task ran (so a missing event
/// can't be explained away as "spawn hadn't started").
#[skuld::test]
fn raw_set_default_on_multi_thread_loses_spawned_events() {
    let writer = VecWriter::default();
    let subscriber = build_subscriber(writer.clone());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        #[allow(clippy::disallowed_methods)] // deliberately demonstrating the bug
        let _g = tracing::subscriber::set_default(subscriber);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tracing::info!("from_spawned_task_should_be_lost");
            let _ = tx.send(());
        });
        rx.await.expect("spawned task must signal completion");

        tracing::info!("from_test_thread");
    });

    assert!(
        captured(&writer).contains("from_test_thread"),
        "control: test-thread event should be captured; got:\n{}",
        captured(&writer),
    );
    assert!(
        !captured(&writer).contains("from_spawned_task_should_be_lost"),
        "demonstration: raw set_default + multi-thread + spawn must lose \
         the spawned event (the helper would have panicked instead). Captured:\n{}",
        captured(&writer),
    );
}

/// Happy path: helper + current-thread runtime + `tokio::spawn` →
/// spawned-task events ARE captured.
#[skuld::test]
fn helper_inside_current_thread_block_on_captures_spawned_events() {
    let writer = VecWriter::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let _g = set_default_in_current_thread(build_subscriber(writer.clone()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tracing::info!("from_spawned_on_ct");
            let _ = tx.send(());
        });
        rx.await.unwrap();
    });

    assert!(
        captured(&writer).contains("from_spawned_on_ct"),
        "happy path: helper + current-thread + spawn must capture; got:\n{}",
        captured(&writer),
    );
}
