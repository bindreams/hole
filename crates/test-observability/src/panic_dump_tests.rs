//! Unit tests for `panic_dump`. Cover registry/guard mechanics; the
//! end-to-end panic-hook chaining (panic_dump dispatcher → hole_common
//! tracing-emit → libtest) is covered by the subprocess regression
//! test in
//! `crates/bridge/src/test_support/dist_harness_panic_hook_tests.rs`.

use super::{install_panic_hook_once, register, registry, PanicDumpSource};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Test source that increments a counter every time `dump` is called.
struct CountingSource {
    label: &'static str,
    count: AtomicUsize,
}

impl CountingSource {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            count: AtomicUsize::new(0),
        }
    }
    fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

impl PanicDumpSource for CountingSource {
    fn dump(&self, out: &mut dyn Write) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(out, "{}", self.label);
    }
}

/// Iterate the registry into a buffer. Mirrors what the installed
/// panic hook would do, without firing `std::panic` (which would
/// interact with the global hook in unpredictable ways under the
/// test runner).
fn dispatch_into_buffer() -> String {
    let reg = registry().lock().expect("registry mutex");
    let mut buf: Vec<u8> = Vec::new();
    for source in reg.values() {
        source.dump(&mut buf);
    }
    String::from_utf8(buf).expect("utf8")
}

#[skuld::test]
fn register_and_dispatch_calls_source() {
    let src = Arc::new(CountingSource::new("source-A"));
    let _guard = register(src.clone());

    let out = dispatch_into_buffer();
    assert!(out.contains("source-A"), "expected source-A in output: {out:?}");
    assert_eq!(src.count(), 1);
}

#[skuld::test]
fn guard_drop_unregisters_source() {
    let src = Arc::new(CountingSource::new("guarded-source"));
    {
        let _guard = register(src.clone());
        let out = dispatch_into_buffer();
        assert!(out.contains("guarded-source"));
    }
    // Guard dropped — source removed from registry.
    let out = dispatch_into_buffer();
    assert!(
        !out.contains("guarded-source"),
        "source must be removed after guard drop: {out:?}"
    );
}

#[skuld::test]
fn double_register_uses_refcount() {
    let src = Arc::new(CountingSource::new("refcount-source"));
    let g1 = register(src.clone());
    let g2 = register(src.clone());

    let out = dispatch_into_buffer();
    assert_eq!(out.matches("refcount-source").count(), 2);

    drop(g1);
    let out = dispatch_into_buffer();
    assert_eq!(out.matches("refcount-source").count(), 1, "one registration left");

    drop(g2);
    let out = dispatch_into_buffer();
    assert!(!out.contains("refcount-source"), "all guards dropped");
}

#[skuld::test]
fn install_panic_hook_once_is_idempotent() {
    install_panic_hook_once();
    install_panic_hook_once();
    install_panic_hook_once();
    // The `Once` inside ensures only the first call installs;
    // subsequent calls are no-ops. No panic, no double-chained hook.
}
