//! Process-wide panic-hook dispatcher with a registry of dump sources.
//!
//! On any test panic, the installed hook iterates the registry and
//! calls [`PanicDumpSource::dump`] on each registered source, writing
//! to stderr. Then chains to the previous hook (typically the
//! tracing-emitting `hole_common::logging::install_panic_hook` chain,
//! which itself chains to libtest's panic printer).
//!
//! Hook installation is wired into [`crate::install`], not exposed at
//! the API surface — consumers register sources, the dispatcher hook
//! is always present in test binaries that invoke
//! `hole_test_observability::register!()`.
//!
//! Primary consumer: `BridgeChildLogSource` in
//! [crates/bridge/src/test_support/dist_harness.rs].
//!
//! ## Contract for `dump` implementations
//!
//! `dump` is called from inside a panic hook. Implementations MUST
//! swallow all I/O errors silently — a double-panic from `unwrap()`
//! or `?` would replace the original panic's message with an I/O
//! error, destroying the diagnostic.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// A diagnostic source registered with the panic-dump dispatcher.
/// Implementations describe their own dump format and own the source
/// of bytes (file path, in-memory buffer, etc.).
///
/// See module docs for the silent-on-write-error contract.
pub trait PanicDumpSource: Send + Sync {
    fn dump(&self, out: &mut dyn Write);
}

/// RAII handle returned by [`register`]. Drop unregisters the source.
///
/// Each [`register`] call returns a fresh `PanicDumpGuard` with an
/// independent registry key — registering the same `Arc` twice
/// produces two guards, both of which must drop before the source
/// stops being dumped on panic.
pub struct PanicDumpGuard {
    key: u64,
}

impl Drop for PanicDumpGuard {
    fn drop(&mut self) {
        // `lock().ok()` — on a poisoned mutex (a concurrent panic
        // hook may have observed mid-mutation state), silently skip
        // unregistration. The map will leak this entry until process
        // exit, which is fine in a test binary.
        if let Ok(mut reg) = registry().lock() {
            reg.remove(&self.key);
        }
    }
}

fn registry() -> &'static Mutex<BTreeMap<u64, Arc<dyn PanicDumpSource>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<u64, Arc<dyn PanicDumpSource>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn next_key() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Register `source` for the lifetime of the returned guard.
///
/// The guard's `Drop` removes the source from the registry. Each call
/// returns a fresh guard with an independent registry key; registering
/// the same `Arc` twice is allowed (refcount semantics — both guards
/// must drop before the source is removed).
///
/// On a poisoned registry mutex (e.g. a panic hook is currently
/// iterating), registration silently no-ops and the returned guard is
/// a tombstone — its `Drop` is also a no-op.
///
/// `next_key()` uses `AtomicU64::fetch_add(1)`; overflow is structurally
/// out of reach (at 1 register/μs that's 584,000 years).
pub fn register(source: Arc<dyn PanicDumpSource>) -> PanicDumpGuard {
    let key = next_key();
    if let Ok(mut reg) = registry().lock() {
        reg.insert(key, source);
    }
    PanicDumpGuard { key }
}

/// Install the process-wide dispatcher hook.
///
/// Idempotent across the entire test binary (first call wins via
/// `Once`). The first call takes the previous hook (typically the
/// chain from `hole_common::logging::install_panic_hook` →
/// libtest) and chains it after the dispatcher pass.
///
/// On panic: iterate registry → call `dump` on each source → chain
/// to previous hook. Poisoned mutex → skip dump pass, fall through.
///
/// Called from [`crate::install`]; test-support consumers should not
/// call this directly — registering a source is enough.
pub(crate) fn install_panic_hook_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Diagnostic marker so operators reading raw stderr can
            // confirm the dispatcher actually fired before looking for
            // source dumps.
            let _ = writeln!(std::io::stderr().lock(), "[panic_dump] dispatcher fired: {info}");
            // Snapshot the registry under the lock, then release it
            // before iterating. Calling `dump()` while holding the
            // registry mutex would deadlock if a source's `dump`
            // re-enters via `register()` / guard drop, and would
            // serialize slow I/O across the lock-hold window. The
            // `Arc` clones are cheap; the snapshot makes the dispatch
            // pass lock-free.
            let sources: Vec<Arc<dyn PanicDumpSource>> = match registry().lock() {
                Ok(reg) => reg.values().cloned().collect(),
                Err(_) => return, // poisoned — silently skip
            };
            if !sources.is_empty() {
                let mut stderr = std::io::stderr().lock();
                for source in &sources {
                    source.dump(&mut stderr);
                }
            }
            prev(info);
        }));
    });
}

#[cfg(test)]
#[path = "panic_dump_tests.rs"]
mod panic_dump_tests;
