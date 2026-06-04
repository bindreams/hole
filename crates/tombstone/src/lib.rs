//! Native-crash observability: catch hardware/OS faults (access violation,
//! stack overflow, abort, illegal instruction, FP, heap corruption) that
//! bypass Rust's unwinding panic hook, and turn a silent process death into
//! a logged event on the next start.
//!
//! Apache-2.0 (NOT GPL): galoshes is released standalone and depends on this
//! crate, so it must stay permissive. See bindreams/hole#438.

pub mod crash;

pub use crash::{attach, sweep};

// Install the workspace test subscriber + panic hook on test binaries.
// dev-dep is cfg(test)-gated (dev-dependencies only link for tests).
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    // The crash-child helper is a SEPARATE [[bin]] (crash_child.rs), so the
    // lib test main needs no env-gated re-exec dispatch — it just runs the
    // suite. (Contrast the FD-redirect re-exec in hole-common's test main.)
    skuld::run_all();
}
