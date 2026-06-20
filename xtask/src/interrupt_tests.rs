//! Unix-gated and nextest-isolated: run with `cargo nextest run` so each test
//! is its own process; self-`raise(SIGINT)` would otherwise hit the shared
//! `cargo test` process (skuld runs in-process). Mirrors
//! crates/dev-console/src/interrupts_tests.rs.

/// After installing the transparent handler, a SIGINT must NOT terminate the
/// process (default disposition would). Reaching the line past the raise is the
/// proof of survival — no timing (raise delivers synchronously before return).
#[cfg(unix)]
#[skuld::test]
fn transparent_handler_survives_sigint() {
    crate::install_transparent_interrupt();
    // SAFETY: raising SIGINT to our own process is sound; the no-op handler
    // installed above replaced the default (terminate) disposition.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    // If the handler were absent, the process would have died on the line above.
}
