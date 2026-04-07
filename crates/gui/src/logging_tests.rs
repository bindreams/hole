use super::*;
use skuld::temp_dir;
use std::path::Path;

/// Set the env var that disables the FD-level stdio redirect inside
/// `hole_common::logging::init`. Required because libtest-mimic prints its
/// per-test result lines to FD 1; with the redirect installed those lines
/// would be eaten and `cargo test` couldn't display per-test status.
fn disable_redirect() {
    // SAFETY: tests in this file run sequentially via skuld's test harness
    // and the env var is only ever set, never read concurrently with set.
    unsafe {
        std::env::set_var("HOLE_LOGGING_DISABLE_REDIRECT", "1");
    }
}

#[skuld::test]
fn init_creates_log_directory(#[fixture(temp_dir)] dir: &Path) {
    disable_redirect();
    let log_dir = dir.join("logs");
    let _guard = init(&log_dir);
    assert!(log_dir.exists());
}

#[skuld::test]
fn init_returns_guard(#[fixture(temp_dir)] dir: &Path) {
    disable_redirect();
    let log_dir = dir.join("logs");
    let guard = init(&log_dir);
    // Guard should be valid (not panic on drop)
    drop(guard);
}
