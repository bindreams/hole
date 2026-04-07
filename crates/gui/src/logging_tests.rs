use super::*;
use skuld::temp_dir;
use std::path::Path;

/// RAII guard: sets `HOLE_LOGGING_DISABLE_REDIRECT` on construction and
/// clears it on drop. Required because libtest-mimic prints its per-test
/// result lines to FD 1; with the redirect installed those lines would be
/// eaten. The cleanup-on-drop ensures the env var does not leak into any
/// subsequent test in the same process that happens to call `init()`.
struct DisableRedirectGuard;

impl DisableRedirectGuard {
    fn new() -> Self {
        // SAFETY: these tests are marked `serial`, so no other test reads or
        // writes the process environment concurrently.
        unsafe {
            std::env::set_var("HOLE_LOGGING_DISABLE_REDIRECT", "1");
        }
        Self
    }
}

impl Drop for DisableRedirectGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("HOLE_LOGGING_DISABLE_REDIRECT");
        }
    }
}

#[skuld::test(serial)]
fn init_creates_log_directory(#[fixture(temp_dir)] dir: &Path) {
    let _g = DisableRedirectGuard::new();
    let log_dir = dir.join("logs");
    let _guard = init(&log_dir);
    assert!(log_dir.exists());
}

#[skuld::test(serial)]
fn init_returns_guard(#[fixture(temp_dir)] dir: &Path) {
    let _g = DisableRedirectGuard::new();
    let log_dir = dir.join("logs");
    let guard = init(&log_dir);
    // Guard should be valid (not panic on drop)
    drop(guard);
}
