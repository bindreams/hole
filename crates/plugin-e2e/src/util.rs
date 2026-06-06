//! Small shared helpers for the plugin-e2e suites. Lives in the lib (not
//! duplicated across `tests/*.rs`) so `interop.rs` and `roundtrip.rs` share one
//! copy.

use std::path::Path;

/// One fresh tokio runtime per test body (the suites are `#[skuld::test]`
/// sync fns that `block_on` their async work).
pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Fail loudly if a required plugin binary is missing, with a remediation hint.
/// Per CLAUDE.md: never silently skip on a missing test dependency.
pub fn require_binary(path: &Path, remediation: &str) {
    assert!(
        path.is_file(),
        "plugin-e2e dependency missing at {path:?} — {remediation}"
    );
}
