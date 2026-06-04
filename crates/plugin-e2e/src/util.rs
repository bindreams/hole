//! Small shared helpers for the plugin-e2e suites. Lives in the lib (not
//! duplicated across `tests/*.rs`) so `interop.rs` and `roundtrip.rs` share one
//! copy.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

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

/// TCP-poll `addr` until it accepts a connection, bounded by `budget`.
///
/// Sanctioned CLAUDE.md sync-exception class 2: this waits on an out-of-process
/// plugin subprocess binding its public TCP port; `budget` is the
/// failure-to-human bound, not intra-process synchronization. The panic message
/// includes the attempt count and last error for Windows-CI diagnosis.
pub async fn wait_for_port(addr: SocketAddr, budget: Duration) {
    let start = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let err = match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(e) => e,
        };
        assert!(
            start.elapsed() < budget,
            "port {addr} not open within {budget:?} ({attempts} attempts; last error: {err})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
