//! Generic retry helper with exponential backoff, plus the
//! `is_file_contention` predicate used by `DistHarness::spawn` to
//! convert transient Windows Defender / macOS exec-busy errors into
//! passes.
//!
//! Sleep uses `tokio::time::sleep`, so callers must be on a Tokio
//! runtime. Tests use `tokio::time::pause()` / `advance()` to avoid
//! burning wall-clock seconds on exponential backoff.

use std::io;
use std::num::NonZeroU32;
use std::time::Duration;

/// Compute an exponential-backoff delay: `base * 2^attempt`, saturating
/// at `u32::MAX` for the multiplier and at `Duration::MAX` for the
/// final product.
pub fn exp_backoff(attempt: u32, base: Duration) -> Duration {
    base.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
}

/// Run `op`, retrying up to `max_attempts` times on errors that match
/// `predicate`. Sleeps `exp_backoff(attempt, base_delay)` between
/// attempts. Errors that don't match the predicate are returned
/// immediately without retry; the terminal error is returned
/// unchanged.
pub async fn retry_if<F, T, E>(
    mut op: F,
    predicate: impl Fn(&E) -> bool,
    max_attempts: NonZeroU32,
    base_delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let n = max_attempts.get();
    for attempt in 0..n {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if attempt + 1 < n && predicate(&e) => {
                tokio::time::sleep(exp_backoff(attempt, base_delay)).await;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("NonZeroU32 guarantees n >= 1")
}

/// Returns `true` for the OS-specific error codes that typically mean
/// "another process holds a handle that blocks this operation":
/// `ERROR_ACCESS_DENIED` (5) and `ERROR_SHARING_VIOLATION` (32) on
/// Windows, `ETXTBSY` / `EBUSY` on macOS.
pub fn is_file_contention(err: &io::Error) -> bool {
    match err.raw_os_error() {
        #[cfg(windows)]
        Some(5 | 32) => true,
        #[cfg(target_os = "macos")]
        Some(e) if e == libc::ETXTBSY || e == libc::EBUSY => true,
        _ => false,
    }
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
