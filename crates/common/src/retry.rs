//! Generic retry helpers with exponential backoff, plus predicates for
//! common transient-error classes:
//!
//! * [`is_file_contention`] — `DistHarness::spawn` uses this to convert
//!   transient Windows Defender / macOS exec-busy errors into passes.
//! * [`is_bind_race`] — `port_alloc::free_port` uses this to retry around
//!   Windows WSAEACCES (independent TCP/UDP excluded-port tables),
//!   EADDRINUSE, and EADDRNOTAVAIL on ephemeral bind paths.
//!
//! Sleep uses `tokio::time::sleep`, so callers must be on a Tokio
//! runtime. Tests use `tokio::time::pause()` so the runtime
//! auto-advances mock time between retries instead of burning
//! wall-clock seconds on exponential backoff.
//!
//! Neither [`retry_if`] nor [`retry_if_async`] imposes a `Send` bound on
//! the operation or its return types — both are awaited inline at all
//! current call sites, not spawned. A caller who needs a spawnable future
//! can wrap the call themselves.

use std::future::Future;
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

/// Async variant of [`retry_if`]: `op` returns a future per attempt.
/// Same contract as the sync version, but each attempt is `await`ed.
/// Callers that want no delay between attempts pass `Duration::ZERO`
/// for `base_delay` — the sleep still happens but resolves instantly.
pub async fn retry_if_async<F, Fut, T, E>(
    mut op: F,
    predicate: impl Fn(&E) -> bool,
    max_attempts: NonZeroU32,
    base_delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let n = max_attempts.get();
    for attempt in 0..n {
        match op().await {
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

/// Returns `true` for `io::Error`s that indicate a transient bind race
/// on an ephemeral port:
///
/// * `AddrInUse` — another socket took the port between our drop and our
///   next bind (`WSAEADDRINUSE` / `EADDRINUSE`).
/// * `PermissionDenied` — Windows `WSAEACCES`: the OS's independent
///   TCP/UDP excluded-port-range tables disagree about whether a
///   just-allocated port is bindable, or another socket holds the port
///   with `SO_EXCLUSIVEADDRUSE` on a wildcard address. See
///   bindreams/galoshes#20 for the deterministic reproducer.
/// * `AddrNotAvailable` — same excluded-port-range class; distinct from
///   `WSAEACCES` only in whether the kernel rejects the bind at the
///   address-reservation layer or the permission layer
///   (`WSAEADDRNOTAVAIL` / `EADDRNOTAVAIL`).
///
/// **Contract**: use ONLY with ephemeral `bind(:0)` paths. On Unix,
/// `PermissionDenied` also means "bind to a privileged port without
/// root" — retrying would waste attempts and ultimately mask the real
/// permission error. The `port_alloc::free_port` API enforces this by
/// only allocating via the OS ephemeral allocator.
pub fn is_bind_race(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable,
    )
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
