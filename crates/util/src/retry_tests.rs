use super::{exp_backoff, is_bind_race, is_file_contention, retry_if, retry_if_async};
use std::cell::Cell;
use std::io;
use std::num::NonZeroU32;
use std::time::Duration;

const BASE: Duration = Duration::from_millis(100);
const THREE: NonZeroU32 = NonZeroU32::new(3).expect("literal");

// exp_backoff =========================================================================================================

#[skuld::test]
fn exp_backoff_attempt_zero_returns_base() {
    assert_eq!(exp_backoff(0, BASE), BASE);
}

#[skuld::test]
fn exp_backoff_doubles_per_attempt() {
    assert_eq!(exp_backoff(1, BASE), BASE * 2);
    assert_eq!(exp_backoff(2, BASE), BASE * 4);
    assert_eq!(exp_backoff(3, BASE), BASE * 8);
}

#[skuld::test]
fn exp_backoff_last_in_range_shift() {
    // attempt = 31: 1u32 << 31 = 0x8000_0000 (last valid shift amount
    // for a u32).
    assert_eq!(exp_backoff(31, BASE), BASE.saturating_mul(0x8000_0000));
}

#[skuld::test]
fn exp_backoff_overflow_saturates() {
    // attempt >= 32: checked_shl returns None, we fall back to u32::MAX;
    // the resulting Duration multiplication saturates. Must not panic.
    let d32 = exp_backoff(32, BASE);
    let d_huge = exp_backoff(1_000_000, BASE);
    assert_eq!(d32, BASE.saturating_mul(u32::MAX));
    assert_eq!(d_huge, BASE.saturating_mul(u32::MAX));
}

// retry_if ============================================================================================================

#[skuld::test]
async fn retry_if_returns_ok_on_first_attempt_without_retrying() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<i32, io::Error> = retry_if(
        || {
            calls.set(calls.get() + 1);
            Ok(42)
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap(), 42);
    assert_eq!(calls.get(), 1);
}

#[skuld::test]
async fn retry_if_retries_until_success() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<&'static str, io::Error> = retry_if(
        || {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 {
                Err(io::Error::other("transient"))
            } else {
                Ok("done")
            }
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap(), "done");
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn retry_if_returns_terminal_err_after_max_attempts() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<(), io::Error> = retry_if(
        || {
            calls.set(calls.get() + 1);
            Err(io::Error::other("nope"))
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap_err().to_string(), "nope");
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn retry_if_sleeps_follow_exponential_schedule() {
    // With `tokio::time::pause()` + auto-advance, each `sleep()` resolves
    // as soon as nothing else is pending. Capture the elapsed mock time
    // at every `op()` invocation; the vector must match the expected
    // backoff schedule [0, BASE, BASE + 2·BASE] = [0, BASE, 3·BASE].
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let observed: std::cell::RefCell<Vec<Duration>> = std::cell::RefCell::new(Vec::new());

    let result: Result<(), io::Error> = retry_if(
        || {
            observed.borrow_mut().push(tokio::time::Instant::now() - start);
            Err(io::Error::other("trigger retry"))
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;

    assert!(result.is_err());
    let observed = observed.into_inner();
    assert_eq!(observed.len(), 3);
    // tokio's paused clock advances in discrete ticks, so equality is
    // unreliable (observed overshoot of 1ms on Windows). Tolerate a
    // small window around the exact expected schedule.
    let tol = Duration::from_millis(5);
    let expect_eq = |idx: usize, got: Duration, want: Duration| {
        let low = want.saturating_sub(tol);
        let high = want + tol;
        assert!(
            got >= low && got <= high,
            "attempt {idx}: expected ~{want:?} (±{tol:?}), got {got:?}"
        );
    };
    expect_eq(0, observed[0], Duration::ZERO);
    expect_eq(1, observed[1], BASE);
    expect_eq(2, observed[2], BASE * 3);
}

#[skuld::test]
async fn retry_if_non_matching_predicate_does_not_retry() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<(), io::Error> = retry_if(
        || {
            calls.set(calls.get() + 1);
            Err(io::Error::other("other"))
        },
        |_| false,
        THREE,
        BASE,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
}

// is_file_contention ==================================================================================================

#[cfg(windows)]
#[skuld::test]
fn is_file_contention_access_denied_windows() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(5)));
}

#[cfg(windows)]
#[skuld::test]
fn is_file_contention_sharing_violation_windows() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(32)));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn is_file_contention_etxtbsy_macos() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(libc::ETXTBSY)));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn is_file_contention_ebusy_macos() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(libc::EBUSY)));
}

#[skuld::test]
fn is_file_contention_unrelated_error_returns_false() {
    // ErrorKind::NotFound, no raw_os_error.
    assert!(!is_file_contention(&io::Error::from(io::ErrorKind::NotFound)));
}

// retry_if_async ======================================================================================================

#[skuld::test]
async fn retry_if_async_returns_ok_on_first_attempt_without_retrying() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<i32, io::Error> = retry_if_async(
        || {
            calls.set(calls.get() + 1);
            async { Ok(42) }
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap(), 42);
    assert_eq!(calls.get(), 1);
}

#[skuld::test]
async fn retry_if_async_retries_until_success() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<&'static str, io::Error> = retry_if_async(
        || {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < 3 {
                    Err(io::Error::other("transient"))
                } else {
                    Ok("done")
                }
            }
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap(), "done");
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn retry_if_async_returns_terminal_err_after_max_attempts() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<(), io::Error> = retry_if_async(
        || {
            calls.set(calls.get() + 1);
            async { Err(io::Error::other("nope")) }
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;
    assert_eq!(result.unwrap_err().to_string(), "nope");
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn retry_if_async_sleeps_follow_exponential_schedule() {
    // Mirrors the sync retry_if timing test: paused clock, capture elapsed
    // at every op() invocation, compare to the exponential schedule.
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let observed: std::cell::RefCell<Vec<Duration>> = std::cell::RefCell::new(Vec::new());

    let result: Result<(), io::Error> = retry_if_async(
        || {
            observed.borrow_mut().push(tokio::time::Instant::now() - start);
            async { Err(io::Error::other("trigger retry")) }
        },
        |_| true,
        THREE,
        BASE,
    )
    .await;

    assert!(result.is_err());
    let observed = observed.into_inner();
    assert_eq!(observed.len(), 3);
    let tol = Duration::from_millis(5);
    let expect_eq = |idx: usize, got: Duration, want: Duration| {
        let low = want.saturating_sub(tol);
        let high = want + tol;
        assert!(
            got >= low && got <= high,
            "attempt {idx}: expected ~{want:?} (±{tol:?}), got {got:?}"
        );
    };
    expect_eq(0, observed[0], Duration::ZERO);
    expect_eq(1, observed[1], BASE);
    expect_eq(2, observed[2], BASE * 3);
}

#[skuld::test]
async fn retry_if_async_non_matching_predicate_does_not_retry() {
    tokio::time::pause();
    let calls = Cell::new(0u32);
    let result: Result<(), io::Error> = retry_if_async(
        || {
            calls.set(calls.get() + 1);
            async { Err(io::Error::other("other")) }
        },
        |_| false,
        THREE,
        BASE,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
}

#[skuld::test]
async fn retry_if_async_honours_zero_base_delay() {
    // With `Duration::ZERO`, sleeps still happen but resolve instantly —
    // total elapsed mock time should remain at zero across attempts.
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let calls = Cell::new(0u32);
    let result: Result<(), io::Error> = retry_if_async(
        || {
            calls.set(calls.get() + 1);
            async { Err(io::Error::other("trigger retry")) }
        },
        |_| true,
        THREE,
        Duration::ZERO,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls.get(), 3);
    let elapsed = tokio::time::Instant::now() - start;
    assert!(
        elapsed < Duration::from_millis(5),
        "ZERO base_delay should not advance the paused clock, got {elapsed:?}"
    );
}

// is_bind_race ========================================================================================================

#[skuld::test]
fn is_bind_race_matches_addr_in_use() {
    assert!(is_bind_race(&io::Error::from(io::ErrorKind::AddrInUse)));
}

#[skuld::test]
fn is_bind_race_matches_permission_denied() {
    assert!(is_bind_race(&io::Error::from(io::ErrorKind::PermissionDenied)));
}

#[skuld::test]
fn is_bind_race_matches_addr_not_available() {
    assert!(is_bind_race(&io::Error::from(io::ErrorKind::AddrNotAvailable)));
}

#[skuld::test]
fn is_bind_race_rejects_unrelated_kinds() {
    assert!(!is_bind_race(&io::Error::from(io::ErrorKind::NotFound)));
    assert!(!is_bind_race(&io::Error::from(io::ErrorKind::WouldBlock)));
    assert!(!is_bind_race(&io::Error::from(io::ErrorKind::ConnectionRefused)));
    assert!(!is_bind_race(&io::Error::from(io::ErrorKind::TimedOut)));
}

#[cfg(windows)]
#[skuld::test]
fn is_bind_race_matches_wsaeaccess_raw_code() {
    // WSAEACCES = 10013 surfaces as ErrorKind::PermissionDenied on Windows;
    // this is the concrete error the predicate exists to catch.
    assert!(is_bind_race(&io::Error::from_raw_os_error(10013)));
}

#[cfg(windows)]
#[skuld::test]
fn is_bind_race_matches_wsaeaddrinuse_raw_code() {
    // WSAEADDRINUSE = 10048 -> ErrorKind::AddrInUse.
    assert!(is_bind_race(&io::Error::from_raw_os_error(10048)));
}

#[cfg(windows)]
#[skuld::test]
fn is_bind_race_matches_wsaeaddrnotavail_raw_code() {
    // WSAEADDRNOTAVAIL = 10049 -> ErrorKind::AddrNotAvailable.
    assert!(is_bind_race(&io::Error::from_raw_os_error(10049)));
}
