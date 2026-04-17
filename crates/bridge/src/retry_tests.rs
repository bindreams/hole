use super::{exp_backoff, is_file_contention, retry_if};
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
