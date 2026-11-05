//! The NTSTATUS behind a failed call, which the Win32 code folds together with other causes: a delete-pending file
//! and a real denial are both `ERROR_ACCESS_DENIED`.
//!
//! The error keeps its [`io::ErrorKind`]. The OS code moves to the error's `source()`, so read it with
//! [`crate::error::raw_os_error`].

use std::fmt;
use std::fs::File;
use std::io;

use windows::Win32::Foundation::{RtlNtStatusToDosError, NTSTATUS};

unsafe extern "system" {
    /// This thread's last NTSTATUS: the TEB's `LastStatusValue`.
    #[link_name = "RtlGetLastNtStatus"]
    fn rtl_get_last_nt_status() -> i32;

    /// Stores `status`, and its Win32 mapping, as this thread's last NTSTATUS and last error.
    #[link_name = "RtlSetLastWin32ErrorAndNtStatusFromNtStatus"]
    fn rtl_set_last_win32_error_and_nt_status_from_nt_status(status: i32);
}

const STATUS_SUCCESS: i32 = 0;

/// A failed call's error with the NTSTATUS behind it. `source()` is the original, so its raw OS code stays reachable.
struct WithNtStatus {
    original: io::Error,
    status: u32,
}

impl WithNtStatus {
    fn wrap(original: io::Error, status: u32) -> io::Error {
        io::Error::new(original.kind(), WithNtStatus { original, status })
    }
}

impl fmt::Display for WithNtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (NTSTATUS {:#010X})", self.original, self.status)
    }
}

impl fmt::Debug for WithNtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithNtStatus")
            .field("original", &self.original)
            .field("status", &format_args!("{:#010X}", self.status))
            .finish()
    }
}

impl std::error::Error for WithNtStatus {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// The error of a failed `NTSTATUS` call: its Win32 mapping, naming the status.
pub(in crate::dir) fn error_of(status: NTSTATUS) -> io::Error {
    // SAFETY: `RtlNtStatusToDosError` takes a status by value and has no preconditions.
    let code = unsafe { RtlNtStatusToDosError(status) };
    WithNtStatus::wrap(io::Error::from_raw_os_error(code as i32), status.0 as u32)
}

/// Reads the rest of `file`, like `Read::read_to_end`. A failure from the kernel also names its NTSTATUS.
///
/// `std` fails a read with `RtlNtStatusToDosError`, which stores the status it is given as the thread's last. A
/// failure that never passes one leaves an earlier call's, so the status is cleared first and a failure that leaves
/// it clear carries none. After the failure `std` only frees its buffer, and that stores no status.
pub(in crate::dir) fn read_to_end(mut file: File) -> io::Result<Vec<u8>> {
    use std::io::Read;

    // SAFETY: takes a status by value and writes only this thread's TEB.
    unsafe { rtl_set_last_win32_error_and_nt_status_from_nt_status(STATUS_SUCCESS) };
    let mut bytes = Vec::new();
    let original = match file.read_to_end(&mut bytes) {
        Ok(_) => return Ok(bytes),
        Err(original) => original,
    };
    // SAFETY: takes no arguments and only reads this thread's TEB.
    let status = unsafe { rtl_get_last_nt_status() };
    if status == STATUS_SUCCESS {
        return Err(original);
    }
    Err(WithNtStatus::wrap(original, status as u32))
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod status_tests;
