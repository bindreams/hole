//! The NTSTATUS behind a failed call, which the Win32 code folds together with other causes: a delete-pending file
//! and a real denial are both `ERROR_ACCESS_DENIED`.
//!
//! The error keeps its [`io::ErrorKind`]. The OS code moves to the error's `source()`, so read it with
//! [`crate::error::raw_os_error`]. [`open_error`] is the one exception: it re-kinds the error as `NotFound` and
//! drops the code.

use std::fmt;
use std::fs::File;
use std::io;

use windows::Win32::Foundation::{RtlNtStatusToDosError, NTSTATUS, STATUS_DELETE_PENDING, STATUS_FILE_DELETED};

unsafe extern "system" {
    /// This thread's last NTSTATUS: the TEB's `LastStatusValue`.
    #[link_name = "RtlGetLastNtStatus"]
    fn rtl_get_last_nt_status() -> i32;

    /// Stores `status`, and its Win32 mapping, as this thread's last NTSTATUS and last error.
    #[link_name = "RtlSetLastWin32ErrorAndNtStatusFromNtStatus"]
    fn rtl_set_last_win32_error_and_nt_status_from_nt_status(status: i32);
}

const STATUS_SUCCESS: i32 = 0;

/// A failed call's error with the NTSTATUS behind it. `source()` is the original error; when that is an OS error its
/// raw code stays reachable.
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

/// A read's open that fails with `STATUS_FILE_DELETED` or `STATUS_DELETE_PENDING` is `NotFound`, naming the status.
/// `STATUS_FILE_DELETED`: a replace or delete has already taken the file the name still leads to.
/// `STATUS_DELETE_PENDING`: a delete waits for the last handle, and the name leads to that going-away file until then.
/// The Win32 code of both is `ERROR_ACCESS_DENIED`, which a real denial
/// shares, so only the status tells them apart. The code is not carried into the `NotFound`, or a reader of codes
/// ([`crate::retry::is_file_contention`]) would take a gone file for a transient denial. An error with no status, or
/// with another one, is returned as it is. Only the read is classified: to every other open the name is still taken,
/// and the OS's error says so.
pub(in crate::dir) fn open_error(err: io::Error) -> io::Error {
    let gone = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<WithNtStatus>())
        .filter(|with| [STATUS_FILE_DELETED, STATUS_DELETE_PENDING].contains(&NTSTATUS(with.status as i32)))
        .map(|with| with.status);
    match gone {
        Some(status) => WithNtStatus::wrap(io::ErrorKind::NotFound.into(), status),
        None => err,
    }
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
