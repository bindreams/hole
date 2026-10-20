use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_SYNCHRONIZE};

use super::{opened_from_token_read, ServiceSid};
use crate::cutover::scm_wait::hold::Opened;

#[skuld::test]
fn a_token_that_carries_the_sid_is_the_service() {
    assert!(matches!(opened_from_token_read((), 1, Ok(true)), Opened::Service(())));
}

#[skuld::test]
fn a_token_that_lacks_the_sid_is_not_the_service() {
    assert!(matches!(
        opened_from_token_read((), 1, Ok(false)),
        Opened::NotTheService
    ));
}

/// The service's own token is readable by SYSTEM and by an elevated
/// administrator, so a token the caller cannot read is not the service's. It is
/// not an error either: failing the retirement because some protected process
/// reused the id would stop an uninstall.
#[skuld::test]
fn a_token_that_cannot_be_read_is_not_the_service() {
    let denied = Err(io::Error::from_raw_os_error(5));
    assert!(matches!(opened_from_token_read((), 1, denied), Opened::NotTheService));
}

/// The real read that fails: a handle opened without
/// `PROCESS_QUERY_LIMITED_INFORMATION` cannot open its token, whatever the
/// caller's rights.
#[skuld::test]
fn a_process_whose_token_the_handle_cannot_open_is_not_the_service() {
    // SAFETY: plain FFI call.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, GetCurrentProcessId()) }
        .expect("open this process for synchronization only");
    // SAFETY: `OpenProcess` returned a new handle this value now owns.
    let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    let read = ServiceSid::everyone().is_in_token_of(&process);
    assert!(read.is_err(), "the token cannot be read through this handle: {read:?}");
    assert!(matches!(
        opened_from_token_read(process, 1, read),
        Opened::NotTheService
    ));
}
