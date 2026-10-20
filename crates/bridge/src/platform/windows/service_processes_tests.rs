use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_SYNCHRONIZE};

use super::{has_exited, open_process, opened_from_token_read, scan_service_processes, ServiceProcesses, ServiceSid};
use crate::cutover::scm_wait::call_error::{io_error_is_a_refused_process_open, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Opened};
use crate::cutover::scm_wait::ReportedPid;

const VALID: Basis = Basis::Named(ReportedPid::Valid);
const MAY_BE_INVALID: Basis = Basis::Named(ReportedPid::MayBeInvalid);

fn read_failed(call: ScmCall, code: u32) -> io::Result<bool> {
    Err(ScmCallError { call, code }.into_io())
}

fn never_exited(_: &()) -> io::Result<bool> {
    Ok(false)
}

#[skuld::test]
fn a_token_that_carries_the_sid_is_the_service_on_every_basis() {
    for basis in [VALID, MAY_BE_INVALID, Basis::Scanned] {
        let got = opened_from_token_read((), basis, Ok(true), never_exited);
        assert!(matches!(got, Ok(Opened::Service(()))), "{basis:?}");
    }
}

#[skuld::test]
fn a_token_that_lacks_the_sid_is_not_the_service_on_every_basis() {
    for basis in [VALID, MAY_BE_INVALID, Basis::Scanned] {
        let got = opened_from_token_read((), basis, Ok(false), never_exited);
        assert!(matches!(got, Ok(Opened::NotTheService)), "{basis:?}");
    }
}

/// The service's own token is readable by SYSTEM and by an elevated
/// administrator, so where the SCM names the id and the id is valid, a token
/// that cannot be read is the service's own process: failing is the answer,
/// as the refused open of its process, not a process to leave behind.
#[skuld::test]
fn a_denied_token_on_a_valid_id_is_a_refused_open() {
    let got = opened_from_token_read((), VALID, read_failed(ScmCall::OpenProcessToken, 5), never_exited);
    let error = got.expect_err("an unreadable service process fails");
    assert!(io_error_is_a_refused_process_open(&error), "{error}");
    let got = opened_from_token_read((), VALID, read_failed(ScmCall::GetTokenInformation, 5), never_exited);
    assert!(io_error_is_a_refused_process_open(&got.expect_err("fails")));
}

/// Where the id may name anything, or when every process on the host is
/// looked at, a denial is some other principal's process.
#[skuld::test]
fn a_denied_token_where_a_stranger_is_possible_is_not_the_service() {
    for basis in [MAY_BE_INVALID, Basis::Scanned] {
        let got = opened_from_token_read((), basis, read_failed(ScmCall::OpenProcessToken, 5), never_exited);
        assert!(matches!(got, Ok(Opened::NotTheService)), "{basis:?}");
    }
}

/// A failure that is not a denial proves nothing about whose process it is:
/// fatal for an id the SCM named, reported for a scan.
#[skuld::test]
fn another_token_failure_is_fatal_for_a_named_id_and_undetermined_for_a_scan() {
    for basis in [VALID, MAY_BE_INVALID] {
        let got = opened_from_token_read((), basis, read_failed(ScmCall::GetTokenInformation, 122), never_exited);
        let error = got.expect_err("fails");
        assert!(io_error_is_a_refused_process_open(&error), "{basis:?}: {error}");
    }
    let got = opened_from_token_read(
        (),
        Basis::Scanned,
        read_failed(ScmCall::GetTokenInformation, 122),
        never_exited,
    );
    assert!(matches!(got, Ok(Opened::Undetermined { code: Some(122) })));
}

/// A token read can fail because the process is exiting under it; that is the
/// process being gone, whatever the basis says a denial means.
#[skuld::test]
fn a_token_that_cannot_be_read_from_a_process_that_has_exited_is_no_process() {
    for basis in [VALID, MAY_BE_INVALID, Basis::Scanned] {
        let got = opened_from_token_read((), basis, read_failed(ScmCall::OpenProcessToken, 5), |_| Ok(true));
        assert!(matches!(got, Ok(Opened::NoSuchProcess)), "{basis:?}");
    }
}

/// The real read that fails: a handle opened without
/// `PROCESS_QUERY_LIMITED_INFORMATION` cannot open its token, whatever the
/// caller's rights.
#[skuld::test]
fn a_process_whose_token_the_handle_cannot_open_is_not_readable() {
    // SAFETY: plain FFI call.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, GetCurrentProcessId()) }
        .expect("open this process for synchronization only");
    // SAFETY: `OpenProcess` returned a new handle this value now owns.
    let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    let read = ServiceSid::everyone().is_in_token_of(&process);
    assert!(read.is_err(), "the token cannot be read through this handle: {read:?}");
    let for_a_scan = opened_from_token_read(process, Basis::Scanned, read, has_exited);
    assert!(matches!(for_a_scan, Ok(Opened::NotTheService)));
}

/// The real open of an id no process has.
#[skuld::test]
fn an_id_no_process_has_is_no_process() {
    // 0xFFFF_FFFC is a multiple of four and above any id the system hands out.
    let got = open_process(0xFFFF_FFFC, &ServiceSid::everyone(), VALID);
    assert!(matches!(got, Ok(Opened::NoSuchProcess)), "{:?}", got.err());
}

/// The scan for a SID every token carries finds the live processes this
/// caller can read, and never the calling one.
#[skuld::test]
fn the_scan_skips_the_calling_process_and_finds_others() {
    let found = scan_service_processes(&ServiceSid::everyone()).expect("scan");
    let this = std::process::id();
    assert!(
        found.alive.iter().all(|(pid, _)| *pid != this),
        "the scan took the calling process for one to wait on"
    );
    assert!(
        !found.alive.is_empty(),
        "the scan found no other process this caller can read (the test runner's parent is one)"
    );
}

/// A SID no token carries finds nothing, however many processes are read.
#[skuld::test]
fn the_scan_for_a_sid_nothing_carries_finds_nothing() {
    let found = scan_service_processes(&ServiceSid::nothing_carries()).expect("scan");
    assert!(found.alive.is_empty());
}

/// A live process held is alive; nothing held is not.
#[skuld::test]
fn service_processes_are_alive_while_a_held_process_has_not_exited() {
    let mut processes = ServiceProcesses::default();
    assert!(!processes.any_alive().expect("nothing held"));
    // SAFETY: plain FFI call.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, GetCurrentProcessId()) }
        .expect("open this process for synchronization only");
    // SAFETY: `OpenProcess` returned a new handle this value now owns.
    let this = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    processes.holds.adopt(std::process::id(), this);
    assert!(processes.any_alive().expect("this process is running"));
}
