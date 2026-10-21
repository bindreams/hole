use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use super::*;
use crate::test_support::reap_child::EchoChild;

/// The creation time `GetProcessTimes` gives for `pid`, opened by id: what a
/// stamp's creation time must equal, taken by the call the stamp does not use.
fn creation_time_of(pid: u32) -> u64 {
    // SAFETY: plain FFI; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
        .expect("open the process");
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the handle is live with the query right; the out-values are locals.
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }.expect("process times");
    // SAFETY: opened above.
    let _ = unsafe { CloseHandle(handle) };
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

#[skuld::test]
fn a_stamp_round_trips_through_its_text() {
    for stamp in [
        Stamp { pid: 0, created: 0 },
        Stamp {
            pid: 4_321,
            created: 134_370_313_404_843_031,
        },
        Stamp {
            pid: u32::MAX,
            created: u64::MAX,
        },
    ] {
        assert_eq!(Stamp::decode(&stamp.encode()), Some(stamp));
    }
    assert_eq!(Stamp { pid: 7, created: 9 }.encode(), "7:9");
}

#[skuld::test]
fn text_that_is_not_a_stamp_is_not_one() {
    for text in [
        "",
        "1",
        ":",
        "1:",
        ":2",
        "a:2",
        "1:b",
        "1:2:3",
        " 1:2",
        "1:2 ",
        "-1:2",
        "+1:2",
        "4294967296:2",
        "1:18446744073709551616",
        "1\n2",
    ] {
        assert_eq!(Stamp::decode(text), None, "{text:?}");
    }
}

/// The snapshot's creation time is read from a structure Windows documents
/// only as opaque bytes; it must be the time `GetProcessTimes` gives, or every
/// stamp reads as a process that is gone.
#[skuld::test]
fn the_creation_time_a_stamp_carries_is_the_one_the_process_times_call_gives() {
    let here = Stamp::current();
    assert_eq!(here.pid, std::process::id());
    assert_eq!(here.created, creation_time_of(here.pid));

    let child = EchoChild::spawn();
    let listed = Stamp::of_listed_process(child.pid())
        .expect("snapshot")
        .expect("the child is listed");
    assert_eq!(listed.created, creation_time_of(child.pid()));
}

#[skuld::test]
fn the_stamping_process_is_running() {
    assert!(Stamp::current().is_running().expect("probe"));
}

#[skuld::test]
fn a_process_that_exited_is_not_running() {
    let mut child = EchoChild::spawn();
    let stamp = Stamp::of_listed_process(child.pid())
        .expect("snapshot")
        .expect("listed");
    assert!(stamp.is_running().expect("probe"), "running while the child is up");

    child.release_and_wait();
    assert!(!stamp.is_running().expect("probe"), "gone once the child exited");
}

/// The id of a running process with another creation time is a reused id.
#[skuld::test]
fn a_running_pid_with_another_creation_time_is_not_the_stamped_process() {
    let here = Stamp::current();
    for created in [here.created.wrapping_add(1), here.created.wrapping_sub(1), 0] {
        let reused = Stamp { pid: here.pid, created };
        assert!(!reused.is_running().expect("probe"), "{created}");
    }
}

/// A process the caller cannot open is still found, which an open by id could
/// not do for another user's or SYSTEM's. Pid 4 is the System process.
#[skuld::test]
fn a_process_the_caller_cannot_open_is_still_found_by_the_snapshot() {
    let system = Stamp::of_listed_process(4)
        .expect("snapshot")
        .expect("the System process is listed");
    assert_eq!(system.pid, 4);
    assert!(system.is_running().expect("probe"));
}
