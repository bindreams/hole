use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FileDispositionInfo, LockFileEx, SetFileInformationByHandle, DELETE, FILE_DISPOSITION_INFO,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows::Win32::System::IO::OVERLAPPED;

use crate::dir::{Dir, ReadDir};
use crate::retry::is_file_contention;

fn put(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// `ReadDir::read` of `name` in the folder of `dir`.
fn read(dir: &tempfile::TempDir, name: &str) -> io::Result<Vec<u8>> {
    ReadDir::open(dir.path(), crate::dir::Principal::System)
        .unwrap()
        .read(name.as_ref())
}

/// [`read`] as an unprivileged thread: a reader with backup rights reads through a holder that denies sharing.
fn read_unprivileged(dir: &tempfile::TempDir, name: &str) -> io::Result<Vec<u8>> {
    crate::dir::testing::as_unprivileged_thread(|| read(dir, name))
}

/// The Win32 code of the call that failed, behind the status wrapper.
fn original_code(err: &io::Error) -> Option<i32> {
    let original = err.get_ref()?.source()?.downcast_ref::<io::Error>()?;
    original.raw_os_error()
}

// A failed open names its NTSTATUS ------------------------------------------------------------------------------------

#[skuld::test]
fn read_of_a_missing_file_names_the_ntstatus_of_the_open() {
    let dir = tempfile::tempdir().unwrap();
    let err = read(&dir, "absent").unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err:?}");
    // STATUS_OBJECT_NAME_NOT_FOUND
    assert!(err.to_string().contains("NTSTATUS 0xC0000034"), "{err}");
}

#[skuld::test]
fn read_of_a_file_held_without_sharing_names_the_ntstatus_of_the_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = put(&dir, "held", b"bytes");
    let _held = crate::dir::testing::held_without_sharing(&path);

    let err = read_unprivileged(&dir, "held").unwrap_err();

    assert_eq!(err.kind(), std::fs::read(&path).unwrap_err().kind(), "{err:?}");
    // STATUS_SHARING_VIOLATION
    assert!(err.to_string().contains("NTSTATUS 0xC0000043"), "{err}");
}

/// The outer error carries no OS code of its own: the code is the source's. Every reader of a code sees through
/// the wrapper (`util::error::raw_os_error`), `is_file_contention` among them.
#[skuld::test]
fn the_os_code_of_a_status_error_is_in_its_source_and_readers_see_through_the_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let path = put(&dir, "held", b"bytes");
    let _held = crate::dir::testing::held_without_sharing(&path);

    let err = read_unprivileged(&dir, "held").unwrap_err();

    assert_eq!(err.raw_os_error(), None, "{err:?}");
    assert_eq!(original_code(&err), Some(32), "ERROR_SHARING_VIOLATION: {err:?}");
    assert_eq!(crate::error::raw_os_error(&err), Some(32), "{err:?}");
    assert!(is_file_contention(&err), "{err:?}");
}

/// A file marked for deletion while a handle to it is open stays at its name until that handle closes, and the open
/// answers `Access is denied` for it: the case the Win32 code alone cannot tell from a real denial. The plain delete
/// calls remove the name at once on current Windows, so the mark is set through the handle.
#[skuld::test]
fn read_of_a_delete_pending_file_names_its_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = put(&dir, "pending", b"bytes");
    let marked = std::fs::OpenOptions::new().access_mode(DELETE.0).open(&path).unwrap();
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `info` is a valid `FILE_DISPOSITION_INFO` of the size passed.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(marked.as_raw_handle()),
            FileDispositionInfo,
            (&raw const info).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .unwrap();

    let err = read(&dir, "pending").unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err:?}");
    // STATUS_DELETE_PENDING
    assert!(err.to_string().contains("NTSTATUS 0xC0000056"), "{err}");
    assert_eq!(original_code(&err), Some(5), "ERROR_ACCESS_DENIED: {err:?}");
    assert!(is_file_contention(&err), "{err:?}");
}

#[skuld::test]
fn the_source_of_a_status_error_is_the_original_io_error_with_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let err = read(&dir, "absent").unwrap_err();

    assert_eq!(original_code(&err), Some(2), "ERROR_FILE_NOT_FOUND: {err:?}");
}

/// The test harness panics with `{:?}`, so that is what the CI log of a hit shows.
#[skuld::test]
fn debug_shows_the_status_in_hex() {
    let dir = tempfile::tempdir().unwrap();
    let err = read(&dir, "absent").unwrap_err();

    assert!(format!("{err:?}").contains("0xC0000034"), "{err:?}");
}

// A failed read names its NTSTATUS ------------------------------------------------------------------------------------

/// The open succeeds and the read fails: the status is the read's, not a leftover of the missing-name open that
/// primes the thread here.
#[skuld::test]
fn a_read_that_fails_after_a_good_open_names_the_status_of_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = put(&dir, "locked", b"bytes");
    let holder = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the handle is open for reading and `overlapped` outlives the call.
    unsafe {
        LockFileEx(
            HANDLE(holder.as_raw_handle()),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            5,
            0,
            &mut overlapped,
        )
    }
    .unwrap();
    let _ = read(&dir, "absent");

    let err = read(&dir, "locked").unwrap_err();

    // STATUS_FILE_LOCK_CONFLICT
    assert!(err.to_string().contains("NTSTATUS 0xC0000054"), "{err}");
    assert_eq!(original_code(&err), Some(33), "ERROR_LOCK_VIOLATION: {err:?}");
}

#[skuld::test]
fn read_of_a_file_returns_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    put(&dir, "f", b"bytes");

    assert_eq!(read(&dir, "f").unwrap(), b"bytes");
}

// Every NT call, not only the open ------------------------------------------------------------------------------------

#[skuld::test]
fn a_rename_onto_a_taken_name_keeps_its_kind_and_names_the_status() {
    let dir = tempfile::tempdir().unwrap();
    put(&dir, "from", b"f");
    put(&dir, "to", b"t");

    let err = Dir::open(dir.path(), false, None, crate::dir::Principal::System)
        .unwrap()
        .rename_noreplace("from".as_ref(), "to".as_ref())
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err:?}");
    // STATUS_OBJECT_NAME_COLLISION
    assert!(err.to_string().contains("NTSTATUS 0xC0000035"), "{err}");
}
