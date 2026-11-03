use std::io;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use super::read;
use super::{publish, rename_noreplace};
use crate::versioned_file::fixtures::{dir, names, put};

#[skuld::test]
fn rename_noreplace_moves_to_a_free_name() {
    let dir = dir();
    let from = put(&dir, "a", b"bytes");

    rename_noreplace(&from, &dir.path().join("b")).unwrap();

    assert_eq!(names(&dir), ["b"]);
    assert_eq!(std::fs::read(dir.path().join("b")).unwrap(), b"bytes");
}

#[skuld::test]
fn rename_noreplace_never_replaces_and_leaves_both_files() {
    let dir = dir();
    let from = put(&dir, "a", b"from");
    let to = put(&dir, "b", b"to");

    let err = rename_noreplace(&from, &to).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err:?}");
    assert_eq!(std::fs::read(&from).unwrap(), b"from");
    assert_eq!(std::fs::read(&to).unwrap(), b"to");
}

#[skuld::test]
fn rename_noreplace_of_a_missing_file_is_not_found() {
    let dir = dir();
    let err = rename_noreplace(&dir.path().join("a"), &dir.path().join("b")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err:?}");
    assert!(names(&dir).is_empty());
}

#[skuld::test]
fn publish_replaces_the_destination_and_leaves_no_temp() {
    let dir = dir();
    let dest = put(&dir, "dest", b"old");
    let mut tmp = tempfile::Builder::new().tempfile_in(dir.path()).unwrap();
    io::Write::write_all(&mut tmp, b"new").unwrap();

    publish(tmp, &dest).unwrap();

    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    assert_eq!(names(&dir), ["dest"]);
}

/// Only an answer that says the flag is unavailable falls back to the hard link.
/// `EPERM` is a real refusal (a sticky directory, a security module): the link
/// is allowed where the rename was not, and the delete that follows it is
/// refused again, so the fallback would leave a backup and fail.
#[cfg(target_os = "linux")]
#[skuld::test]
fn only_renameat2_answers_that_mean_it_is_unavailable_fall_back_to_the_link() {
    use super::unix_impl::renameat2_unavailable;

    for errno in [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP] {
        assert!(renameat2_unavailable(errno), "errno {errno}");
    }
    for errno in [
        libc::EPERM,
        libc::EEXIST,
        libc::ENOENT,
        libc::EACCES,
        libc::EXDEV,
        libc::EROFS,
    ] {
        assert!(!renameat2_unavailable(errno), "errno {errno}");
    }
}

#[cfg(windows)]
mod windows_fallback {
    use std::cell::Cell;

    use super::super::windows_impl::{
        posix_rename_unsupported, publish_with, rename_replace_legacy, without_temporary,
    };
    use super::*;

    fn tmp_with(dir: &tempfile::TempDir, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::Builder::new().tempfile_in(dir.path()).unwrap();
        io::Write::write_all(&mut tmp, bytes).unwrap();
        tmp
    }

    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;

    fn os(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    /// `ERROR_INVALID_PARAMETER` (87: measured on a 9P volume), `ERROR_NOT_SUPPORTED`
    /// (50) and `ERROR_INVALID_FUNCTION` (1) are what a volume that lacks POSIX
    /// rename answers; the same three `std` treats as "unsupported" for POSIX delete.
    #[skuld::test]
    fn only_the_unsupported_answers_select_the_legacy_replace() {
        for code in [87, 50, 1] {
            assert!(posix_rename_unsupported(&os(code)), "code {code}");
        }
        for code in [
            5,   // ERROR_ACCESS_DENIED
            2,   // ERROR_FILE_NOT_FOUND
            3,   // ERROR_PATH_NOT_FOUND
            32,  // ERROR_SHARING_VIOLATION
            80,  // ERROR_FILE_EXISTS
            112, // ERROR_DISK_FULL
            120, // ERROR_CALL_NOT_IMPLEMENTED
            183, // ERROR_ALREADY_EXISTS
        ] {
            assert!(!posix_rename_unsupported(&os(code)), "code {code}");
        }
        assert!(!posix_rename_unsupported(&io::Error::other("no os code")));
    }

    /// `HIDDEN` 0x2, `ARCHIVE` 0x20, `TEMPORARY` 0x100, `NORMAL` 0x80 (valid
    /// only alone: the call ignores a write of 0, so an empty set is `NORMAL`).
    #[skuld::test]
    fn without_temporary_clears_that_bit_and_keeps_the_others() {
        assert_eq!(without_temporary(0x100 | 0x2 | 0x20), 0x2 | 0x20);
        assert_eq!(without_temporary(0x2 | 0x20), 0x2 | 0x20);
        assert_eq!(without_temporary(0x100 | 0x20), 0x20);
    }

    #[skuld::test]
    fn without_temporary_never_yields_an_empty_set() {
        assert_eq!(without_temporary(0x100), 0x80);
        assert_eq!(without_temporary(0), 0x80);
    }

    #[skuld::test]
    fn an_unsupported_posix_rename_replaces_with_the_legacy_move() {
        let dir = dir();
        let dest = put(&dir, "dest", b"old");
        let legacy_calls = Cell::new(0);

        publish_with(
            tmp_with(&dir, b"new"),
            &dest,
            |_, _| Err(os(87)),
            |from, to| {
                legacy_calls.set(legacy_calls.get() + 1);
                std::fs::rename(from, to)
            },
        )
        .unwrap();

        assert_eq!(legacy_calls.get(), 1);
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert_eq!(names(&dir), ["dest"]);
    }

    #[skuld::test]
    fn the_legacy_move_does_not_leave_the_file_marked_temporary() {
        use std::os::windows::fs::MetadataExt;

        let dir = dir();
        let dest = put(&dir, "dest", b"old");

        publish_with(tmp_with(&dir, b"new"), &dest, |_, _| Err(os(87)), rename_replace_legacy).unwrap();

        let attributes = std::fs::metadata(&dest).unwrap().file_attributes();
        assert_eq!(attributes & FILE_ATTRIBUTE_TEMPORARY, 0, "attributes {attributes:#x}");
    }

    #[skuld::test]
    fn the_legacy_move_replaces_an_existing_file() {
        let dir = dir();
        let from = put(&dir, "from", b"new");
        let to = put(&dir, "to", b"old");

        rename_replace_legacy(&from, &to).unwrap();

        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        assert_eq!(names(&dir), ["to"]);
    }

    #[skuld::test]
    fn the_legacy_move_runs_only_after_an_unsupported_answer() {
        let dir = dir();
        let dest = put(&dir, "dest", b"old");

        publish_with(
            tmp_with(&dir, b"new"),
            &dest,
            |from, to| std::fs::rename(from, to),
            |_, _| panic!("the legacy move ran although the POSIX rename succeeded"),
        )
        .unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[skuld::test]
    fn any_other_posix_error_is_returned_without_the_legacy_move_and_leaves_no_temp() {
        let dir = dir();
        let dest = put(&dir, "dest", b"old");

        let err = publish_with(
            tmp_with(&dir, b"new"),
            &dest,
            |_, _| Err(os(5)),
            |_, _| panic!("the legacy move ran on ERROR_ACCESS_DENIED"),
        )
        .unwrap_err();

        assert_eq!(err.raw_os_error(), Some(5), "{err:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(names(&dir), ["dest"]);
    }

    #[skuld::test]
    fn a_failed_legacy_move_is_returned_and_leaves_no_temp() {
        let dir = dir();
        let dest = put(&dir, "dest", b"old");

        let err = publish_with(tmp_with(&dir, b"new"), &dest, |_, _| Err(os(87)), |_, _| Err(os(5))).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(5), "{err:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(names(&dir), ["dest"]);
    }
}

#[cfg(windows)]
mod windows_rename_info {
    use super::super::windows_impl::rename_info;

    #[skuld::test]
    fn the_rename_name_is_nul_terminated_inside_the_buffer_for_every_length() {
        let header = std::mem::offset_of!(windows::Win32::Storage::FileSystem::FILE_RENAME_INFO, FileName);
        // Every residue of the name length against the buffer's 8-byte units.
        for len in 0..=8 {
            let name = vec![u16::from(b'a'); len];
            let (buf, size) = rename_info(&name);
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
            let end = header + len * 2;

            assert_eq!(
                size as usize,
                end + 2,
                "len {len}: size covers the name and its terminator"
            );
            assert!(bytes.len() >= size as usize, "len {len}: buffer holds `size` bytes");
            assert_eq!(&bytes[end..end + 2], &[0, 0], "len {len}: a NUL follows the name");
            let named: Vec<u16> = bytes[header..end]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            assert_eq!(named, name, "len {len}: the name is copied after the header");

            // SAFETY: `buf` is 8-aligned and holds a `FILE_RENAME_INFO` header.
            let info = unsafe {
                &*buf
                    .as_ptr()
                    .cast::<windows::Win32::Storage::FileSystem::FILE_RENAME_INFO>()
            };
            // REPLACE_IF_EXISTS | POSIX_SEMANTICS, from the `FILE_RENAME_FLAG_*` values.
            assert_eq!(
                unsafe { info.Anonymous.Flags },
                0x3,
                "len {len}: replace with POSIX semantics"
            );
            assert_eq!(
                info.FileNameLength as usize,
                len * 2,
                "len {len}: the length excludes the NUL"
            );
        }
    }
}

#[cfg(windows)]
mod windows_long_paths {
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::super::windows_impl::{rename_replace_legacy, verbatim};
    use super::*;
    use crate::versioned_file::fixtures::long_dir;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn verbatim_of(s: &str) -> Vec<u16> {
        verbatim(&PathBuf::from(s)).unwrap()
    }

    #[skuld::test]
    fn a_drive_path_gets_the_verbatim_prefix_with_dots_and_slashes_resolved() {
        assert_eq!(verbatim_of("C:/a/../b/./c"), wide(r"\\?\C:\b\c"));
    }

    #[skuld::test]
    fn a_unc_path_gets_the_verbatim_unc_prefix() {
        assert_eq!(verbatim_of(r"\\srv\share\x\..\y"), wide(r"\\?\UNC\srv\share\y"));
    }

    #[skuld::test]
    fn a_verbatim_path_is_passed_through_untouched() {
        assert_eq!(verbatim_of(r"\\?\C:\a\..\b"), wide(r"\\?\C:\a\..\b"));
        assert_eq!(verbatim_of(r"\\?\UNC\srv\share\y"), wide(r"\\?\UNC\srv\share\y"));
    }

    #[skuld::test]
    fn a_relative_path_is_made_absolute_first() {
        let cwd = std::env::current_dir().unwrap();
        let mut expected = wide(r"\\?\");
        expected.extend(cwd.join("rel").as_os_str().encode_wide());
        assert_eq!(verbatim_of("rel"), expected);
    }

    #[skuld::test]
    fn a_path_with_a_nul_is_invalid_input() {
        let err = verbatim(&PathBuf::from("C:\\a\0b")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err:?}");
    }

    #[skuld::test]
    fn rename_noreplace_works_in_a_directory_of_260_characters_or_more() {
        let root = dir();
        let long = long_dir(root.path());
        std::fs::write(long.join("a"), b"bytes").unwrap();

        rename_noreplace(&long.join("a"), &long.join("b")).unwrap();
        let err = rename_noreplace(&long.join("a"), &long.join("b")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err:?}");
        assert_eq!(std::fs::read(long.join("b")).unwrap(), b"bytes");
    }

    #[skuld::test]
    fn rename_noreplace_never_replaces_in_a_directory_of_260_characters_or_more() {
        let root = dir();
        let long = long_dir(root.path());
        std::fs::write(long.join("a"), b"from").unwrap();
        std::fs::write(long.join("b"), b"to").unwrap();

        let err = rename_noreplace(&long.join("a"), &long.join("b")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err:?}");
    }

    #[skuld::test]
    fn the_legacy_move_works_in_a_directory_of_260_characters_or_more() {
        let root = dir();
        let long = long_dir(root.path());
        std::fs::write(long.join("from"), b"new").unwrap();
        std::fs::write(long.join("to"), b"old").unwrap();

        rename_replace_legacy(&long.join("from"), &long.join("to")).unwrap();

        assert_eq!(std::fs::read(long.join("to")).unwrap(), b"new");
    }

    #[skuld::test]
    fn publish_works_in_a_directory_of_260_characters_or_more() {
        let root = dir();
        let long = long_dir(root.path());
        let dest = long.join("dest");
        std::fs::write(&dest, b"old").unwrap();
        let mut tmp = tempfile::Builder::new().tempfile_in(&long).unwrap();
        io::Write::write_all(&mut tmp, b"new").unwrap();

        publish(tmp, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }
}

// A failed read names its NTSTATUS ------------------------------------------------------------------------------------

#[cfg(windows)]
mod windows_read_status {
    use std::ffi::OsString;
    use std::fs::File;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, LockFileEx, SetFileInformationByHandle, DELETE, FILE_DISPOSITION_INFO,
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows::Win32::System::IO::OVERLAPPED;

    use super::*;
    use crate::retry::is_file_contention;

    /// The Win32 code of the call that failed, behind the status wrapper.
    fn original_code(err: &io::Error) -> Option<i32> {
        let original = err.get_ref()?.source()?.downcast_ref::<io::Error>()?;
        original.raw_os_error()
    }

    fn held_without_sharing(path: &Path) -> File {
        std::fs::OpenOptions::new().read(true).share_mode(0).open(path).unwrap()
    }

    #[skuld::test]
    fn read_of_a_missing_file_names_the_ntstatus_of_the_open() {
        let dir = dir();
        let err = read(&dir.path().join("absent")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err:?}");
        // STATUS_OBJECT_NAME_NOT_FOUND
        assert!(err.to_string().contains("NTSTATUS 0xC0000034"), "{err}");
    }

    #[skuld::test]
    fn read_of_a_file_held_without_sharing_names_the_ntstatus_of_the_open() {
        let dir = dir();
        let path = put(&dir, "held", b"bytes");
        let _held = held_without_sharing(&path);

        let err = read(&path).unwrap_err();

        assert_eq!(err.kind(), std::fs::read(&path).unwrap_err().kind(), "{err:?}");
        // STATUS_SHARING_VIOLATION
        assert!(err.to_string().contains("NTSTATUS 0xC0000043"), "{err}");
    }

    /// The outer error carries no OS code of its own: the code is the source's.
    /// Every reader of a code sees through the wrapper (`raw_os_error` of
    /// `error_chain`), `is_file_contention` among them.
    #[skuld::test]
    fn the_os_code_of_a_status_error_is_in_its_source_and_readers_see_through_the_wrapper() {
        let dir = dir();
        let path = put(&dir, "held", b"bytes");
        let _held = held_without_sharing(&path);

        let err = read(&path).unwrap_err();

        assert_eq!(err.raw_os_error(), None, "{err:?}");
        assert_eq!(original_code(&err), Some(32), "ERROR_SHARING_VIOLATION: {err:?}");
        assert_eq!(crate::error_chain::raw_os_error(&err), Some(32), "{err:?}");
        assert!(is_file_contention(&err), "{err:?}");
    }

    /// A file marked for deletion while a handle to it is open stays at its
    /// name until that handle closes, and `CreateFileW` answers `Access is
    /// denied` for it: the case the Win32 code alone cannot tell from a real
    /// denial. The plain delete calls remove the name at once on current
    /// Windows, so the mark is set through the handle.
    #[skuld::test]
    fn read_of_a_delete_pending_file_names_its_status() {
        let dir = dir();
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

        let err = read(&path).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err:?}");
        // STATUS_DELETE_PENDING
        assert!(err.to_string().contains("NTSTATUS 0xC0000056"), "{err}");
        assert_eq!(original_code(&err), Some(5), "ERROR_ACCESS_DENIED: {err:?}");
        assert!(is_file_contention(&err), "{err:?}");
    }

    /// The open succeeds and the read fails: the status is the read's, not a
    /// leftover of the missing-file open that primes the thread here.
    #[skuld::test]
    fn a_read_that_fails_after_a_good_open_names_the_status_of_the_read() {
        let dir = dir();
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
        let _ = read(&dir.path().join("absent"));

        let err = read(&path).unwrap_err();

        // STATUS_FILE_LOCK_CONFLICT
        assert!(err.to_string().contains("NTSTATUS 0xC0000054"), "{err}");
        assert_eq!(original_code(&err), Some(33), "ERROR_LOCK_VIOLATION: {err:?}");
    }

    #[skuld::test]
    fn read_of_a_file_returns_its_bytes() {
        let dir = dir();
        let path = put(&dir, "f", b"bytes");
        assert_eq!(read(&path).unwrap(), b"bytes");
    }

    #[skuld::test]
    fn the_source_of_a_status_error_is_the_original_io_error_with_its_code() {
        let dir = dir();
        let err = read(&dir.path().join("absent")).unwrap_err();

        assert_eq!(original_code(&err), Some(2), "ERROR_FILE_NOT_FOUND: {err:?}");
    }

    /// The test harness panics with `{:?}`, so that is what the CI log of a hit shows.
    #[skuld::test]
    fn debug_shows_the_status_in_hex() {
        let dir = dir();
        let err = read(&dir.path().join("absent")).unwrap_err();

        assert!(format!("{err:?}").contains("0xC0000034"), "{err:?}");
    }

    /// `std` refuses a NUL path before any system call, and `CreateFileW` fails
    /// an empty one with a Win32 code and no status. Neither sets a status, so
    /// the thread's last one is an earlier call's: the primed open leaves
    /// 0xC0000034 there, and it must not be attached.
    #[skuld::test]
    fn a_path_that_fails_without_a_status_is_returned_unchanged() {
        let dir = dir();
        let nul = PathBuf::from(OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]));
        for path in [nul, PathBuf::new()] {
            let _ = read(&dir.path().join("absent"));
            let err = read(&path).unwrap_err();
            let expected = std::fs::read(&path).unwrap_err();

            assert_eq!(err.kind(), expected.kind(), "{path:?}: {err:?}");
            assert_eq!(err.raw_os_error(), expected.raw_os_error(), "{path:?}: {err:?}");
            assert_eq!(err.to_string(), expected.to_string(), "{path:?}");
            assert!(!err.to_string().contains("NTSTATUS"), "{path:?}: {err}");
        }
    }
}
