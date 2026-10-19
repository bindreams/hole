use std::io;

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

    use super::super::windows_impl::{posix_rename_unsupported, publish_with, rename_replace_legacy};
    use super::*;

    fn tmp_with(dir: &tempfile::TempDir, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::Builder::new().tempfile_in(dir.path()).unwrap();
        io::Write::write_all(&mut tmp, bytes).unwrap();
        tmp
    }

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
        }
    }
}
