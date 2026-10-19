use std::io;

use super::{lock_exclusive, publish, rename_noreplace, try_lock_exclusive, unlock};
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

#[skuld::test]
fn a_lock_excludes_a_second_handle_until_it_is_released() {
    let dir = dir();
    let path = put(&dir, "x.lock", b"");
    let first = std::fs::File::open(&path).unwrap();
    let second = std::fs::File::open(&path).unwrap();

    lock_exclusive(&first).unwrap();
    assert!(!try_lock_exclusive(&second).unwrap(), "held by the first handle");

    unlock(&first);
    assert!(try_lock_exclusive(&second).unwrap(), "free after the release");
}

/// `EPERM` is what a seccomp profile that predates `renameat2` answers with.
/// A real `EPERM` falls back to a hard link, which fails the same way.
#[cfg(target_os = "linux")]
#[skuld::test]
fn renameat2_answers_that_mean_it_is_unavailable_fall_back_to_the_link() {
    use super::unix_impl::renameat2_unavailable;

    for errno in [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP, libc::EPERM] {
        assert!(renameat2_unavailable(errno), "errno {errno}");
    }
    for errno in [libc::EEXIST, libc::ENOENT, libc::EACCES, libc::EXDEV, libc::EROFS] {
        assert!(!renameat2_unavailable(errno), "errno {errno}");
    }
}
