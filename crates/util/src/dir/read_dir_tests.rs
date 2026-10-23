use super::*;
use crate::dir::testing::plant_link;
use crate::dir::{Dir, OpenFile};
use std::ffi::OsString;

fn name(s: &str) -> OsString {
    OsString::from(s)
}

fn kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
    result.err().map(|e| e.kind())
}

/// A symlink to the file `target` at `link`, of the kind an unprivileged user can plant.
fn plant_file_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

#[skuld::test]
fn read_returns_the_bytes_of_the_file_and_not_found_for_a_missing_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = ReadDir::open(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("state.json"), b"{\"a\":1}").unwrap();

    assert_eq!(dir.read(&name("state.json")).unwrap(), b"{\"a\":1}");
    assert_eq!(kind(dir.read(&name("absent"))), Some(io::ErrorKind::NotFound));
}

#[skuld::test]
fn a_missing_directory_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();

    let err = ReadDir::open(&tmp.path().join("absent"))
        .err()
        .expect("nothing to open");

    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[skuld::test]
fn nothing_is_created_by_opening() {
    let tmp = tempfile::tempdir().unwrap();

    assert!(ReadDir::open(&tmp.path().join("a").join("b")).is_err());

    assert!(!tmp.path().join("a").exists());
}

#[skuld::test]
fn a_read_view_of_a_writable_directory_reads_what_it_wrote_and_outlives_it() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic(&name("state.json"), b"one", None, |_| Ok(())).unwrap();

    let reader = dir.reader().unwrap();
    drop(dir);

    assert_eq!(reader.read(&name("state.json")).unwrap(), b"one");
}

#[skuld::test]
fn read_does_not_follow_a_symlink_at_the_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = ReadDir::open(tmp.path()).unwrap();
    let target = tmp.path().join("secret");
    std::fs::write(&target, b"theirs").unwrap();
    plant_file_symlink(&target, &tmp.path().join("link"));

    assert!(dir.read(&name("link")).is_err());
}

#[skuld::test]
fn read_refuses_a_name_with_a_separator() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = ReadDir::open(tmp.path()).unwrap();

    assert_eq!(kind(dir.read(&name("a/b"))), Some(io::ErrorKind::InvalidInput),);
}

#[cfg(unix)]
#[skuld::test]
fn read_refuses_a_fifo_at_the_name_and_does_not_block() {
    use crate::dir::Refusal;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = ReadDir::open(tmp.path()).unwrap();
    let fifo = std::ffi::CString::new(tmp.path().join("state.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let err = dir.read(&name("state.json")).unwrap_err();

    assert_eq!(Refusal::from_error(&err), Some(&Refusal::NotRegular));
}

#[skuld::test]
fn a_file_open_for_reading_does_not_block_a_replace_of_it() {
    // A reader that shares delete, as `std::fs::read` does: the store of a versioned file replaces the
    // file under it.
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic(&name("state.json"), b"one", None, |_| Ok(())).unwrap();
    let reader = dir.open_file(&name("state.json"), OpenFile::Read).unwrap();

    dir.write_atomic(&name("state.json"), b"two", None, |_| Ok(())).unwrap();

    assert_eq!(dir.reader().unwrap().read(&name("state.json")).unwrap(), b"two");
    drop(reader);
}

#[skuld::test]
fn a_walk_through_a_users_link_to_their_own_folder_is_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    crate::dir::testing::user_dir(&real);
    std::fs::write(real.join("state.json"), b"x").unwrap();
    plant_link(&real, &tmp.path().join("link"));

    let dir = ReadDir::open(&tmp.path().join("link")).unwrap();

    assert_eq!(dir.read(&name("state.json")).unwrap(), b"x");
}

#[skuld::test]
fn kind_of_says_what_a_name_is_without_following_it() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = ReadDir::open(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("file"), b"x").unwrap();
    std::fs::create_dir(tmp.path().join("folder")).unwrap();
    plant_file_symlink(&tmp.path().join("file"), &tmp.path().join("link"));

    assert_eq!(dir.kind_of(&name("file")).unwrap(), Some(EntryKind::File));
    assert_eq!(dir.kind_of(&name("folder")).unwrap(), Some(EntryKind::Directory));
    assert_eq!(dir.kind_of(&name("link")).unwrap(), Some(EntryKind::Symlink));
    assert_eq!(dir.kind_of(&name("absent")).unwrap(), None);
}
