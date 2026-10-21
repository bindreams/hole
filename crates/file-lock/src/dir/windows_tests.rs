// `mklink /J` makes a junction, the reparse point an unprivileged user can create; `std` has no call for it.
#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use super::*;
use crate::dir::Dir;
use std::path::PathBuf;

fn junction(target: &Path, link: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J: {status:?}");
}

fn refusal(result: io::Result<Dir>) -> Refusal {
    let err = result.err().expect("the path must be refused");
    *Refusal::from_error(&err).unwrap_or_else(|| panic!("not a typed refusal: {err:?}"))
}

fn is_empty(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

// split ===============================================================================================================

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[skuld::test]
fn a_drive_path_splits_into_the_nt_root_and_its_names() {
    let (root, names) = split(Path::new(r"C:\Users\x\state")).unwrap();

    assert_eq!(root, units(r"\??\C:\"));
    assert_eq!(names, ["Users", "x", "state"].map(OsString::from));
}

#[skuld::test]
fn a_verbatim_drive_path_splits_like_the_plain_one() {
    let (root, names) = split(Path::new(r"\\?\C:\a\b")).unwrap();

    assert_eq!(root, units(r"\??\C:\"));
    assert_eq!(names, ["a", "b"].map(OsString::from));
}

#[skuld::test]
fn a_unc_path_splits_into_the_nt_share_root_and_its_names() {
    let (root, names) = split(Path::new(r"\\server\share\a")).unwrap();

    assert_eq!(root, units(r"\??\UNC\server\share\"));
    assert_eq!(names, ["a"].map(OsString::from));
}

#[skuld::test]
fn a_relative_path_is_made_absolute_first() {
    let (root, names) = split(Path::new("state")).unwrap();

    let cwd = std::env::current_dir().unwrap();
    let expected: Vec<OsString> = cwd
        .components()
        .skip(2)
        .map(|c| c.as_os_str().to_owned())
        .chain([OsString::from("state")])
        .collect();
    assert_eq!(
        String::from_utf16(&root)
            .unwrap()
            .to_ascii_uppercase()
            .chars()
            .take(4)
            .collect::<String>(),
        r"\??\"
    );
    assert_eq!(names.into_iter().collect::<Vec<_>>(), expected);
}

#[skuld::test]
fn a_verbatim_path_with_a_parent_component_is_refused() {
    let err = split(Path::new(r"\\?\C:\a\..\b")).err().unwrap();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

// Reparse points ------------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_junction_as_the_last_component_is_refused_and_nothing_is_made_through_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = tmp.path().join("state");
    junction(&outside, &link);

    for create in [false, true] {
        assert_eq!(
            refusal(Dir::open(&link, create, None)),
            Refusal::Symlink,
            "create {create}"
        );
    }
    assert!(is_empty(&outside));
}

#[skuld::test]
fn a_junction_as_a_parent_component_is_refused_and_nothing_is_made_through_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = tmp.path().join("hole");
    junction(&outside, &link);

    for path in [link.join("state"), link.join("state").join("deeper")] {
        assert_eq!(refusal(Dir::open(&path, true, None)), Refusal::Symlink, "{path:?}");
    }
    assert!(is_empty(&outside), "something was created outside");
}

// Name and handle rules -----------------------------------------------------------------------------------------------

#[skuld::test]
fn a_name_that_would_open_an_alternate_data_stream_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    let err = dir
        .open_file("lock:stream".as_ref(), OpenFile::CreateNew { mode: 0o600 })
        .err()
        .unwrap();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(is_empty(tmp.path()));
}

#[skuld::test]
fn a_file_opened_through_the_directory_cannot_be_deleted_or_renamed_while_it_is_open() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let _held = dir
        .open_file("lock".as_ref(), OpenFile::CreateNew { mode: 0o600 })
        .unwrap();

    assert!(std::fs::remove_file(tmp.path().join("lock")).is_err());
    assert!(std::fs::rename(tmp.path().join("lock"), tmp.path().join("moved")).is_err());
}

#[skuld::test]
fn a_directory_opened_for_its_acl_can_have_its_acl_read_and_rewritten() {
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open_for_acl(tmp.path(), false).unwrap();
    let handle = HANDLE(dir.file().as_raw_handle());
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // SAFETY: the handle is open with `READ_CONTROL`; the out-pointers are live locals. The descriptor
    // is LocalAlloc'd and leaked: it is a test.
    let read = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    assert_eq!(read.0, 0, "read the DACL");
    // SAFETY: the handle is open with `WRITE_DAC` and `dacl` points into the descriptor read above.
    let write = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    assert_eq!(write.0, 0, "rewrite the DACL");
}

#[skuld::test]
fn write_atomic_replaces_a_file_a_reader_has_open() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic("state.json".as_ref(), b"old", None, |_| Ok(()))
        .unwrap();
    let reader = std::fs::File::open(tmp.path().join("state.json")).unwrap();

    dir.write_atomic("state.json".as_ref(), b"new", None, |_| Ok(()))
        .unwrap();

    drop(reader);
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"new");
}

#[skuld::test]
fn a_path_longer_than_max_path_is_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let mut deep: PathBuf = tmp.path().to_path_buf();
    for _ in 0..8 {
        deep.push("a".repeat(40));
    }

    Dir::open(&deep, true, None).unwrap();

    assert!(deep.as_os_str().len() > 260);
}
