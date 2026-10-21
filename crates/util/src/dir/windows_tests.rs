use super::*;
use crate::dir::testing::{own, plant_link, user_dir, SystemScratch};
use crate::dir::Dir;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

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

// Links ---------------------------------------------------------------------------------------------------------------
//
// A test cannot make a link or folder of another principal without privilege, so each case is stated for
// any runner: the fixtures give what they make to an unprivileged owner whoever runs the test.

fn file_id(path: &Path) -> (u64, u64) {
    let file = std::fs::OpenOptions::new()
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .read(true)
        .open(path)
        .unwrap();
    super::file_id(&file).unwrap()
}

/// The system's own links: `C:\Documents and Settings` is a junction and `C:\Users\All Users` a directory symlink,
/// both owned by SYSTEM in a folder SYSTEM owns.
const SYSTEM_JUNCTION: (&str, &str) = (r"C:\Documents and Settings\Public", r"C:\Users\Public");
const SYSTEM_SYMLINK: (&str, &str) = (r"C:\Users\All Users", r"C:\ProgramData");

#[skuld::test]
fn a_junction_the_system_owns_in_a_folder_the_system_owns_is_followed() {
    let (through, real) = SYSTEM_JUNCTION;

    let dir = Dir::open(Path::new(through), false, None).unwrap_or_else(|err| {
        panic!("{through}: {err:?} (a Windows without the compatibility junction `Documents and Settings` cannot run this test)")
    });

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(Path::new(real)));
}

#[skuld::test]
fn a_directory_symlink_the_system_owns_in_a_folder_the_system_owns_is_followed() {
    let (through, real) = SYSTEM_SYMLINK;

    let dir = Dir::open(Path::new(through), false, None).unwrap_or_else(|err| {
        panic!("{through}: {err:?} (a Windows without the compatibility link `All Users` cannot run this test)")
    });

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(Path::new(real)));
}

/// Removes the folder when dropped.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[skuld::test]
fn a_folder_the_caller_may_pass_through_but_not_read_the_acl_of_is_walked_through() {
    // `%SystemRoot%\Temp` lets an ordinary user traverse it and add to it, but not read its permissions, so the
    // by-path walk this replaced got through it (a `HOLE_LOG_DIR` there is a real setting of the GUI). A walk that
    // asks every folder for `READ_CONTROL` fails there as an ordinary user and passes as an administrator.
    let temp = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot names the Windows folder")).join("Temp");
    let made = temp.join(format!("hole-dir-test-acl-{}", std::process::id()));
    let _remove = RemoveOnDrop(made.clone());

    Dir::open(&made.join("below"), true, None).unwrap();

    assert!(made.join("below").is_dir());
}

#[skuld::test]
fn a_users_junction_to_a_folder_the_same_user_owns_is_followed() {
    // A profile folder moved to another disk and linked back.
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant_link(&real, &tmp.path().join("link"));

    let dir = Dir::open(&tmp.path().join("link"), false, None).unwrap();

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(&real));
}

#[skuld::test]
fn a_users_directory_symlink_to_a_folder_the_same_user_owns_is_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    let link = tmp.path().join("link");
    std::os::windows::fs::symlink_dir(&real, &link)
        .expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
    own(&link);

    let dir = Dir::open(&link, false, None).unwrap();

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(&real));
}

#[skuld::test]
fn a_users_relative_symlink_resolves_from_the_folder_it_is_in() {
    let tmp = tempfile::tempdir().unwrap();
    user_dir(&tmp.path().join("a").join("real"));
    user_dir(&tmp.path().join("b"));
    let link = tmp.path().join("b").join("link");
    std::os::windows::fs::symlink_dir(r"..\a\real", &link)
        .expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
    own(&link);

    Dir::open(&link.join("made"), true, None).unwrap();

    assert!(tmp.path().join("a").join("real").join("made").is_dir());
}

#[skuld::test]
fn a_relative_symlink_that_ends_on_a_parent_opens_that_folder_for_use() {
    let tmp = tempfile::tempdir().unwrap();
    user_dir(&tmp.path().join("a").join("b"));
    let link = tmp.path().join("a").join("b").join("up");
    std::os::windows::fs::symlink_dir(r"..", &link)
        .expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
    own(&link);

    let dir = Dir::open(&link, false, None).unwrap();

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(&tmp.path().join("a")));
    dir.write_atomic("state.json".as_ref(), b"x", None, |_| Ok(())).unwrap();
}

#[skuld::test]
fn a_relative_symlink_that_ends_on_a_parent_gives_the_rights_asked_for_the_final_directory() {
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let tmp = tempfile::tempdir().unwrap();
    user_dir(&tmp.path().join("a").join("b"));
    let link = tmp.path().join("a").join("b").join("up");
    std::os::windows::fs::symlink_dir(r"..", &link)
        .expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
    own(&link);

    let dir = Dir::open_for_acl(&link, false).unwrap();

    // A directory flush needs the right to add files; reading the ACL needs `READ_CONTROL`.
    dir.sync().unwrap();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle is open with `READ_CONTROL`; the out-pointer is a live local. The descriptor is
    // LocalAlloc'd and leaked: it is a test.
    let read = unsafe {
        GetSecurityInfo(
            HANDLE(dir.file().as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    assert_eq!(read.0, 0);
}

#[skuld::test]
fn a_users_junction_to_a_folder_the_system_owns_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    plant_link(scratch.root(), &tmp.path().join("link"));

    assert_eq!(
        refusal(Dir::open(&tmp.path().join("link"), false, None)),
        Refusal::Symlink
    );
}

#[skuld::test]
fn nothing_is_made_in_a_folder_the_system_owns_through_a_users_junction() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    plant_link(scratch.root(), &tmp.path().join("link"));
    let through = tmp.path().join("link").join(scratch.name()).join("state");

    assert_eq!(refusal(Dir::open(&through, true, None)), Refusal::Symlink);

    assert!(
        !scratch.path().exists(),
        "a folder was made in the system's scratch folder"
    );
}

#[skuld::test]
fn a_folder_missing_below_a_users_junction_is_made_in_the_users_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant_link(&real, &tmp.path().join("link"));

    Dir::open(&tmp.path().join("link").join("a").join("b"), true, None).unwrap();

    assert!(real.join("a").join("b").is_dir());
}

#[skuld::test]
fn a_users_symlink_to_a_missing_folder_makes_the_folder_in_the_users_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    user_dir(&base);
    let target = base.join("not-yet").join("deeper");
    let link = tmp.path().join("link");
    std::os::windows::fs::symlink_dir(&target, &link)
        .expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
    own(&link);

    Dir::open(&link, true, None).unwrap();

    assert!(target.is_dir());
}

#[skuld::test]
fn a_link_met_again_after_its_own_resolution_is_not_a_loop() {
    // `link` leads to `real`, where `again` leads back through `link`.
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real.join("sub"));
    plant_link(&real, &tmp.path().join("link"));
    plant_link(&tmp.path().join("link").join("sub"), &real.join("again"));

    let dir = Dir::open(&tmp.path().join("link").join("again"), false, None).unwrap();

    assert_eq!(super::file_id(dir.file()).unwrap(), file_id(&real.join("sub")));
}

#[skuld::test]
fn a_loop_of_junctions_is_refused_not_followed_forever() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    user_dir(&b);
    plant_link(&b, &a);
    std::fs::remove_dir(&b).unwrap();
    plant_link(&a, &b);

    assert_eq!(refusal(Dir::open(&a, false, None)), Refusal::Symlink);
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

// Replace falls back to the plain rename ------------------------------------------------------------------------------

fn os(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// `ERROR_INVALID_PARAMETER` (87: measured on a 9P volume), `ERROR_NOT_SUPPORTED` (50) and `ERROR_INVALID_FUNCTION`
/// (1) are what a volume that lacks POSIX rename answers; the same three `std` treats as "unsupported" for POSIX
/// delete.
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
fn the_legacy_replace_runs_only_after_an_unsupported_answer() {
    let legacy_calls = std::cell::Cell::new(0);
    let legacy = || {
        legacy_calls.set(legacy_calls.get() + 1);
        Ok(())
    };

    posix_or_legacy(|| Ok(()), legacy).unwrap();
    assert_eq!(legacy_calls.get(), 0, "a rename that worked needs no fallback");

    let refused = posix_or_legacy(|| Err(os(5)), legacy).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(5));
    assert_eq!(legacy_calls.get(), 0, "any other error is returned as it is");

    posix_or_legacy(|| Err(os(87)), legacy).unwrap();
    assert_eq!(legacy_calls.get(), 1);
}

#[skuld::test]
fn a_failed_legacy_replace_is_returned() {
    let err = posix_or_legacy(|| Err(os(87)), || Err(os(32))).unwrap_err();

    assert_eq!(err.raw_os_error(), Some(32));
}

#[skuld::test]
fn the_legacy_replace_replaces_an_existing_file_and_keeps_the_destination_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("dest"), b"old").unwrap();
    let temp = open_file(&dir.file, "src".as_ref(), OpenFile::CreateNew { mode: 0o600 }).unwrap();
    std::io::Write::write_all(&mut &temp, b"new").unwrap();
    drop(temp);
    let source = open_for_delete(&dir.file, "src".as_ref()).unwrap();

    set_name(&dir.file, &source, &units("dest"), FileRenameInformation, REPLACE).unwrap();

    assert_eq!(std::fs::read(tmp.path().join("dest")).unwrap(), b"new");
    assert!(!tmp.path().join("src").exists());
}
