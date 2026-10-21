use super::*;
use std::ffi::OsString;
use std::path::PathBuf;

// Fixtures ------------------------------------------------------------------------------------------------------------

/// A symlink to the directory `target` at `link`, of the kind an unprivileged user can plant. Run as
/// root, the link is given away so that it is no longer root's own.
fn plant_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::lchown(link, Some(65534), Some(65534)).unwrap();
        }
    }
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link).unwrap();
}

fn names(dir: &Path) -> Vec<OsString> {
    let mut found: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    found.sort();
    found
}

fn refusal(result: io::Result<Dir>) -> Refusal {
    let err = result.err().expect("the path must be refused");
    *Refusal::from_error(&err).unwrap_or_else(|| panic!("not a typed refusal: {err:?}"))
}

fn kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
    result.err().map(|e| e.kind())
}

fn name(s: &str) -> OsString {
    OsString::from(s)
}

// open ================================================================================================================

#[skuld::test]
fn an_existing_directory_opens() {
    let tmp = tempfile::tempdir().unwrap();
    Dir::open(tmp.path(), false, None).unwrap();
}

#[skuld::test]
fn a_missing_directory_is_not_created_unless_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("a").join("b");

    let err = Dir::open(&missing, false, None).err().expect("nothing to open");

    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(names(tmp.path()).is_empty());
}

#[skuld::test]
fn missing_components_are_created_when_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let deep = tmp.path().join("a").join("b").join("c");

    Dir::open(&deep, true, None).unwrap();

    assert!(deep.is_dir());
}

#[skuld::test]
fn a_directory_that_exists_is_opened_not_recreated_when_asked_to_create() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("kept"), b"x").unwrap();

    Dir::open(tmp.path(), true, None).unwrap();

    assert_eq!(std::fs::read(tmp.path().join("kept")).unwrap(), b"x");
}

#[skuld::test]
fn a_symlink_as_the_last_component_is_refused_and_nothing_is_made_through_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = tmp.path().join("state");
    plant_symlink(&outside, &link);

    for create in [false, true] {
        assert_eq!(
            refusal(Dir::open(&link, create, None)),
            Refusal::Symlink,
            "create {create}"
        );
    }
    assert!(names(&outside).is_empty());
}

#[skuld::test]
fn a_symlink_as_a_parent_component_is_refused_and_nothing_is_made_through_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = tmp.path().join("hole");
    plant_symlink(&outside, &link);

    // Both the state directory and a missing directory below it.
    for path in [link.join("state"), link.join("state").join("deeper")] {
        assert_eq!(refusal(Dir::open(&path, true, None)), Refusal::Symlink, "{path:?}");
    }
    assert!(names(&outside).is_empty(), "something was created outside");
}

#[skuld::test]
fn a_symlink_to_a_missing_directory_is_refused_and_its_target_is_not_made() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("not-yet");
    let link = tmp.path().join("state");
    plant_symlink(&target, &link);

    assert_eq!(refusal(Dir::open(&link, true, None)), Refusal::Symlink);
    assert!(!target.exists());
}

#[skuld::test]
fn a_file_where_a_directory_belongs_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("file");
    std::fs::write(&file, b"").unwrap();

    for path in [file.clone(), file.join("below")] {
        assert_eq!(refusal(Dir::open(&path, true, None)), Refusal::NotDirectory, "{path:?}");
    }
}

#[skuld::test]
fn a_relative_path_is_resolved_from_the_current_directory() {
    // The test binary is one process; nothing here changes the current directory.
    let cwd = std::env::current_dir().unwrap();
    assert!(cwd.is_absolute());
    let relative = PathBuf::from(".");
    Dir::open(&relative, false, None).unwrap();
}

#[skuld::test]
fn a_symlink_below_the_root_is_not_trusted_for_being_in_the_system_temp_dir() {
    // `temp_dir()` may itself be reached through system symlinks (macOS: `/var`), so this
    // also proves those are followed; a symlink planted inside it is not.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = tmp.path().join("link");
    plant_symlink(&target, &link);

    Dir::open(tmp.path(), false, None).unwrap();
    assert_eq!(refusal(Dir::open(&link, false, None)), Refusal::Symlink);
}

// open_file / id_of / unlink ==========================================================================================

#[skuld::test]
fn open_file_creates_then_reopens_and_the_two_are_the_same_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    let created = dir
        .open_file(&name("lock"), OpenFile::CreateNew { mode: 0o600 })
        .unwrap();
    let again = dir.open_file(&name("lock"), OpenFile::Existing).unwrap();

    assert_eq!(FileId::of(&created).unwrap(), FileId::of(&again).unwrap());
    assert_eq!(dir.id_of(&name("lock")).unwrap(), Some(FileId::of(&created).unwrap()));
    assert!(tmp.path().join("lock").is_file());
}

#[skuld::test]
fn creating_over_a_taken_name_fails_with_already_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("taken"), b"theirs").unwrap();

    let err = dir
        .open_file(&name("taken"), OpenFile::CreateNew { mode: 0o600 })
        .err()
        .unwrap();

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(tmp.path().join("taken")).unwrap(), b"theirs");
}

#[skuld::test]
fn a_missing_name_is_not_found_and_has_no_id() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    let err = dir.open_file(&name("absent"), OpenFile::Existing).err().unwrap();

    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert_eq!(dir.id_of(&name("absent")).unwrap(), None);
    assert_eq!(
        dir.unlink(&name("absent")).err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
}

#[skuld::test]
fn unlink_removes_the_name_and_not_what_a_symlink_points_at() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    let file_target = tmp.path().join("target-dir");
    std::fs::create_dir(&file_target).unwrap();
    plant_symlink(&file_target, &tmp.path().join("link"));

    dir.unlink(&name("link")).unwrap();

    assert!(std::fs::symlink_metadata(tmp.path().join("link")).is_err());
    assert!(file_target.is_dir());
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[skuld::test]
fn a_name_that_is_not_one_file_name_is_refused_by_every_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    for bad in ["", ".", "..", "a/b", "a\\b", "/abs"] {
        let bad = name(bad);
        // `a\b` is one name on unix; the point is that no operation resolves a path.
        if cfg!(unix) && bad == "a\\b" {
            continue;
        }
        assert_eq!(
            kind(dir.open_file(&bad, OpenFile::Existing)),
            Some(io::ErrorKind::InvalidInput),
            "{bad:?}"
        );
        assert_eq!(kind(dir.id_of(&bad)), Some(io::ErrorKind::InvalidInput), "{bad:?}");
        assert_eq!(kind(dir.unlink(&bad)), Some(io::ErrorKind::InvalidInput), "{bad:?}");
        assert_eq!(
            kind(dir.write_atomic(&bad, b"", None, |_| Ok(())).map(|_| ())),
            Some(io::ErrorKind::InvalidInput),
            "{bad:?}"
        );
    }
}

// write_atomic ========================================================================================================

#[skuld::test]
fn write_atomic_creates_and_then_replaces_the_file_and_leaves_no_temp() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    dir.write_atomic(&name("state.json"), b"first", None, |_| Ok(()))
        .unwrap();
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"first");
    dir.write_atomic(&name("state.json"), b"second", None, |_| Ok(()))
        .unwrap();

    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"second");
    assert_eq!(names(tmp.path()), vec![name("state.json")]);
}

#[skuld::test]
fn write_atomic_runs_protect_on_the_temp_before_the_rename_and_a_failure_leaves_the_old_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic(&name("state.json"), b"old", None, |_| Ok(())).unwrap();
    let mut seen_name = None;

    let err = dir
        .write_atomic(&name("state.json"), b"new", None, |temp| {
            seen_name = Some(FileId::of(temp).unwrap());
            assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"old");
            Err(io::Error::other("protect failed"))
        })
        .expect_err("a failing protect fails the write");

    assert_eq!(err.to_string(), "protect failed");
    assert!(seen_name.is_some());
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"old");
    assert_eq!(
        names(tmp.path()),
        vec![name("state.json")],
        "the temp file was left behind"
    );
}

#[skuld::test]
fn write_atomic_does_not_follow_a_symlink_at_the_final_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim, tmp.path().join("state.json")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&victim, tmp.path().join("state.json")).unwrap();

    dir.write_atomic(&name("state.json"), b"new", None, |_| Ok(())).unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"keep", "wrote through the symlink");
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"new");
    assert!(!std::fs::symlink_metadata(tmp.path().join("state.json"))
        .unwrap()
        .is_symlink());
}

#[skuld::test]
fn write_atomic_replaces_a_hard_link_by_name_and_leaves_the_other_name_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::fs::hard_link(&victim, tmp.path().join("state.json")).unwrap();

    dir.write_atomic(&name("state.json"), b"new", None, |_| Ok(())).unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"keep", "wrote through the hard link");
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"new");
}

// write_state_file ====================================================================================================

#[skuld::test]
fn write_state_file_creates_the_directory_and_writes_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("hole").join("state");

    write_state_file(&state, &name("bridge-x.json"), b"{}", None).unwrap();

    assert_eq!(std::fs::read(state.join("bridge-x.json")).unwrap(), b"{}");
    assert_eq!(names(&state), vec![name("bridge-x.json")]);
}

#[skuld::test]
fn write_state_file_refuses_a_symlinked_state_directory_and_writes_nothing_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let state = tmp.path().join("state");
    plant_symlink(&outside, &state);

    let err = write_state_file(&state, &name("bridge-x.json"), b"{}", None).unwrap_err();

    assert_eq!(Refusal::from_error(&err), Some(&Refusal::Symlink));
    assert!(names(&outside).is_empty());
}
