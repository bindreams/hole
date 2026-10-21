use super::testing::{plant_link, user_dir, SystemScratch};
use super::*;
use std::ffi::OsString;
use std::path::PathBuf;

// Fixtures ------------------------------------------------------------------------------------------------------------

/// A symlink to the file `target` at `link`, of the kind an unprivileged user can plant.
fn plant_file_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
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
fn a_link_to_a_folder_the_system_owns_as_the_last_component_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let link = tmp.path().join("state");
    plant_link(scratch.root(), &link);

    for create in [false, true] {
        assert_eq!(
            refusal(Dir::open(&link, create, None)),
            Refusal::Symlink,
            "create {create}"
        );
    }
}

#[skuld::test]
fn nothing_is_made_through_a_link_to_a_folder_the_system_owns_as_a_parent_component() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let link = tmp.path().join("hole");
    plant_link(scratch.root(), &link);
    let below = link.join(scratch.name());

    // Both the state directory and a missing directory below it.
    for path in [below.join("state"), below.join("state").join("deeper")] {
        assert_eq!(refusal(Dir::open(&path, true, None)), Refusal::Symlink, "{path:?}");
    }
    assert!(!scratch.path().exists(), "something was made in the system's folder");
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
fn the_system_temp_dir_is_reachable_but_a_link_in_it_leads_only_to_the_users_folders() {
    // `temp_dir()` may itself be reached through system links (macOS: `/var`).
    let tmp = tempfile::tempdir().unwrap();
    let mine = tmp.path().join("mine");
    user_dir(&mine);
    plant_link(&mine, &tmp.path().join("to-mine"));
    plant_link(SystemScratch::new().root(), &tmp.path().join("to-the-system"));

    Dir::open(tmp.path(), false, None).unwrap();
    Dir::open(&tmp.path().join("to-mine"), false, None).unwrap();
    assert_eq!(
        refusal(Dir::open(&tmp.path().join("to-the-system"), false, None)),
        Refusal::Symlink
    );
}

// A walk's link budget ------------------------------------------------------------------------------------------------
//
// A user plants the links, and the walk is a privileged process's. The bound on how many it follows is the one the
// OS applies to a path: Linux `MAXSYMLINKS` 40 (`include/linux/namei.h`), macOS `MAXSYMLINKS` 32 (xnu
// `bsd/sys/param.h`), Windows 63 reparse points in a path (learn.microsoft.com, "Symbolic link programming
// considerations"). The numbers here are the OS's, written again so that a wrong constant in the code fails.

#[cfg(target_os = "linux")]
const OS_LINK_LIMIT: usize = 40;
#[cfg(windows)]
const OS_LINK_LIMIT: usize = 63;
#[cfg(not(any(target_os = "linux", windows)))]
const OS_LINK_LIMIT: usize = 32;

/// `dir/l1 -> dir/l2 -> ... -> dir/l<n> -> dir/real`, every link absolute and the user's; returns `dir/l1`.
fn linear_chain(dir: &Path, n: usize) -> PathBuf {
    user_dir(&dir.join("real"));
    // Last first: a junction cannot point at a name that is not there yet.
    for k in (1..=n).rev() {
        let target = match k == n {
            true => dir.join("real"),
            false => dir.join(format!("l{}", k + 1)),
        };
        plant_link(&target, &dir.join(format!("l{k}")));
    }
    dir.join("l1")
}

/// `dir/l<k> -> dir/l<k+1>/l<k+1>` and `dir/l<n> -> dir`: each link names the next one twice, so a walk that
/// follows every mention does `2^n` steps. Returns `dir/l1`.
fn branching_chain(dir: &Path, n: usize) -> PathBuf {
    for k in (1..=n).rev() {
        let target = match k == n {
            true => dir.to_path_buf(),
            false => dir.join(format!("l{}", k + 1)).join(format!("l{}", k + 1)),
        };
        plant_link(&target, &dir.join(format!("l{k}")));
    }
    dir.join("l1")
}

#[skuld::test]
fn a_chain_of_as_many_links_as_the_os_allows_in_a_path_is_walked() {
    let tmp = tempfile::tempdir().unwrap();
    let start = linear_chain(tmp.path(), OS_LINK_LIMIT);
    // The OS agrees that the path is fine.
    assert!(std::fs::metadata(&start).unwrap().is_dir());

    let dir = Dir::open(&start, false, None).unwrap();

    assert_eq!(
        FileId::of(dir.file()).unwrap(),
        FileId::of(Dir::open(&tmp.path().join("real"), false, None).unwrap().file()).unwrap()
    );
}

#[skuld::test]
fn a_chain_of_one_more_link_than_the_os_allows_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let start = linear_chain(tmp.path(), OS_LINK_LIMIT + 1);
    // The OS refuses the path too.
    assert!(std::fs::metadata(&start).is_err());

    assert_eq!(refusal(Dir::open(&start, false, None)), Refusal::Symlink);
}

#[skuld::test]
fn links_that_each_name_the_next_twice_are_refused_and_not_walked_in_exponential_time() {
    let tmp = tempfile::tempdir().unwrap();
    let start = branching_chain(tmp.path(), 40);

    assert_eq!(refusal(Dir::open(&start, true, None)), Refusal::Symlink);
}

// Folders made below a user's link ------------------------------------------------------------------------------------
//
// The walk is bound to the owner of a link it followed and ends and creates only in that owner's folders. A folder
// a privileged process made there is the system's on disk (Windows: Administrators'), so unless it is handed over,
// the next walk through the same link meets a folder that is not the user's and refuses the process's own folders.
// Run elevated (root; an elevated Windows token) to observe the difference; as the user, a made folder is the
// user's already.

/// Who owns `path` itself, in a form that compares.
#[cfg(unix)]
fn owner_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).unwrap().uid()
}

#[cfg(windows)]
fn owner_of(path: &Path) -> Vec<u8> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .access_mode(::windows::Win32::Storage::FileSystem::READ_CONTROL.0)
        .share_mode(7)
        .custom_flags(::windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
        .unwrap();
    match platform::owner_of(&file).unwrap() {
        trail::Owner::Privileged => b"privileged".to_vec(),
        trail::Owner::User(sid) => sid,
    }
}

/// `tmp/link -> tmp/profile`, both the user's; returns the path of a folder two levels below the link.
fn two_levels_below_a_users_link(tmp: &Path) -> PathBuf {
    user_dir(&tmp.join("profile"));
    plant_link(&tmp.join("profile"), &tmp.join("link"));
    tmp.join("link").join("hole").join("state")
}

#[skuld::test]
fn every_folder_made_below_a_users_link_is_given_to_the_links_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let path = two_levels_below_a_users_link(tmp.path());

    Dir::open(&path, true, None).unwrap();

    let profile = owner_of(&tmp.path().join("profile"));
    assert_eq!(owner_of(&tmp.path().join("profile").join("hole")), profile);
    assert_eq!(
        owner_of(&tmp.path().join("profile").join("hole").join("state")),
        profile
    );
}

#[skuld::test]
fn a_second_walk_through_a_users_link_accepts_the_folders_the_first_walk_made() {
    let tmp = tempfile::tempdir().unwrap();
    let path = two_levels_below_a_users_link(tmp.path());

    Dir::open(&path, true, None).unwrap();

    Dir::open(&path, true, None).unwrap();
    Dir::open(&path, false, None).unwrap();
    // And a folder below the ones made before.
    Dir::open(&path.join("deeper"), true, None).unwrap();
    Dir::open(&path.join("deeper"), true, None).unwrap();
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
    plant_link(&file_target, &tmp.path().join("link"));

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
fn write_state_file_refuses_a_link_to_a_folder_the_system_owns_and_writes_nothing_there() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let state = tmp.path().join("state");
    plant_link(scratch.root(), &state);
    let file = format!("{}.json", scratch.path().display());

    let err = write_state_file(&state, OsStr::new(&file), b"{}", None).unwrap_err();

    assert_eq!(Refusal::from_error(&err), Some(&Refusal::Symlink));
    assert!(
        !Path::new(&file).exists(),
        "a state file was written in the system's folder"
    );
}

// read ================================================================================================================

#[skuld::test]
fn read_returns_the_bytes_of_the_file_and_not_found_for_a_missing_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("state.json"), b"{\"a\":1}").unwrap();

    assert_eq!(dir.read(&name("state.json")).unwrap(), b"{\"a\":1}");
    assert_eq!(kind(dir.read(&name("absent"))), Some(io::ErrorKind::NotFound));
}

#[skuld::test]
fn read_does_not_follow_a_symlink_at_the_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let target = tmp.path().join("secret");
    std::fs::write(&target, b"theirs").unwrap();
    plant_file_symlink(&target, &tmp.path().join("link"));

    assert!(dir.read(&name("link")).is_err());
}

#[cfg(unix)]
#[skuld::test]
fn read_refuses_a_fifo_at_the_name_and_does_not_block() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
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

    assert_eq!(dir.read(&name("state.json")).unwrap(), b"two");
    drop(reader);
}

// open_file: CreateAppend and Append ----------------------------------------------------------------------------------

const LOG: &str = "log";

fn create_append() -> OpenFile {
    OpenFile::CreateAppend { mode: 0o644 }
}

#[skuld::test]
fn append_adds_to_the_end_of_a_file_without_truncating() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    let mut first = dir.open_file(&name(LOG), create_append()).unwrap();
    first.write_all(b"one\n").unwrap();
    drop(first);
    let mut second = dir.open_file(&name(LOG), OpenFile::Append).unwrap();
    second.write_all(b"two\n").unwrap();

    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"one\ntwo\n");
}

#[skuld::test]
fn append_does_not_create_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    assert_eq!(
        kind(dir.open_file(&name(LOG), OpenFile::Append)),
        Some(io::ErrorKind::NotFound)
    );
    assert!(names(tmp.path()).is_empty());
}

#[skuld::test]
fn create_append_creates_only_a_free_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join(LOG), b"theirs").unwrap();

    assert_eq!(
        kind(dir.open_file(&name(LOG), create_append())),
        Some(io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"theirs");
}

#[skuld::test]
fn append_does_not_follow_a_symlink_at_the_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let target = tmp.path().join("secret");
    std::fs::write(&target, b"theirs").unwrap();
    plant_file_symlink(&target, &tmp.path().join(LOG));

    assert!(dir.open_file(&name(LOG), OpenFile::Append).is_err());
    assert!(dir.open_file(&name(LOG), create_append()).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"theirs");
}

#[skuld::test]
fn an_appended_file_can_be_renamed_by_anyone_who_shares_delete() {
    // The log writer keeps its file open while a reader or a scanner looks at it.
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let mut open = dir.open_file(&name(LOG), create_append()).unwrap();
    open.write_all(b"x").unwrap();

    std::fs::rename(tmp.path().join(LOG), tmp.path().join("log.1")).unwrap();

    assert_eq!(std::fs::read(tmp.path().join("log.1")).unwrap(), b"x");
}

// append_own_file =====================================================================================================
//
// A privileged log writer in a folder a user may own: whatever sits at the log's name is written to only if it is
// the owner's file. Anything else (another name of someone else's file, a link, a FIFO) is replaced by a fresh file
// and left as it was.

/// The owner the writer is told to expect: not this process, so that a file this process made is not it.
#[cfg(unix)]
fn another_owner() -> Option<(u32, u32)> {
    // SAFETY: geteuid and getegid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Some((uid + 1, gid + 1))
}

#[cfg(windows)]
fn another_owner() -> Option<(u32, u32)> {
    None
}

/// This process: the owner of every file it makes.
#[cfg(unix)]
fn this_owner() -> Option<(u32, u32)> {
    // SAFETY: geteuid and getegid take no arguments and cannot fail.
    Some(unsafe { (libc::geteuid(), libc::getegid()) })
}

fn append_line(dir: &Dir, owner: Option<(u32, u32)>, line: &str) -> io::Result<()> {
    dir.append_own_file(&name(LOG), 0o644, owner)?
        .write_all(line.as_bytes())
}

#[skuld::test]
fn a_log_that_is_not_there_is_created_and_the_next_open_continues_it() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    append_line(&dir, None, "one\n").unwrap();
    append_line(&dir, None, "two\n").unwrap();

    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"one\ntwo\n");
}

#[cfg(unix)]
#[skuld::test]
fn a_log_the_owner_owns_is_continued() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join(LOG), b"before\n").unwrap();

    append_line(&dir, this_owner(), "after\n").unwrap();

    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"before\nafter\n");
}

#[skuld::test]
fn another_name_of_a_file_is_replaced_and_the_file_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"theirs\n").unwrap();
    let before = std::fs::metadata(&victim).unwrap();
    std::fs::hard_link(&victim, tmp.path().join(LOG)).unwrap();

    append_line(&dir, another_owner(), "log\n").unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"theirs\n");
    let after = std::fs::metadata(&victim).unwrap();
    assert_eq!(after.permissions(), before.permissions());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!((after.uid(), after.mode()), (before.uid(), before.mode()));
    }
    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"log\n");
}

#[skuld::test]
fn a_symlink_at_the_name_is_replaced_and_what_it_points_at_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let target = tmp.path().join("secret");
    std::fs::write(&target, b"theirs\n").unwrap();
    plant_file_symlink(&target, &tmp.path().join(LOG));

    append_line(&dir, another_owner(), "log\n").unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"theirs\n");
    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"log\n");
    assert!(!std::fs::symlink_metadata(tmp.path().join(LOG))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[skuld::test]
fn a_fifo_at_the_name_is_replaced_and_does_not_block_the_open() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let fifo = std::ffi::CString::new(tmp.path().join(LOG).as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    append_line(&dir, None, "log\n").unwrap();

    assert_eq!(std::fs::read(tmp.path().join(LOG)).unwrap(), b"log\n");
}

#[skuld::test]
fn a_directory_at_the_name_is_an_error_and_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::create_dir(tmp.path().join(LOG)).unwrap();

    assert!(append_line(&dir, None, "log\n").is_err());
    assert!(tmp.path().join(LOG).is_dir());
}

#[cfg(unix)]
#[skuld::test]
fn a_continued_log_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    append_line(&dir, this_owner(), "one\n").unwrap();
    std::fs::set_permissions(tmp.path().join(LOG), std::fs::Permissions::from_mode(0o640)).unwrap();

    append_line(&dir, this_owner(), "two\n").unwrap();

    let mode = std::fs::metadata(tmp.path().join(LOG)).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640, "an existing file's mode is not set again");
}

// link / rename / rename_noreplace / sync =============================================================================

#[skuld::test]
fn link_gives_the_file_a_second_name_and_never_replaces_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("a"), b"a").unwrap();
    std::fs::write(tmp.path().join("taken"), b"theirs").unwrap();

    dir.link(&name("a"), &name("b")).unwrap();
    let refused = dir.link(&name("a"), &name("taken"));

    assert_eq!(dir.id_of(&name("a")).unwrap(), dir.id_of(&name("b")).unwrap());
    assert_eq!(kind(refused), Some(io::ErrorKind::AlreadyExists));
    assert_eq!(std::fs::read(tmp.path().join("taken")).unwrap(), b"theirs");
    assert_eq!(
        kind(dir.link(&name("absent"), &name("c"))),
        Some(io::ErrorKind::NotFound)
    );
}

#[skuld::test]
fn rename_moves_a_file_over_the_name_it_is_given_and_by_name_only() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("active"), b"new").unwrap();
    std::fs::write(tmp.path().join("old"), b"old").unwrap();

    dir.rename(&name("active"), &name("old")).unwrap();

    assert_eq!(names(tmp.path()), vec![name("old")]);
    assert_eq!(std::fs::read(tmp.path().join("old")).unwrap(), b"new");
    assert_eq!(
        kind(dir.rename(&name("absent"), &name("x"))),
        Some(io::ErrorKind::NotFound)
    );
}

#[skuld::test]
fn rename_noreplace_moves_to_a_free_name_and_never_replaces() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("from"), b"from").unwrap();
    std::fs::write(tmp.path().join("taken"), b"theirs").unwrap();

    dir.rename_noreplace(&name("from"), &name("free")).unwrap();
    std::fs::write(tmp.path().join("from"), b"from").unwrap();
    let refused = dir.rename_noreplace(&name("from"), &name("taken"));

    assert_eq!(std::fs::read(tmp.path().join("free")).unwrap(), b"from");
    assert_eq!(kind(refused), Some(io::ErrorKind::AlreadyExists));
    assert_eq!(std::fs::read(tmp.path().join("from")).unwrap(), b"from");
    assert_eq!(std::fs::read(tmp.path().join("taken")).unwrap(), b"theirs");
    assert_eq!(
        kind(dir.rename_noreplace(&name("absent"), &name("y"))),
        Some(io::ErrorKind::NotFound)
    );
}

#[skuld::test]
fn sync_flushes_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    // A volume with no directory flush answers an error the caller reads; the temp dir is on one that has it.
    dir.sync().unwrap();
}

// stage ===============================================================================================================

#[skuld::test]
fn a_staged_file_is_invisible_under_its_name_until_published() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic(&name("state.json"), b"old", None, |_| Ok(())).unwrap();

    let staged = dir.stage(&name("state.json"), b"new", None, |_| Ok(())).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"old");

    staged.publish().unwrap();
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"new");
    assert_eq!(names(tmp.path()), vec![name("state.json")]);
}

#[skuld::test]
fn a_staged_file_that_is_dropped_leaves_nothing_and_the_old_file_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    dir.write_atomic(&name("state.json"), b"old", None, |_| Ok(())).unwrap();

    drop(dir.stage(&name("state.json"), b"new", None, |_| Ok(())).unwrap());

    assert_eq!(names(tmp.path()), vec![name("state.json")]);
    assert_eq!(std::fs::read(tmp.path().join("state.json")).unwrap(), b"old");
}

#[skuld::test]
fn claiming_publishes_a_free_name_and_loses_to_a_taken_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    dir.stage(&name("marker"), b"first", None, |_| Ok(()))
        .unwrap()
        .claim()
        .unwrap();
    let lost = dir.stage(&name("marker"), b"second", None, |_| Ok(())).unwrap().claim();

    assert_eq!(kind(lost), Some(io::ErrorKind::AlreadyExists));
    assert_eq!(std::fs::read(tmp.path().join("marker")).unwrap(), b"first");
    assert_eq!(names(tmp.path()), vec![name("marker")], "no temp left behind");
}

#[skuld::test]
fn a_failed_protect_leaves_no_staged_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    let err = dir
        .stage(&name("state.json"), b"x", None, |_| Err(io::Error::other("no")))
        .err()
        .unwrap();

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(names(tmp.path()).is_empty());
}

#[skuld::test]
fn link_and_rename_work_for_a_name_of_every_length() {
    // Windows reads the new name out of a buffer sized by its length; a short name is the edge.
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("source"), b"x").unwrap();

    for len in 1..=40 {
        let target = "n".repeat(len);
        dir.link(&name("source"), &name(&target)).unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join(&target)).unwrap(),
            b"x",
            "link, length {len}"
        );

        let moved = "m".repeat(len);
        dir.rename(&name(&target), &name(&moved)).unwrap();
        assert!(!tmp.path().join(&target).exists(), "rename, length {len}");
        assert_eq!(
            std::fs::read(tmp.path().join(&moved)).unwrap(),
            b"x",
            "rename, length {len}"
        );

        dir.rename_noreplace(&name(&moved), &name(&target)).unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join(&target)).unwrap(),
            b"x",
            "noreplace, length {len}"
        );
        dir.unlink(&name(&target)).unwrap();
    }
}

#[skuld::test]
fn unlink_refuses_a_directory_and_leaves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();

    let err = dir.unlink(&name("sub")).unwrap_err();

    assert!(err.kind() != io::ErrorKind::NotFound, "{err:?}");
    assert!(tmp.path().join("sub").is_dir());
}

#[skuld::test]
fn unlink_frees_the_name_at_once_even_while_a_reader_holds_the_file() {
    // A reader that shares delete, as `std` opens: on Windows a delete that waits for the last handle leaves
    // the name unusable, and a new file cannot take it.
    let tmp = tempfile::tempdir().unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    std::fs::write(tmp.path().join("state.json"), b"old").unwrap();
    let reader = std::fs::File::open(tmp.path().join("state.json")).unwrap();

    dir.unlink(&name("state.json")).unwrap();
    let recreated = dir.open_file(&name("state.json"), OpenFile::CreateNew { mode: 0o600 });

    assert!(recreated.is_ok(), "the name is still taken: {:?}", recreated.err());
    drop(reader);
}
