use super::*;
use crate::dir::Dir;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const ROOT: u32 = 0;
const USER: u32 = 1000;

fn meta(uid: u32, mode: u32) -> Meta {
    Meta {
        dev: 1,
        ino: 1,
        uid,
        mode,
    }
}

fn is_root() -> bool {
    caller() == ROOT
}

fn refusal(result: io::Result<Dir>) -> Refusal {
    let err = result.err().expect("the path must be refused");
    *Refusal::from_error(&err).unwrap_or_else(|| panic!("not a typed refusal: {err:?}"))
}

// trusted_symlink =====================================================================================================

#[skuld::test]
fn a_symlink_root_owns_in_a_directory_only_root_can_write_is_trusted() {
    assert!(trusted_symlink(meta(ROOT, 0o120755), meta(ROOT, 0o040755)));
    assert!(trusted_symlink(meta(ROOT, 0o120755), meta(ROOT, 0o040700)));
}

#[skuld::test]
fn a_symlink_owned_by_anyone_but_root_is_not_trusted() {
    assert!(!trusted_symlink(meta(USER, 0o120755), meta(ROOT, 0o040755)));
}

#[skuld::test]
fn a_symlink_in_a_directory_root_does_not_own_is_not_trusted() {
    // A user can hard-link a root-owned symlink into a directory they own.
    assert!(!trusted_symlink(meta(ROOT, 0o120755), meta(USER, 0o040755)));
}

#[skuld::test]
fn a_symlink_in_a_directory_others_can_write_is_not_trusted() {
    for mode in [0o040775, 0o040757, 0o041777, 0o040777] {
        assert!(!trusted_symlink(meta(ROOT, 0o120755), meta(ROOT, mode)), "{mode:o}");
    }
}

// The real walk -------------------------------------------------------------------------------------------------------
//
// A test cannot make a root-owned symlink without being root, so each of these says what it must do
// as root and as anyone else: both are real behavior, neither is skipped.

#[skuld::test]
fn a_symlink_the_caller_owns_is_followed_only_when_the_caller_is_root() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();

    let opened = Dir::open(&tmp.path().join("link"), false, None);

    match is_root() {
        true => assert!(opened.is_ok(), "a root-owned link in a root-only directory is followed"),
        false => assert_eq!(refusal(opened), Refusal::Symlink),
    }
}

#[skuld::test]
fn a_followed_relative_link_resolves_from_the_directory_it_sits_in() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("a").join("real")).unwrap();
    std::fs::create_dir(tmp.path().join("b")).unwrap();
    std::os::unix::fs::symlink("../a/real", tmp.path().join("b").join("link")).unwrap();

    let opened = Dir::open(&tmp.path().join("b").join("link").join("made"), true, None);

    match is_root() {
        true => {
            opened.unwrap();
            assert!(tmp.path().join("a").join("real").join("made").is_dir());
        }
        false => assert_eq!(refusal(opened), Refusal::Symlink),
    }
}

#[skuld::test]
fn a_followed_absolute_link_resolves_from_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();

    let opened = Dir::open(&tmp.path().join("link").join("made"), true, None);

    match is_root() {
        true => {
            opened.unwrap();
            assert!(real.join("made").is_dir());
        }
        false => assert_eq!(refusal(opened), Refusal::Symlink),
    }
}

#[skuld::test]
fn a_loop_of_links_is_refused_not_followed_forever() {
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("b", tmp.path().join("a")).unwrap();
    std::os::unix::fs::symlink("a", tmp.path().join("b")).unwrap();

    assert_eq!(refusal(Dir::open(&tmp.path().join("a"), true, None)), Refusal::Symlink);
}

#[skuld::test]
fn a_parent_component_is_resolved_by_the_directory_in_hand() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("a")).unwrap();
    std::fs::create_dir(tmp.path().join("b")).unwrap();

    let dir = Dir::open(&tmp.path().join("a").join("..").join("b"), false, None).unwrap();

    assert_eq!(
        FileIdOf::of(dir.file()),
        FileIdOf::of(&std::fs::File::open(tmp.path().join("b")).unwrap())
    );
}

/// `(dev, ino)` of an open file, read independently of the code under test.
#[derive(Debug, PartialEq)]
struct FileIdOf(u64, u64);

impl FileIdOf {
    fn of(file: &File) -> Self {
        let meta = file.metadata().unwrap();
        FileIdOf(meta.dev(), meta.ino())
    }
}

// Ownership of the final directory ------------------------------------------------------------------------------------

fn mine() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[skuld::test]
fn a_directory_owned_by_neither_the_owner_nor_the_caller_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let me = tmp.path().metadata().unwrap().uid();

    let refused = refusal(Dir::open_as(tmp.path(), false, Some((me + 2, me + 2)), me + 1));

    assert_eq!(refused, Refusal::ForeignOwner { uid: me });
}

#[skuld::test]
fn a_directory_owned_by_the_expected_owner_is_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let me = tmp.path().metadata().unwrap().uid();

    Dir::open_as(tmp.path(), false, Some((me, me)), me + 1).unwrap();
}

#[skuld::test]
fn a_directory_owned_by_the_caller_is_accepted_for_another_owner() {
    // The state directory a previous run created before it could hand it to the user.
    let tmp = tempfile::tempdir().unwrap();
    let me = tmp.path().metadata().unwrap().uid();

    Dir::open_as(tmp.path(), false, Some((me + 2, me + 2)), me).unwrap();
}

#[skuld::test]
fn no_owner_means_no_ownership_check_on_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let me = tmp.path().metadata().unwrap().uid();

    Dir::open_as(tmp.path(), false, None, me + 1).unwrap();
}

#[skuld::test]
fn the_caller_is_the_real_effective_uid() {
    let tmp = tempfile::tempdir().unwrap();

    assert_eq!(caller(), tmp.path().metadata().unwrap().uid());
}

// secure / write_atomic ownership -------------------------------------------------------------------------------------

/// Whether this process may give a file to `uid`, as the OS says for a scratch file.
fn may_chown_to(scratch_dir: &Path, uid: u32) -> bool {
    let scratch = scratch_dir.join("scratch");
    std::fs::write(&scratch, b"").unwrap();
    std::os::unix::fs::chown(&scratch, Some(uid), Some(uid)).is_ok()
}

#[skuld::test]
fn secure_sets_the_mode_and_hands_the_directory_to_the_owner_when_the_os_allows() {
    let tmp = tempfile::tempdir().unwrap();
    let dir_path = tmp.path().join("state");
    let foreign = mine() + 2;
    let allowed = may_chown_to(tmp.path(), foreign);
    let dir = Dir::open(&dir_path, true, None).unwrap();

    dir.secure(Some((foreign, foreign)), Some(0o700)).unwrap();

    let meta = std::fs::metadata(&dir_path).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o700);
    assert_eq!(meta.uid() == foreign, allowed, "uid {}", meta.uid());
}

#[skuld::test]
fn write_atomic_seals_the_file_to_the_owner_and_to_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let foreign = mine() + 2;
    let allowed = may_chown_to(tmp.path(), foreign);
    let dir = Dir::open(tmp.path(), false, None).unwrap();

    dir.write_atomic("state.json".as_ref(), b"x", Some((foreign, foreign)), |_| Ok(()))
        .unwrap();

    let meta = std::fs::metadata(tmp.path().join("state.json")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_eq!(meta.uid() == foreign, allowed, "uid {}", meta.uid());
}

#[skuld::test]
fn a_file_swapped_in_after_the_rename_is_not_touched() {
    // The attack on a writer that chowns and chmods the final path after renaming onto it: the name
    // is replaced by a hard link to a file the privileged process owns, and the follow-up
    // re-permissions that file.
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::metadata(&victim).unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let foreign = mine() + 2;

    dir.write_atomic_with(
        "state.json".as_ref(),
        b"new",
        Some((foreign, foreign)),
        |_| Ok(()),
        || {
            std::fs::remove_file(tmp.path().join("state.json")).unwrap();
            std::fs::hard_link(&victim, tmp.path().join("state.json")).unwrap();
        },
    )
    .unwrap();

    let after = std::fs::metadata(&victim).unwrap();
    assert_eq!(
        (after.mode(), after.uid(), after.gid()),
        (before.mode(), before.uid(), before.gid())
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[skuld::test]
fn a_symlink_swapped_in_after_the_rename_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::metadata(&victim).unwrap();
    let dir = Dir::open(tmp.path(), false, None).unwrap();
    let foreign = mine() + 2;

    dir.write_atomic_with(
        "state.json".as_ref(),
        b"new",
        Some((foreign, foreign)),
        |_| Ok(()),
        || {
            std::fs::remove_file(tmp.path().join("state.json")).unwrap();
            std::os::unix::fs::symlink(&victim, tmp.path().join("state.json")).unwrap();
        },
    )
    .unwrap();

    let after = std::fs::metadata(&victim).unwrap();
    assert_eq!(
        (after.mode(), after.uid(), after.gid()),
        (before.mode(), before.uid(), before.gid())
    );
}

// Search-only directories on the path ---------------------------------------------------------------------------------
//
// The path calls `Dir` replaces need only search permission on the directories above the file. As root
// (which bypasses the check) these pass whatever the open flags are: the check only has teeth for anyone else.

/// Restores a directory's mode so the temp dir can be removed even when an assertion fails.
struct Restore(PathBuf, u32);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

#[skuld::test]
fn a_directory_the_caller_can_search_but_not_read_is_walked_through() {
    for mode in [0o311, 0o111] {
        let tmp = tempfile::tempdir().unwrap();
        let leaf = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&leaf).unwrap();
        let guarded = tmp.path().join("a");
        let _restore = Restore(guarded.clone(), 0o755);
        std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(mode)).unwrap();

        let dir = Dir::open(&leaf, false, None).unwrap_or_else(|err| panic!("mode {mode:o}: {err:?}"));
        dir.write_atomic("state.json".as_ref(), b"x", None, |_| Ok(())).unwrap();

        assert_eq!(std::fs::read(leaf.join("state.json")).unwrap(), b"x", "mode {mode:o}");
    }
}

#[skuld::test]
fn a_missing_directory_is_created_below_one_the_caller_can_search_but_not_read() {
    let tmp = tempfile::tempdir().unwrap();
    let guarded = tmp.path().join("a");
    std::fs::create_dir(&guarded).unwrap();
    let _restore = Restore(guarded.clone(), 0o755);
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o311)).unwrap();

    Dir::open(&guarded.join("new").join("deeper"), true, None).unwrap();

    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(guarded.join("new").join("deeper").is_dir());
}

#[skuld::test]
fn a_symlink_below_a_directory_the_caller_can_only_search_is_still_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let guarded = tmp.path().join("a");
    std::fs::create_dir_all(guarded.join("real")).unwrap();
    std::os::unix::fs::symlink(guarded.join("real"), guarded.join("link")).unwrap();
    let _restore = Restore(guarded.clone(), 0o755);
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o311)).unwrap();

    let opened = Dir::open(&guarded.join("link"), false, None);

    match is_root() {
        true => assert!(opened.is_ok(), "root owns the link in a root-only directory"),
        false => assert_eq!(refusal(opened), Refusal::Symlink),
    }
}

// rename_noreplace ----------------------------------------------------------------------------------------------------

/// Only an answer that says the flag is unavailable falls back to the hard link. `EPERM` is a real refusal (a sticky
/// directory, a security module): the link is allowed where the rename was not, and the delete that follows it is
/// refused again, so the fallback would leave a backup and fail.
#[cfg(target_os = "linux")]
#[skuld::test]
fn only_renameat2_answers_that_mean_it_is_unavailable_fall_back_to_the_link() {
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

#[skuld::test]
fn the_real_open_refuses_a_directory_of_a_third_party_only_when_the_caller_can_make_one() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let me = state.metadata().unwrap().uid();
    let made = std::os::unix::fs::chown(&state, Some(me + 7), None).is_ok();

    let opened = Dir::open(&state, false, Some((me + 3, me + 3)));

    match made {
        true => assert_eq!(refusal(opened), Refusal::ForeignOwner { uid: me + 7 }),
        false => assert!(opened.is_ok()),
    }
}
