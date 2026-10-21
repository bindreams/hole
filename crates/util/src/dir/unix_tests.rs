use super::*;
use crate::dir::testing::{plant_link as plant, user_dir, SystemScratch};
use crate::dir::Dir;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const ROOT: u32 = 0;

fn refusal(result: io::Result<Dir>) -> Refusal {
    let err = result.err().expect("the path must be refused");
    *Refusal::from_error(&err).unwrap_or_else(|| panic!("not a typed refusal: {err:?}"))
}

// Links ---------------------------------------------------------------------------------------------------------------
//
// A test cannot make a root-owned link, or a folder of another user, without being root, and cannot
// be sure what the host's `/` holds. So each case is stated for any runner: the fixtures give what they
// make to an unprivileged user whoever runs the test.

/// The first symlink in `/` that root owns and that leads to a directory: macOS's `/var`, `/etc` and
/// `/tmp`, a merged-usr Linux's `/bin` and `/lib`.
fn system_link() -> PathBuf {
    std::fs::read_dir("/")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            let meta = std::fs::symlink_metadata(path).unwrap();
            meta.file_type().is_symlink() && meta.uid() == ROOT && path.is_dir()
        })
        .expect(
            "no link owned by root in `/` leads to a directory: this host cannot run the test of the system's links",
        )
}

#[skuld::test]
fn a_link_the_system_owns_in_a_folder_the_system_owns_is_followed() {
    let link = system_link();

    let dir = Dir::open(&link, false, None).unwrap_or_else(|err| panic!("{link:?}: {err:?}"));

    assert_eq!(
        FileIdOf::of(dir.file()),
        FileIdOf::of(&std::fs::File::open(&link).unwrap())
    );
}

#[skuld::test]
fn root_is_the_system_and_every_other_uid_a_user() {
    let meta = |uid| Meta {
        dev: 1,
        ino: 1,
        uid,
        mode: 0,
    };

    assert_eq!(meta(0).owner(), Owner::Privileged);
    for uid in [1, 1000, 65534, u32::MAX] {
        assert_eq!(meta(uid).owner(), Owner::User(uid), "uid {uid}");
    }
}

#[skuld::test]
fn a_link_the_runner_owns_to_a_folder_a_user_owns_is_followed() {
    // As root this is a link the system owns to a user's folder (macOS's `/var/folders/.../T`): followed, and
    // not binding the walk to a user. As anyone else it is that user's link to their own folder.
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();

    let dir = Dir::open(&tmp.path().join("link"), false, None).unwrap();

    assert_eq!(
        FileIdOf::of(dir.file()),
        FileIdOf::of(&std::fs::File::open(&real).unwrap())
    );
}

#[skuld::test]
fn a_users_link_to_a_folder_the_same_user_owns_is_followed() {
    // A profile folder moved to another disk and linked back.
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant(&real, &tmp.path().join("link"));

    let dir = Dir::open(&tmp.path().join("link"), false, None).unwrap();

    assert_eq!(
        FileIdOf::of(dir.file()),
        FileIdOf::of(&std::fs::File::open(&real).unwrap())
    );
}

#[skuld::test]
fn a_users_link_to_a_folder_the_system_owns_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    plant(Path::new("/etc"), &tmp.path().join("link"));

    assert_eq!(
        refusal(Dir::open(&tmp.path().join("link"), false, None)),
        Refusal::Symlink
    );
}

#[skuld::test]
fn a_users_link_to_a_folder_the_system_owns_is_refused_below_the_link_too() {
    // `/etc` has `ssl`; the folder below the link is still not the user's.
    let tmp = tempfile::tempdir().unwrap();
    plant(Path::new("/etc"), &tmp.path().join("link"));

    assert_eq!(
        refusal(Dir::open(&tmp.path().join("link").join("ssl"), false, None)),
        Refusal::Symlink
    );
}

#[skuld::test]
fn nothing_is_made_in_a_folder_the_system_owns_through_a_users_link() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    plant(scratch.root(), &tmp.path().join("link"));
    let through = tmp.path().join("link").join(scratch.name()).join("state");

    assert_eq!(refusal(Dir::open(&through, true, None)), Refusal::Symlink);

    assert!(
        !scratch.path().exists(),
        "a folder was made in the system's scratch folder"
    );
}

#[skuld::test]
fn a_folder_missing_below_a_users_link_is_made_in_the_users_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant(&real, &tmp.path().join("link"));

    Dir::open(&tmp.path().join("link").join("a").join("b"), true, None).unwrap();

    assert!(real.join("a").join("b").is_dir());
}

#[skuld::test]
fn a_users_link_to_a_missing_folder_makes_the_folder_in_the_users_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    user_dir(&base);
    let target = base.join("not-yet").join("deeper");
    plant(&target, &tmp.path().join("link"));

    Dir::open(&tmp.path().join("link"), true, None).unwrap();

    assert!(target.is_dir());
}

#[skuld::test]
fn a_users_link_in_a_users_folder_to_the_system_is_refused_after_a_followed_link() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant(Path::new("/etc"), &real.join("inner"));
    plant(&real, &tmp.path().join("link"));

    assert_eq!(
        refusal(Dir::open(&tmp.path().join("link").join("inner"), false, None)),
        Refusal::Symlink
    );
}

#[skuld::test]
fn a_followed_relative_link_resolves_from_the_directory_it_sits_in() {
    let tmp = tempfile::tempdir().unwrap();
    user_dir(&tmp.path().join("a").join("real"));
    user_dir(&tmp.path().join("b"));
    plant(Path::new("../a/real"), &tmp.path().join("b").join("link"));

    Dir::open(&tmp.path().join("b").join("link").join("made"), true, None).unwrap();

    assert!(tmp.path().join("a").join("real").join("made").is_dir());
}

#[skuld::test]
fn a_followed_absolute_link_resolves_from_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    plant(&real, &tmp.path().join("link"));

    Dir::open(&tmp.path().join("link").join("made"), true, None).unwrap();

    assert!(real.join("made").is_dir());
}

#[skuld::test]
fn a_link_met_again_after_its_own_resolution_is_not_a_loop() {
    // `link` leads to `real`, where `again` leads back through `link`: the way macOS's `/var` shows up twice in a
    // path under `/var/folders` whose user link points at another `/var/folders` path.
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real.join("sub"));
    plant(&real, &tmp.path().join("link"));
    plant(&tmp.path().join("link").join("sub"), &real.join("again"));

    let dir = Dir::open(&tmp.path().join("link").join("again"), false, None).unwrap();

    assert_eq!(
        FileIdOf::of(dir.file()),
        FileIdOf::of(&std::fs::File::open(real.join("sub")).unwrap())
    );
}

#[skuld::test]
fn a_link_to_a_path_through_itself_is_a_loop() {
    let tmp = tempfile::tempdir().unwrap();
    user_dir(&tmp.path().join("real"));
    plant(&tmp.path().join("link").join("deeper"), &tmp.path().join("link"));

    assert_eq!(
        refusal(Dir::open(&tmp.path().join("link"), true, None)),
        Refusal::Symlink
    );
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
fn a_symlink_below_a_directory_the_caller_can_only_search_is_followed_by_the_same_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let guarded = tmp.path().join("a");
    user_dir(&guarded.join("real"));
    plant(&guarded.join("real"), &guarded.join("link"));
    plant(Path::new("/etc"), &guarded.join("etc"));
    let _restore = Restore(guarded.clone(), 0o755);
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o311)).unwrap();

    assert!(Dir::open(&guarded.join("link"), false, None).is_ok());
    assert_eq!(refusal(Dir::open(&guarded.join("etc"), false, None)), Refusal::Symlink);
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
