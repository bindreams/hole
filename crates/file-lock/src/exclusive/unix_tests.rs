use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use util::dir::testing::as_unprivileged;

const ME: u32 = 1000;
const OWNER: u32 = 2001;
const STRANGER: u32 = 3002;

fn file(uid: u32) -> Facts {
    Facts {
        regular: true,
        uid,
        links: 1,
    }
}

// vet =================================================================================================================

#[skuld::test]
fn a_single_link_regular_file_owned_by_the_process_is_kept_when_no_owner_is_expected() {
    assert_eq!(vet(file(ME), ME, None), Ok(Verdict::Keep));
}

#[skuld::test]
fn a_single_link_regular_file_owned_by_the_expected_owner_is_kept() {
    assert_eq!(vet(file(OWNER), ME, Some((OWNER, OWNER))), Ok(Verdict::Keep));
    assert_eq!(vet(file(OWNER), OWNER, Some((OWNER, OWNER))), Ok(Verdict::Keep));
}

#[skuld::test]
fn a_file_owned_by_the_process_instead_of_the_expected_owner_is_replaced() {
    assert_eq!(vet(file(ME), ME, Some((OWNER, OWNER))), Ok(Verdict::Replace));
}

#[skuld::test]
fn a_file_with_another_owner_is_refused_when_an_owner_is_expected() {
    assert_eq!(
        vet(file(STRANGER), ME, Some((OWNER, OWNER))),
        Err(Refusal::ForeignOwner { uid: STRANGER })
    );
}

#[skuld::test]
fn ownership_is_not_checked_when_no_owner_is_expected() {
    assert_eq!(vet(file(STRANGER), ME, None), Ok(Verdict::Keep));
}

// open_locked =========================================================================================================
//
// The owner rule reaches the real open path through `open_locked`, which
// takes the caller's effective uid as input: a test cannot make a file owned by someone
// else without root, but it can claim to be someone else.

fn real_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[skuld::test]
fn a_file_owned_by_neither_the_owner_nor_the_process_is_refused_by_the_real_open_and_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mine = real_uid();
    let (pretend_euid, pretend_owner) = (mine + 1, mine + 2);

    let err = open_locked(&path, false, Some((pretend_owner, pretend_owner)), pretend_euid)
        .expect_err("a file owned by neither the owner nor the process must be refused");

    let refused = Refused::from_error(&err).expect("a typed refusal");
    assert_eq!(refused.path(), path);
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o644, "a refused file must not be re-permissioned");
    assert_eq!(meta.uid(), mine);
}

#[skuld::test]
fn a_file_owned_by_the_expected_owner_is_accepted_by_the_real_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    let mine = real_uid();

    let file = open_locked(&path, false, Some((mine, mine)), mine + 1).unwrap();
    assert!(file.is_some());
}

#[skuld::test]
fn no_owner_means_no_ownership_check_in_the_real_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();

    let file = open_locked(&path, false, None, real_uid() + 1).unwrap();
    assert!(file.is_some());
}

fn ino(path: &std::path::Path) -> u64 {
    std::fs::symlink_metadata(path).unwrap().ino()
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o777
}

#[skuld::test]
fn a_lock_file_left_by_a_crash_before_its_fchown_is_replaced_by_a_fresh_one() {
    // The crashed process created the file and owns it; the expected owner is someone else.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"leftover").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mine = real_uid();

    let file = open_locked_with(&path, false, Some((mine + 2, mine + 2)), mine, || {})
        .unwrap()
        .expect("a leftover must not lock the owner out")
        .file;

    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"",
        "the leftover must be replaced, not reused"
    );
    assert_eq!(mode(&path), 0o600);
    assert_eq!(
        file.metadata().unwrap().ino(),
        ino(&path),
        "the lock must be on the file at the name"
    );
}

#[skuld::test]
fn a_victim_unlinked_from_the_lock_name_after_the_open_is_left_alone() {
    // A file the privileged process owns is hard-linked at the lock name; once the open
    // has returned, the planted name is removed, so the victim's link count is back to 1.
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"victim").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::hard_link(&victim, &path).unwrap();
    let mine = real_uid();
    let mut planted = true;

    let file = open_locked_with(&path, false, Some((mine + 2, mine + 2)), mine, || {
        if std::mem::take(&mut planted) {
            std::fs::remove_file(&path).unwrap();
        }
    })
    .unwrap()
    .expect("acquired")
    .file;

    let meta = std::fs::metadata(&victim).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o644, "the victim must not be re-permissioned");
    assert_eq!(meta.uid(), mine);
    assert_eq!(meta.nlink(), 1);
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert_ne!(ino(&path), meta.ino(), "the lock must not be the victim");
    assert_eq!(file.metadata().unwrap().ino(), ino(&path));
}

#[skuld::test]
fn a_file_swapped_in_after_the_open_is_the_one_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"first").unwrap();
    let mine = real_uid();
    let mut swapped = false;

    let file = open_locked_with(&path, false, Some((mine, mine)), mine + 1, || {
        if !std::mem::replace(&mut swapped, true) {
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, b"second").unwrap();
        }
    })
    .unwrap()
    .expect("acquired")
    .file;

    assert_eq!(
        file.metadata().unwrap().ino(),
        ino(&path),
        "the lock was taken on an orphaned file"
    );
}

#[skuld::test]
fn a_file_unlinked_after_the_open_is_replaced_not_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"first").unwrap();
    let mine = real_uid();
    let mut unlinked = false;

    let file = open_locked_with(&path, false, Some((mine, mine)), mine + 1, || {
        if !std::mem::replace(&mut unlinked, true) {
            std::fs::remove_file(&path).unwrap();
        }
    })
    .unwrap()
    .expect("acquired")
    .file;

    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(file.metadata().unwrap().ino(), ino(&path));
}

#[skuld::test]
fn a_leftover_that_another_process_holds_is_left_in_place_and_reported_held() {
    // A process that created the file and has not yet fchowned it holds the lock on it.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"mid-setup").unwrap();
    let holder = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    // SAFETY: `holder` is a valid, open fd.
    assert_eq!(
        unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let mine = real_uid();

    let got = open_locked(&path, false, Some((mine + 2, mine + 2)), mine).unwrap();

    assert!(got.is_none(), "a held leftover is contention");
    assert_eq!(
        ino(&path),
        holder.metadata().unwrap().ino(),
        "the held file must stay at the name"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"mid-setup");
}

#[skuld::test]
fn the_caller_is_the_real_effective_uid() {
    // A file this process creates is owned by its effective uid; the expectation
    // is read off the file, not off `geteuid`.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("created");
    std::fs::write(&path, b"").unwrap();

    assert_eq!(caller(), std::fs::metadata(&path).unwrap().uid());
}

// Directory swapped under the open ------------------------------------------------------------------------------------

#[skuld::test]
fn a_directory_swapped_for_a_symlink_after_the_open_is_not_followed() {
    // A leftover of ours is replaced: its name is unlinked and a new file created. Both go through the
    // directory that was opened, so a path that now leads elsewhere is not consulted. A file of the same
    // name outside is the victim of a path-based unlink.
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("target.json.lock"), b"victim").unwrap();
    let state = tmp.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("target.json.lock"), b"leftover").unwrap();
    let mine = real_uid();
    let mut swapped = false;

    let file = open_locked_with(
        &state.join("target.json.lock"),
        false,
        Some((mine + 2, mine + 2)),
        mine,
        || {
            if !std::mem::replace(&mut swapped, true) {
                std::fs::rename(&state, tmp.path().join("state.moved")).unwrap();
                std::os::unix::fs::symlink(&outside, &state).unwrap();
            }
        },
    )
    .unwrap()
    .expect("acquired")
    .file;

    assert_eq!(
        std::fs::read(outside.join("target.json.lock")).unwrap(),
        b"victim",
        "a file outside the opened directory was removed or replaced"
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    let moved = tmp.path().join("state.moved").join("target.json.lock");
    assert_eq!(
        std::fs::read(&moved).unwrap(),
        b"",
        "the lock must be in the opened directory"
    );
    assert_eq!(file.metadata().unwrap().ino(), ino(&moved));
}

// A directory above the lock that the caller can search but not read --------------------------------------------------

/// Gives a directory its mode back when dropped, so the temp dir can be removed whatever an assertion says.
struct Restore(std::path::PathBuf);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[skuld::test]
fn a_lock_below_a_directory_the_caller_can_only_search_is_acquired() {
    let tmp = tempfile::tempdir().unwrap();
    let guarded = tmp.path().join("a");
    let lock_dir = guarded.join("state");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let _restore = Restore(guarded.clone());
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o311)).unwrap();

    // Root bypasses the check, so the walk runs as a child that has dropped to `nobody` when the runner is root.
    as_unprivileged(tmp.path(), || {
        let held = crate::Exclusive::try_acquire(&lock_dir.join("target.json.lock"), None);
        assert!(held.unwrap().is_some());
    });
}

// A file that has other names -----------------------------------------------------------------------------------------

/// A group other than this process's own that it may give a file to: any group as root, else one it is a member of.
fn another_gid() -> u32 {
    // SAFETY: getegid and geteuid take no arguments and cannot fail.
    let (egid, euid) = unsafe { (libc::getegid(), libc::geteuid()) };
    if euid == 0 {
        return egid + 1;
    }
    let mut groups = [0 as libc::gid_t; 256];
    // SAFETY: `groups` holds the 256 entries the call is told it may fill.
    let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    assert!(n >= 0, "getgroups failed: {}", std::io::Error::last_os_error());
    groups[..n as usize]
        .iter()
        .copied()
        .find(|gid| *gid != egid)
        .expect("this test needs the user to be in a second group, to give a file to it")
}

fn gid(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().gid()
}

#[skuld::test]
fn a_file_with_another_name_is_locked_and_its_mode_and_group_are_not_changed() {
    // The owner's own file, hard-linked at the lock name: the expected owner owns it, so it is kept, and it is
    // not this call's to re-permission or hand to another group.
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"victim").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::hard_link(&victim, &path).unwrap();
    let (mine, group_before, other) = (real_uid(), gid(&victim), another_gid());

    let held = crate::Exclusive::try_acquire_as(&path, Some((mine, other)), mine)
        .unwrap()
        .expect("a file the owner owns, with another name, is still lockable");

    assert_eq!(mode(&victim), 0o644, "the victim must not be re-permissioned");
    assert_eq!(
        gid(&victim),
        group_before,
        "the victim must not be handed to another group"
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert_eq!(ino(&path), ino(&victim), "the lock is the file at the name");
    assert_eq!(held.file.metadata().unwrap().ino(), ino(&path));
}

#[skuld::test]
fn a_file_with_one_name_that_the_owner_owns_is_made_private_and_handed_to_the_owners_group() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (mine, other) = (real_uid(), another_gid());

    let _held = crate::Exclusive::try_acquire_as(&path, Some((mine, other)), mine)
        .unwrap()
        .expect("acquired");

    assert_eq!(mode(&path), 0o600);
    assert_eq!(gid(&path), other);
}

#[skuld::test]
fn a_file_is_changed_only_when_this_call_made_it_or_it_has_one_name_and_an_owner_is_expected() {
    let facts = |links| Facts {
        regular: true,
        uid: ME,
        links,
    };
    let owner = Some((ME, ME));
    assert!(changes(true, facts(1), owner), "made by this call");
    assert!(
        changes(true, facts(2), owner),
        "made by this call, then linked by someone"
    );
    assert!(changes(true, facts(1), None), "made by this call, no owner");
    assert!(
        changes(false, facts(1), owner),
        "the owner's own file, with no other name"
    );
    assert!(!changes(false, facts(2), owner), "another name leads to it");
    assert!(!changes(false, facts(1), None), "no owner is expected");
}
