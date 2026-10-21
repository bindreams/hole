use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;

const ME: u32 = 1000;
const OWNER: u32 = 2001;
const STRANGER: u32 = 3002;

fn file(uid: u32) -> Facts {
    Facts {
        regular: true,
        links: 1,
        uid,
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
fn a_file_replaced_for_its_owner_is_replaced_whatever_its_link_count() {
    for links in [0, 1, 2, 7] {
        let facts = Facts { links, ..file(ME) };
        assert_eq!(
            vet(facts, ME, Some((OWNER, OWNER))),
            Ok(Verdict::Replace),
            "{links} links"
        );
    }
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

#[skuld::test]
fn a_kept_file_with_more_than_one_link_is_refused() {
    for (uid, owner) in [(OWNER, Some((OWNER, OWNER))), (ME, None), (STRANGER, None)] {
        let facts = Facts { links: 2, ..file(uid) };
        assert_eq!(
            vet(facts, ME, owner),
            Err(Refusal::ExtraLinks { links: 2 }),
            "uid {uid}"
        );
    }
}

#[skuld::test]
fn a_file_unlinked_since_the_open_is_not_refused_for_its_links() {
    let facts = Facts { links: 0, ..file(ME) };
    assert_eq!(vet(facts, ME, None), Ok(Verdict::Keep));
}

#[skuld::test]
fn a_file_that_is_not_regular_is_refused_whoever_owns_it() {
    for uid in [ME, OWNER, STRANGER] {
        let facts = Facts {
            regular: false,
            ..file(uid)
        };
        assert_eq!(
            vet(facts, ME, Some((OWNER, OWNER))),
            Err(Refusal::NotRegular),
            "uid {uid}"
        );
    }
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

    let file = open_locked(&path, false, Some((mine + 2, mine + 2)), mine)
        .unwrap()
        .expect("a leftover must not lock the owner out");

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
    .expect("acquired");

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
    // A second name keeps the first file at one link once the lock name is swapped.
    std::fs::hard_link(&path, tmp.path().join("kept")).unwrap();
    let mine = real_uid();
    let mut swapped = false;

    let file = open_locked_with(&path, false, Some((mine, mine)), mine + 1, || {
        if !std::mem::replace(&mut swapped, true) {
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, b"second").unwrap();
        }
    })
    .unwrap()
    .expect("acquired");

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
    .expect("acquired");

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
    .expect("acquired");

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

#[skuld::test]
fn a_lock_below_a_directory_the_caller_can_only_search_is_acquired() {
    let tmp = tempfile::tempdir().unwrap();
    let guarded = tmp.path().join("a");
    let lock_dir = guarded.join("state");
    std::fs::create_dir_all(&lock_dir).unwrap();
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o311)).unwrap();

    let held = crate::Exclusive::try_acquire(&lock_dir.join("target.json.lock"), None);

    // Restored first so the temp dir can be removed whatever the assertion says.
    std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(held.unwrap().is_some());
}
