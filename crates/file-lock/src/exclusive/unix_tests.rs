use super::*;

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
fn a_single_link_regular_file_owned_by_the_process_passes() {
    assert_eq!(vet(file(ME), ME, None), Ok(()));
    assert_eq!(vet(file(ME), ME, Some((OWNER, OWNER))), Ok(()));
}

#[skuld::test]
fn a_single_link_regular_file_owned_by_the_expected_owner_passes() {
    assert_eq!(vet(file(OWNER), ME, Some((OWNER, OWNER))), Ok(()));
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
    assert_eq!(vet(file(STRANGER), ME, None), Ok(()));
}

#[skuld::test]
fn a_file_with_more_than_one_link_is_refused_whoever_owns_it() {
    for uid in [ME, OWNER, STRANGER] {
        let facts = Facts { links: 2, ..file(uid) };
        assert_eq!(
            vet(facts, ME, Some((OWNER, OWNER))),
            Err(Refusal::ExtraLinks { links: 2 }),
            "uid {uid}"
        );
    }
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

// open_locked_as ======================================================================================================
//
// The owner rule reaches the real open path through `open_locked_as`, which
// takes the effective uid as input: a test cannot make a file owned by someone
// else without root, but it can claim to be someone else.

fn real_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[skuld::test]
fn a_file_owned_by_neither_the_owner_nor_the_process_is_refused_by_the_real_open_and_left_alone() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mine = real_uid();
    let (pretend_euid, pretend_owner) = (mine + 1, mine + 2);

    let err = open_locked_as(&path, false, Some((pretend_owner, pretend_owner)), pretend_euid)
        .expect_err("a file owned by neither the owner nor the process must be refused");

    let refused = Refused::from_error(&err).expect("a typed refusal");
    assert_eq!(refused.path(), path);
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o644, "a refused file must not be re-permissioned");
    assert_eq!(meta.uid(), mine);
}

#[skuld::test]
fn a_file_owned_by_the_pretend_process_is_accepted_by_the_real_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    let mine = real_uid();

    let file = open_locked_as(&path, false, Some((mine + 2, mine + 2)), mine).unwrap();
    assert!(file.is_some());
}

#[skuld::test]
fn a_file_owned_by_the_expected_owner_is_accepted_by_the_real_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    let mine = real_uid();

    let file = open_locked_as(&path, false, Some((mine, mine)), mine + 1).unwrap();
    assert!(file.is_some());
}

#[skuld::test]
fn no_owner_means_no_ownership_check_in_the_real_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();

    let file = open_locked_as(&path, false, None, real_uid() + 1).unwrap();
    assert!(file.is_some());
}
