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
