use super::Privilege;
use util::dir::Principal;

/// The oracle is the owner of a file this process makes: the system's when the process is privileged (unix: root;
/// Windows: an elevated token's files belong to Administrators), a user's otherwise.
#[skuld::test]
fn the_principal_is_the_privilege_of_this_process() {
    let expected = match util::dir::testing::runner_is_the_system() {
        true => Principal::System,
        false => Principal::User,
    };

    assert_eq!(super::principal(), expected);
}

/// A token query that fails says nothing about the process, so the guards stay on: only a measured "not privileged" is
/// the user's.
#[skuld::test]
fn a_privilege_that_could_not_be_read_is_privileged() {
    assert!(!Privilege::Unprivileged.is_privileged());
    assert!(Privilege::Privileged.is_privileged());
    assert!(Privilege::Unreadable.is_privileged());
}
