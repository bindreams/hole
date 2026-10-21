use super::*;

const ROOT: Owner<u32> = Owner::Privileged;

fn user(id: u32) -> Owner<u32> {
    Owner::User(id)
}

fn existing(owner: Owner<u32>) -> Folder<u32> {
    Folder::Existing(owner)
}

// may_enter ===========================================================================================================

#[skuld::test]
fn a_walk_may_leave_a_privileged_folder_for_anything() {
    assert!(ROOT.may_enter(&ROOT));
    assert!(ROOT.may_enter(&user(1)));
}

#[skuld::test]
fn a_walk_may_move_between_folders_of_one_user() {
    assert!(user(1).may_enter(&user(1)));
}

#[skuld::test]
fn a_walk_may_not_leave_a_users_folder_for_the_systems_or_another_users() {
    assert!(!user(1).may_enter(&ROOT));
    assert!(!user(1).may_enter(&user(2)));
}

// follow ==============================================================================================================

#[skuld::test]
fn a_privileged_link_in_a_privileged_folder_is_followed_and_binds_nothing() {
    let mut trail = Trail::new();

    assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));

    assert_eq!(trail.end_at(&existing(ROOT)), Ok(()));
    assert_eq!(trail.end_at(&existing(user(1))), Ok(()));
    assert_eq!(trail.create_in(&existing(ROOT)), Ok(()));
}

#[skuld::test]
fn a_privileged_link_in_a_users_folder_is_refused() {
    // A user can hard-link a link the system owns into a folder they own.
    assert_eq!(Trail::new().follow(&user(1), &ROOT), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_users_link_in_the_users_own_folder_is_followed() {
    assert_eq!(Trail::new().follow(&user(1), &user(1)), Ok(()));
}

#[skuld::test]
fn a_users_link_in_a_privileged_folder_is_followed() {
    // `/tmp` is the system's and anyone may plant a link in it.
    assert_eq!(Trail::new().follow(&ROOT, &user(1)), Ok(()));
}

#[skuld::test]
fn a_link_in_one_users_folder_owned_by_another_is_refused() {
    assert_eq!(Trail::new().follow(&user(1), &user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn once_a_users_link_is_followed_every_later_link_is_that_users_or_the_systems() {
    let mut trail = Trail::new();
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.follow(&ROOT, &user(1)), Ok(()));
    assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));
    assert_eq!(trail.follow(&ROOT, &user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_refused_link_binds_nothing() {
    let mut trail = Trail::new();
    trail.follow(&user(1), &user(2)).unwrap_err();

    assert_eq!(trail.end_at(&existing(ROOT)), Ok(()));
}

// end_at and create_in ------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_walk_that_followed_a_users_link_ends_only_in_that_users_folder() {
    let mut trail = Trail::new();
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.end_at(&existing(user(1))), Ok(()));
    assert_eq!(trail.end_at(&existing(ROOT)), Err(Refusal::Symlink));
    assert_eq!(trail.end_at(&existing(user(2))), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_walk_that_followed_a_users_link_creates_only_in_that_users_folder() {
    let mut trail = Trail::new();
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.create_in(&existing(user(1))), Ok(()));
    assert_eq!(trail.create_in(&existing(ROOT)), Err(Refusal::Symlink));
    assert_eq!(trail.create_in(&existing(user(2))), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_folder_the_walk_made_in_the_link_owners_tree_is_the_link_owners() {
    // The privileged process made it, so the file system says it is the system's.
    let mut trail = Trail::new();
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.create_in(&Folder::Made), Ok(()));
    assert_eq!(trail.end_at(&Folder::Made), Ok(()));
}

#[skuld::test]
fn a_walk_that_followed_no_users_link_ends_and_creates_anywhere() {
    let trail = Trail::<u32>::new();

    for folder in [existing(ROOT), existing(user(1)), Folder::Made] {
        assert_eq!(trail.end_at(&folder), Ok(()));
        assert_eq!(trail.create_in(&folder), Ok(()));
    }
}
