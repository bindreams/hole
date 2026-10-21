use super::*;

const ROOT: Owner<u32> = Owner::Privileged;

fn user(id: u32) -> Owner<u32> {
    Owner::User(id)
}

/// More links than any test follows.
const PLENTY: usize = 1000;

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
    let mut trail = Trail::new(PLENTY);

    assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));

    assert_eq!(trail.end_at(&ROOT), Ok(()));
    assert_eq!(trail.end_at(&user(1)), Ok(()));
    assert_eq!(trail.create_in(&ROOT), Ok(()));
}

#[skuld::test]
fn a_privileged_link_in_a_users_folder_is_refused() {
    // A user can hard-link a link the system owns into a folder they own.
    assert_eq!(Trail::new(PLENTY).follow(&user(1), &ROOT), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_users_link_in_the_users_own_folder_is_followed() {
    assert_eq!(Trail::new(PLENTY).follow(&user(1), &user(1)), Ok(()));
}

#[skuld::test]
fn a_users_link_in_a_privileged_folder_is_followed() {
    // `/tmp` is the system's and anyone may plant a link in it.
    assert_eq!(Trail::new(PLENTY).follow(&ROOT, &user(1)), Ok(()));
}

#[skuld::test]
fn a_link_in_one_users_folder_owned_by_another_is_refused() {
    assert_eq!(Trail::new(PLENTY).follow(&user(1), &user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn once_a_users_link_is_followed_every_later_link_is_that_users_or_the_systems() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.follow(&ROOT, &user(1)), Ok(()));
    assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));
    assert_eq!(trail.follow(&ROOT, &user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_refused_link_binds_nothing() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&user(1), &user(2)).unwrap_err();

    assert_eq!(trail.end_at(&ROOT), Ok(()));
}

// end_at and create_in ------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_walk_that_followed_a_users_link_ends_only_in_that_users_folder() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.end_at(&user(1)), Ok(()));
    assert_eq!(trail.end_at(&ROOT), Err(Refusal::Symlink));
    assert_eq!(trail.end_at(&user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_walk_that_followed_a_users_link_creates_only_in_that_users_folder() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(trail.create_in(&user(1)), Ok(()));
    assert_eq!(trail.create_in(&ROOT), Err(Refusal::Symlink));
    assert_eq!(trail.create_in(&user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_walk_that_followed_no_users_link_ends_and_creates_anywhere() {
    let trail = Trail::<u32>::new(PLENTY);

    for folder in [ROOT, user(1)] {
        assert_eq!(trail.end_at(&folder), Ok(()));
        assert_eq!(trail.create_in(&folder), Ok(()));
    }
}

// the limit ===========================================================================================================

#[skuld::test]
fn a_walk_follows_as_many_links_as_its_limit_and_refuses_the_next() {
    let mut trail = Trail::<u32>::new(3);

    for _ in 0..3 {
        assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));
    }
    assert_eq!(trail.follow(&ROOT, &ROOT), Err(Refusal::Symlink));
    assert_eq!(trail.follow(&ROOT, &user(1)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_refused_link_is_not_counted() {
    let mut trail = Trail::<u32>::new(1);
    trail.follow(&user(1), &user(2)).unwrap_err();

    assert_eq!(trail.follow(&ROOT, &ROOT), Ok(()));
}

#[skuld::test]
fn a_walk_that_follows_no_links_is_bound_to_no_one() {
    let mut trail = Trail::<u32>::new(1);
    assert_eq!(trail.led_by(), None);

    trail.follow(&ROOT, &ROOT).unwrap();
    assert_eq!(trail.led_by(), None);
}

#[skuld::test]
fn the_first_users_link_names_the_user_the_walk_is_bound_to() {
    let mut trail = Trail::<u32>::new(2);

    trail.follow(&ROOT, &user(7)).unwrap();

    assert_eq!(trail.led_by(), Some(&7));
}
