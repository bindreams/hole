use super::*;

const ROOT: Owner<u32> = Owner::Privileged;

fn user(id: u32) -> Owner<u32> {
    Owner::User(id)
}

/// What `Trail::end_at` says of a walk ending in a folder `owner` owns.
fn end_at(trail: &Trail<u32>, owner: Owner<u32>) -> Result<(), Refusal> {
    trail
        .end_at(|| Ok(owner))
        .map_err(|err| *Refusal::from_error(&err).expect("a refusal"))
}

/// What `Trail::create_in` says of creating in a folder `owner` owns.
fn create_in(trail: &Trail<u32>, owner: Owner<u32>) -> Result<(), Refusal> {
    trail
        .create_in(|| Ok(owner))
        .map_err(|err| *Refusal::from_error(&err).expect("a refusal"))
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

    assert_eq!(end_at(&trail, ROOT), Ok(()));
    assert_eq!(end_at(&trail, user(1)), Ok(()));
    assert_eq!(create_in(&trail, ROOT), Ok(()));
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

    assert_eq!(end_at(&trail, ROOT), Ok(()));
}

// end_at and create_in ------------------------------------------------------------------------------------------------

#[skuld::test]
fn a_walk_that_followed_a_users_link_ends_only_in_that_users_folder() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(end_at(&trail, user(1)), Ok(()));
    assert_eq!(end_at(&trail, ROOT), Err(Refusal::Symlink));
    assert_eq!(end_at(&trail, user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_walk_that_followed_a_users_link_creates_only_in_that_users_folder() {
    let mut trail = Trail::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();

    assert_eq!(create_in(&trail, user(1)), Ok(()));
    assert_eq!(create_in(&trail, ROOT), Err(Refusal::Symlink));
    assert_eq!(create_in(&trail, user(2)), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_walk_that_followed_no_users_link_ends_and_creates_anywhere() {
    let trail = Trail::<u32>::new(PLENTY);

    for folder in [ROOT, user(1)] {
        assert_eq!(end_at(&trail, folder.clone()), Ok(()));
        assert_eq!(create_in(&trail, folder), Ok(()));
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

// the owner is read only when it is judged ============================================================================

#[skuld::test]
fn a_walk_bound_to_no_one_never_reads_a_folders_owner() {
    let trail = Trail::<u32>::new(PLENTY);
    let unreadable = || Err(io::Error::from(io::ErrorKind::PermissionDenied));

    assert!(trail.end_at(unreadable).is_ok());
    assert!(trail.create_in(unreadable).is_ok());
}

#[skuld::test]
fn a_walk_bound_to_a_user_that_cannot_read_a_folders_owner_does_not_proceed() {
    let mut trail = Trail::<u32>::new(PLENTY);
    trail.follow(&ROOT, &user(1)).unwrap();
    let unreadable = || Err(io::Error::from(io::ErrorKind::PermissionDenied));

    assert_eq!(
        trail.end_at(unreadable).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}
