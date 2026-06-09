use std::path::PathBuf;

use crate::privilege::{ElevateStrategy, Host, InvokingUser, Privilege, Transition};

fn user() -> InvokingUser {
    InvokingUser::Posix {
        name: "alice".into(),
        uid: 501,
        gid: 20,
        home: PathBuf::from("/Users/alice"),
    }
}
fn host(elevated: bool, u: Option<InvokingUser>, is_ci: bool, has_tty: bool, strategy: ElevateStrategy) -> Host {
    Host {
        elevated,
        invoking_user: u,
        is_ci,
        has_tty,
        strategy,
    }
}

#[skuld::test]
fn unprivileged_target_unprivileged_runs_as_is() {
    for s in [ElevateStrategy::Posix, ElevateStrategy::Windows] {
        assert_eq!(
            host(false, None, false, true, s).plan(Privilege::Unprivileged),
            Transition::RunAsIs
        );
    }
}

#[skuld::test]
fn elevated_host_unprivileged_target_drops_to_user() {
    let h = host(true, Some(user()), false, true, ElevateStrategy::Posix);
    assert_eq!(h.plan(Privilege::Unprivileged), Transition::DropTo(user()));
}

#[skuld::test]
fn elevated_host_no_user_warns_vacuous_off_ci() {
    let h = host(true, None, false, true, ElevateStrategy::Posix);
    match h.plan(Privilege::Unprivileged) {
        Transition::WarnVacuous(m) => assert!(m.contains("HOLE_BUILD_USER")),
        o => panic!("expected WarnVacuous, got {o:?}"),
    }
}

#[skuld::test]
fn elevated_host_no_user_hard_fails_under_ci() {
    let h = host(true, None, true, false, ElevateStrategy::Posix);
    match h.plan(Privilege::Unprivileged) {
        Transition::HardFail(m) => assert!(m.contains("CI") && m.contains("HOLE_BUILD_USER")),
        o => panic!("expected HardFail, got {o:?}"),
    }
}

#[skuld::test]
fn elevated_target_elevated_host_runs_as_is() {
    for s in [ElevateStrategy::Posix, ElevateStrategy::Windows] {
        assert_eq!(
            host(true, Some(user()), false, true, s).plan(Privilege::Elevated),
            Transition::RunAsIs
        );
    }
}

#[skuld::test]
fn elevated_target_unprivileged_host_gains_privilege_per_strategy() {
    assert_eq!(
        host(false, None, false, true, ElevateStrategy::Posix).plan(Privilege::Elevated),
        Transition::ElevateChild
    );
    assert_eq!(
        host(false, None, false, true, ElevateStrategy::Windows).plan(Privilege::Elevated),
        Transition::SelfElevateProcess
    );
}

#[skuld::test]
fn ci_tripwire_requires_all_three_conditions() {
    // CI + elevated + user present → DropTo (a user to honor exists).
    assert_eq!(
        host(true, Some(user()), true, false, ElevateStrategy::Posix).plan(Privilege::Unprivileged),
        Transition::DropTo(user())
    );
    // Not CI + elevated + no user → WarnVacuous, not HardFail.
    assert!(matches!(
        host(true, None, false, false, ElevateStrategy::Posix).plan(Privilege::Unprivileged),
        Transition::WarnVacuous(_)
    ));
}
