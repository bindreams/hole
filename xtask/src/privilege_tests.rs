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

// Effect test: actually drop and read back the child uid. Needs root; labeled
// `root`, runs by default (CI supplies root via the elevated xtask-tests
// target). Opt out locally with SKULD_LABELS="!root". Does NOT use skuld's
// `requires` (that marks the trial ignored — a green-build skip); asserts root
// and fails LOUDLY instead.
#[cfg(unix)]
#[skuld::label]
const ROOT: skuld::Label;

#[cfg(unix)]
#[skuld::test(labels = [ROOT])]
fn drop_actually_changes_uid() {
    use crate::privilege::{Groups, Host, InvokingUser, Privilege, Transition};
    use std::process::Command;

    // SAFETY: geteuid is always safe.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this test requires root. Run the elevated `xtask-tests` target (CI does this), \
         or opt out locally with SKULD_LABELS=\"!root\"."
    );

    let host = Host::detect();
    let uid = match &host.invoking_user {
        Some(InvokingUser::Posix { uid, .. }) => *uid,
        _ => panic!(
            "no invoking user resolved: set SUDO_USER or HOLE_BUILD_USER (the elevated \
             xtask-tests target runs under sudo, which sets SUDO_USER)"
        ),
    };
    assert!(matches!(host.plan(Privilege::Unprivileged), Transition::DropTo(_)));

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("uid.txt");
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("id -u > {}", out.display()));
    crate::privilege::run_command(&host, Privilege::Unprivileged, cmd, &Groups::Full, "id -u").unwrap();
    let got: u32 = std::fs::read_to_string(&out).unwrap().trim().parse().unwrap();
    assert_eq!(got, uid, "child did not drop to the invoking user's uid");
}

// ===== Windows quoter ================================================================================================

// The CommandLineToArgvW quoter must round-trip exactly: every arg we quote and
// join must parse back to the identical argv. Verified against the real Win32
// parser (runs on Windows only).
#[cfg(windows)]
#[skuld::test]
fn quoter_roundtrips_through_commandlinetoargvw() {
    use crate::privilege::win_quote::{cmdline_roundtrips, join_command_line};

    let cases: Vec<Vec<String>> = vec![
        vec![],
        vec!["plain".into()],
        vec!["a".into(), "b".into(), "c".into()],
        vec!["has spaces".into()],
        vec!["a\ttab".into()],
        vec!["embedded\"quote".into()],
        vec!["trailing\\".into()],
        vec!["two\\\\".into()],
        vec!["C:\\Program Files\\x\\".into()],
        vec!["quote\\\"and\\back".into()],
        vec![
            "build".into(),
            "--target".into(),
            "C:\\Program Files\\hole\\".into(),
            "with space".into(),
        ],
        vec!["".into(), "after-empty".into()],
    ];

    for argv in &cases {
        let cmdline = join_command_line(argv);
        assert!(
            cmdline_roundtrips(&cmdline, argv),
            "argv {argv:?} did not round-trip; produced cmdline {cmdline:?}"
        );
    }
}
