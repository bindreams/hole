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

#[skuld::test]
fn windows_elevated_no_linked_token_warns_not_hard_fails_even_under_ci() {
    // GitHub-hosted Windows runners are elevated but expose no UAC-split linked
    // token, so there is nothing to de-elevate to. Windows has no root-owned-file
    // hazard, so this must NOT trip the (POSIX-only) CI hard-fail — it warns and
    // runs the step as-is. Regression guard for the Windows-CI breakage.
    let h = host(true, None, true, false, ElevateStrategy::Windows);
    assert!(matches!(h.plan(Privilege::Unprivileged), Transition::WarnVacuous(_)));
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

    // The DROPPED (unprivileged) child must be able to write the output. A
    // `tempfile::tempdir()` is created by this root process at 0700 — and under
    // sudo the platform temp dir can be root-owned 0700 (macOS `/var/folders`),
    // untraversable by the dropped user. Use a pre-created world-writable file
    // in `/tmp` (1777 + sticky on both Linux and macOS): the dropped child can
    // truncate+write an existing 0666 file there with only directory traversal.
    use std::os::unix::fs::PermissionsExt;
    let out = std::path::PathBuf::from(format!("/tmp/hole-xtask-drop-{}.txt", std::process::id()));
    std::fs::write(&out, "").unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o666)).unwrap();

    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("id -u > {}", out.display()));
    let result = crate::privilege::run_command(&host, Privilege::Unprivileged, cmd, &Groups::Full, "id -u");
    let contents = std::fs::read_to_string(&out).ok();
    let _ = std::fs::remove_file(&out);

    result.unwrap();
    let got: u32 = contents
        .expect("dropped child produced no output")
        .trim()
        .parse()
        .unwrap();
    assert_eq!(got, uid, "child did not drop to the invoking user's uid");
}

// Unit test for the getgrnam-backed `group_gid` (the resolution path used by
// `Groups::Only`). Portable and root-free: resolve our own real primary gid,
// look up its group name via getgrgid, then assert group_gid(name) round-trips
// back to that gid. The negative lookup runs unconditionally.
#[cfg(unix)]
#[skuld::test]
fn group_gid_resolves_own_primary_group_and_misses_unknown() {
    use crate::privilege::posix::group_gid;
    use std::ffi::CStr;

    // SAFETY: getgid never fails and has no preconditions.
    let gid = unsafe { libc::getgid() };
    // SAFETY: getgrgid returns a pointer into static storage or null; we read
    // gr_name only while the (non-null) record is valid, before any other libc
    // call that could clobber the static buffer.
    let name: Option<String> = unsafe {
        let grp = libc::getgrgid(gid);
        if grp.is_null() {
            None
        } else {
            CStr::from_ptr((*grp).gr_name).to_str().ok().map(str::to_owned)
        }
    };

    // If the environment can resolve our primary group's name, the getgrnam
    // path must agree on the gid. (Some minimal containers lack a name for the
    // primary gid; tolerate that — it is not the unit under test.)
    if let Some(name) = name {
        assert_eq!(
            group_gid(&name),
            Some(gid),
            "group_gid({name:?}) must round-trip to the primary gid {gid}"
        );
    }

    // The not-found path is unconditional.
    assert_eq!(
        group_gid("hole-no-such-group-zzzzz"),
        None,
        "a nonexistent group name must resolve to None"
    );
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

// ===== Windows de-elevation effect tests =============================================================================

// These EFFECT tests need an ELEVATED process to exercise linked-token
// de-elevation. Labeled `windows_elevated`, they run by default (the elevated
// CI runner / `xtask-tests` target supplies elevation). Opt out locally with
// SKULD_LABELS="!windows_elevated". They do NOT use skuld's `requires` (which
// would mark the trial ignored — a green-build skip); they assert elevation and
// fail LOUDLY otherwise.
#[cfg(windows)]
#[skuld::label]
const WINDOWS_ELEVATED: skuld::Label;

#[cfg(windows)]
fn require_elevated() {
    let host = crate::privilege::Host::detect();
    assert!(
        host.elevated,
        "this test requires an elevated process (to obtain the linked token for de-elevation). \
         Run via the elevated `xtask-tests` target / the elevated CI runner, or opt out locally \
         with SKULD_LABELS=\"!windows_elevated\"."
    );
    assert!(
        host.invoking_user.is_some(),
        "elevated but no linked token available — cannot de-elevate. The runner must have \
         EnableLUA=1 with a linked (limited) token."
    );
}

// Drop effect: a child launched via the Unprivileged transition must land at
// Medium integrity, not High. We assert on the locale-independent integrity SID
// in `whoami /groups`: S-1-16-8192 (Medium) present, S-1-16-12288 (High) absent.
#[cfg(windows)]
#[skuld::test(labels = [WINDOWS_ELEVATED])]
fn de_elevate_drops_child_integrity_below_high() {
    use crate::privilege::{Groups, Host, Privilege};
    use std::process::Command;

    require_elevated();
    let host = Host::detect();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("groups.txt");
    // cmd's `>` redirect writes the file directly (not through our relay pipes),
    // proving the child ran AND letting us inspect its integrity SID.
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(format!("whoami /groups > \"{}\"", out.display()));
    crate::privilege::run_command(&host, Privilege::Unprivileged, cmd, &Groups::Full, "whoami /groups").unwrap();

    let groups = std::fs::read_to_string(&out).expect("child did not write its groups file");
    assert!(
        groups.contains("S-1-16-8192"),
        "de-elevated child is not at Medium integrity (no S-1-16-8192 in whoami /groups):\n{groups}"
    );
    assert!(
        !groups.contains("S-1-16-12288"),
        "de-elevated child is still at High integrity (S-1-16-12288 present):\n{groups}"
    );
}

// Suspend rendezvous: prove CREATE_SUSPENDED survives the seclogon round-trip.
// The proof is race-free — `ResumeThread` returns the thread's PREVIOUS suspend
// count, which is 1 for a CREATE_SUSPENDED thread and 0 if the flag was ignored.
// There is no byte-peek and no timing. We additionally confirm stdio works by
// reading a post-resume sentinel the child wrote to a file.
#[cfg(windows)]
#[skuld::test(labels = [WINDOWS_ELEVATED])]
fn de_elevate_creates_child_suspended() {
    use std::process::Command;

    require_elevated();

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("ran.txt");
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(format!("echo resumed > \"{}\"", sentinel.display()));

    let resume_count = crate::privilege::windows::de_elevate_for_test(&mut cmd, "suspend-proof").unwrap();
    assert_eq!(
        resume_count, 1,
        "ResumeThread returned previous suspend count {resume_count}, expected 1; \
         CREATE_SUSPENDED was not honored through seclogon"
    );

    // Stdio/exec actually worked: the child ran to completion past the resume.
    let body = std::fs::read_to_string(&sentinel).expect("child did not write its sentinel file");
    assert!(
        body.contains("resumed"),
        "sentinel file had unexpected content: {body:?}"
    );
}
