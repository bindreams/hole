use super::*;

use cosca::identity::Resolved;

#[skuld::test]
fn the_death_watch_returns_when_a_live_predecessor_exits() {
    // Waiting on an external process's exit is the sanctioned timing exception.
    // The residual: a `wait` broken in the "never returns" direction hangs, and
    // no assertion can convert that into a clean failure without a timeout. The
    // PASS case is prompt — the child exits as soon as the control socket
    // closes.
    let mut child = crate::test_child::HoldChild::spawn();
    let pid = child.pid();

    // The precondition the whole pid-reuse duty rests on, asserted rather than
    // assumed: a child that died early would otherwise steer this into the
    // vacuous `Gone` arm.
    let Resolved::Found(predecessor) = cosca::Process::from_pid(pid) else {
        panic!("the predecessor must be alive when its identity is read");
    };
    child.release();

    let mut out = Vec::new();
    handshake_then_wait(pid, Resolved::Found(predecessor), &mut out).expect("the death watch must return Ok");
    assert_eq!(out, b"READY\n");
}

#[skuld::test]
fn a_gone_predecessor_still_completes_the_handshake() {
    let mut out = Vec::new();
    handshake_then_wait(4242, Resolved::Gone, &mut out).expect("a gone predecessor is nothing to wait for");
    assert_eq!(out, b"READY\n");
}

#[skuld::test]
fn an_unassessable_predecessor_still_completes_the_handshake() {
    // Treating this as an error would never print READY, so the predecessor's
    // `read_line` would never return and the handoff would break. Treating it
    // as `Found` is not even expressible — `Unknown` carries no `Process`.
    let mut out = Vec::new();
    handshake_then_wait(4242, Resolved::Unknown, &mut out)
        .expect("an unassessable predecessor must not fail the handoff");
    assert_eq!(out, b"READY\n");
}

// Successor handoff: a relaunch reproduces the predecessor's window state using
// signals every shipped build handles — an argv flag all versions accept, and an
// env var older versions ignore.

#[skuld::test]
fn showing_uses_an_argv_flag_every_build_accepts() {
    assert_eq!(super::successor_args(true), [crate::launch::SHOW_DASHBOARD]);
}

#[skuld::test]
fn suppressing_passes_no_argv() {
    // An older successor would reject an unknown flag at parse and never arm.
    assert!(super::successor_args(false).is_empty());
}

#[skuld::test]
fn suppressing_sets_the_env_var() {
    assert_eq!(super::successor_env(false), Some(crate::launch::NO_DASHBOARD_ENV));
}

#[skuld::test]
fn showing_sets_no_env_var() {
    assert!(super::successor_env(true).is_none());
}
