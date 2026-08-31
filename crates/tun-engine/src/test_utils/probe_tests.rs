use std::io;

use super::{classify, classify_send, ProbeFate, SendFate};

fn err<T>(kind: io::ErrorKind) -> io::Result<T> {
    Err(io::Error::new(kind, "test"))
}

#[skuld::test]
fn a_successful_probe_is_delivered() {
    assert_eq!(classify(&io::Result::Ok(())), ProbeFate::Delivered);
}

/// The two shapes a firewall block takes. `PermissionDenied` is what a
/// Windows WFP deny at `ALE_AUTH_CONNECT` (`WSAEACCES`) surfaces as — the
/// kind whose misclassification made a real block read as a harness fault.
#[skuld::test]
fn a_blocked_probe_is_rejected_not_a_harness_fault() {
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::TimedOut] {
        assert_eq!(classify(&err::<()>(kind)), ProbeFate::Rejected(kind), "{kind:?}");
    }
}

/// Abort/reset/refused reach the stack too — an unanswered destination
/// produces them with no cover engaged at all, so none is a harness fault
/// either.
#[skuld::test]
fn reset_and_refused_are_rejected() {
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
    ] {
        assert_eq!(classify(&err::<()>(kind)), ProbeFate::Rejected(kind), "{kind:?}");
    }
}

/// Route/address-class failures say nothing about any cover, and the kind
/// must survive so the failure is diagnosable from the first run.
#[skuld::test]
fn a_probe_that_never_reached_the_stack_carries_its_kind() {
    for kind in [
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::AddrInUse,
        io::ErrorKind::InvalidInput,
    ] {
        assert_eq!(classify(&err::<()>(kind)), ProbeFate::NeverLeft(kind), "{kind:?}");
    }
}

#[skuld::test]
fn only_delivered_and_rejected_are_verdicts() {
    assert!(classify(&io::Result::Ok(())).is_verdict());
    assert!(classify(&err::<()>(io::ErrorKind::TimedOut)).is_verdict());
    assert!(!classify(&err::<()>(io::ErrorKind::NetworkUnreachable)).is_verdict());
}

/// [`classify_send`]'s whole reason to exist: a `send_to` `Ok` classifies as
/// `Accepted`, never as anything shaped like `ProbeFate::Delivered` — there
/// is no such variant on [`SendFate`] to reach for.
#[skuld::test]
fn a_successful_send_is_accepted_not_delivered() {
    assert_eq!(classify_send(&io::Result::Ok(())), SendFate::Accepted);
}

/// [`classify`] and [`classify_send`] must not drift into disjoint notions
/// of which `io::ErrorKind`s are a rejection versus a harness fault.
#[skuld::test]
fn classify_send_agrees_with_classify_on_every_error_kind() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::AddrInUse,
        io::ErrorKind::InvalidInput,
    ] {
        let probe_fate = classify(&err::<()>(kind));
        let send_fate = classify_send(&err::<()>(kind));
        assert_eq!(probe_fate.is_verdict(), send_fate.is_verdict(), "{kind:?}");
        match (probe_fate, send_fate) {
            (ProbeFate::Rejected(a), SendFate::Rejected(b)) => assert_eq!(a, b, "{kind:?}"),
            (ProbeFate::NeverLeft(a), SendFate::NeverLeft(b)) => assert_eq!(a, b, "{kind:?}"),
            (a, b) => panic!("{kind:?}: classify={a:?} classify_send={b:?} disagree in shape"),
        }
    }
}
