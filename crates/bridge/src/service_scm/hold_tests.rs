use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::*;
use crate::service_scm::call_error::{io_error_is_a_refused_process_open, ScmCall, ScmCallError};
use crate::service_scm::ReportedPid;

/// What the fake OS did, in order: `read`, `open(pid)`, `close(pid)`.
type Log = Rc<RefCell<Vec<String>>>;

/// A process whose drop is logged, so a handle that was let go shows in the log.
struct Handle {
    pid: u32,
    log: Log,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.log.borrow_mut().push(format!("close({})", self.pid));
    }
}

/// A source whose `read`s are scripted. A process is open to the fake whether
/// or not the script still names it; `gone` lists ids that no process has and
/// `strangers` ids whose process does not carry the service's SID.
struct Script {
    log: Log,
    reads: VecDeque<Reading>,
    gone: Vec<u32>,
    strangers: Vec<u32>,
    /// Ids of processes that are open but already signalled.
    exited: Vec<u32>,
    /// The basis each `open` was asked on, in order.
    bases: Vec<Basis>,
}

impl Script {
    fn new(log: &Log, reads: Vec<Reading>) -> Self {
        Self {
            log: log.clone(),
            reads: reads.into(),
            gone: vec![],
            strangers: vec![],
            exited: vec![],
            bases: vec![],
        }
    }
}

impl ProcessSource for Script {
    type Process = Handle;

    fn read(&mut self) -> io::Result<Reading> {
        self.log.borrow_mut().push("read".into());
        Ok(self.reads.pop_front().expect("read script ran dry"))
    }

    fn open(&mut self, pid: u32, basis: Basis) -> io::Result<Opened<Handle>> {
        self.log.borrow_mut().push(format!("open({pid})"));
        self.bases.push(basis);
        if self.gone.contains(&pid) {
            return Ok(Opened::NoSuchProcess);
        }
        let handle = Handle {
            pid,
            log: self.log.clone(),
        };
        if self.strangers.contains(&pid) {
            // Dropped here, as the real source drops a process it rejects.
            return Ok(Opened::NotTheService);
        }
        Ok(Opened::Service(handle))
    }

    fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
        Ok(self.exited.contains(&process.pid))
    }
}

fn reading(observed: Observed, pid: u32) -> Reading {
    Reading { observed, pid }
}

fn named_by(holds: &mut ProcessHolds<Handle>, source: &mut Script) -> Hold {
    holds.hold_current(source).unwrap()
}

fn held_pids(holds: &ProcessHolds<Handle>) -> Vec<u32> {
    holds.processes().map(|handle| handle.pid).collect()
}

#[skuld::test]
fn a_process_the_service_names_on_both_sides_of_the_open_is_held() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![reading(Observed::Running, 100), reading(Observed::Running, 100)],
    );
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::Running, 100));
    assert_eq!(held_pids(&holds), vec![100]);
    assert_eq!(*log.borrow(), vec!["read", "open(100)", "read"]);
}

#[skuld::test]
fn the_same_process_in_another_live_state_is_still_the_same_process() {
    // RUNNING -> STOP_PENDING keeps the process; the answer is the second look.
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![reading(Observed::Running, 100), reading(Observed::StopPending, 100)],
    );
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::StopPending, 100));
    assert_eq!(held_pids(&holds), vec![100]);
}

#[skuld::test]
fn a_service_that_became_stopped_between_the_look_and_the_open_holds_nothing() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![reading(Observed::Running, 100), reading(Observed::Stopped, 0)],
    );
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::Stopped, 0));
    assert!(held_pids(&holds).is_empty());
    // The opened handle was let go, and nothing was opened for the second look.
    assert_eq!(*log.borrow(), vec!["read", "open(100)", "read", "close(100)"]);
}

#[skuld::test]
fn a_stopped_service_confirms_nothing_even_if_it_still_reports_the_id() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![reading(Observed::Running, 100), reading(Observed::Stopped, 100)],
    );
    let mut holds = ProcessHolds::default();
    holds.hold_current(&mut source).unwrap();
    assert!(held_pids(&holds).is_empty());
    assert_eq!(count(&log, "close(100)"), 1);
}

#[skuld::test]
fn a_process_the_service_no_longer_names_after_the_open_is_dropped_and_the_new_one_held() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            // The id changed under the open: the handle may be a stranger's.
            reading(Observed::StartPending, 200),
            // Confirmed on the pass that followed.
            reading(Observed::Running, 200),
        ],
    );
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::Running, 200));
    assert_eq!(held_pids(&holds), vec![200]);
    assert_eq!(
        *log.borrow(),
        vec!["read", "open(100)", "read", "close(100)", "open(200)", "read"]
    );
}

#[skuld::test]
fn a_service_that_keeps_changing_process_is_followed_until_it_holds_still() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 1),
            reading(Observed::Running, 2),
            reading(Observed::Running, 3),
            reading(Observed::Running, 4),
            reading(Observed::Running, 5),
            reading(Observed::Running, 5),
        ],
    );
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::Running, 5));
    assert_eq!(held_pids(&holds), vec![5]);
}

/// 100 is dropped for 200, and 200 for 100: a dropped id is opened afresh when
/// the service names it again, and the last confirmed one is held.
#[skuld::test]
fn a_process_dropped_as_unconfirmed_is_opened_afresh_when_the_service_names_it_again() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 200),
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.hold_current(&mut source).unwrap();
    assert_eq!(held_pids(&holds), vec![100]);
    assert_eq!(
        *log.borrow(),
        vec![
            "read",
            "open(100)",
            "read",
            "close(100)",
            "open(200)",
            "read",
            "close(200)",
            "open(100)",
            "read"
        ]
    );
}

#[skuld::test]
fn a_stopped_service_holds_nothing_and_opens_nothing() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::Stopped, 0)]);
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::Stopped, 0));
    assert_eq!(*log.borrow(), vec!["read"]);
}

#[skuld::test]
fn a_live_state_that_names_no_process_holds_nothing_and_opens_nothing() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::StartPending, 0)]);
    let mut holds = ProcessHolds::default();
    holds.hold_current(&mut source).unwrap();
    assert_eq!(*log.borrow(), vec!["read"]);
}

#[skuld::test]
fn a_process_already_held_is_not_opened_again() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::StopPending, 100),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.hold_current(&mut source).unwrap();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::StopPending, 100));
    assert_eq!(held_pids(&holds), vec![100]);
    assert_eq!(count(&log, "open(100)"), 1);
}

#[skuld::test]
fn a_process_that_has_exited_before_the_open_is_not_held() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::StopPending, 100)]);
    source.gone.push(100);
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source).reading;
    assert_eq!(got, reading(Observed::StopPending, 100));
    assert!(held_pids(&holds).is_empty());
}

/// A process the SCM names but whose token lacks the service's SID is not the
/// service's: a reused id, or a service process the SID type never reached.
#[skuld::test]
fn a_process_without_the_service_sid_is_never_held() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![reading(Observed::Running, 100), reading(Observed::Running, 100)],
    );
    source.strangers.push(100);
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source);
    assert_eq!(got.reading, reading(Observed::Running, 100));
    assert_eq!(got.named, Named::NotTheService);
    assert!(held_pids(&holds).is_empty());
    // The source closes a rejected process as it returns it.
    assert_eq!(*log.borrow(), vec!["read", "open(100)", "close(100)", "read"]);
}

#[skuld::test]
fn a_process_without_the_service_sid_is_never_held_in_any_live_state() {
    for live in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, steady(live, 100));
        source.strangers.push(100);
        let (got, holds) = look_of(&mut source);
        assert_eq!(
            got,
            Look {
                observed: live,
                fate: ProcessFate::Unheld,
                held_alive: false,
                named_alive: false,
                ever_held: false
            },
            "{live:?}"
        );
        assert!(held_pids(&holds).is_empty(), "{live:?}");
    }
}

#[skuld::test]
fn a_service_that_moves_off_a_stranger_to_its_own_process_has_that_process_held() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 200),
            reading(Observed::Running, 200),
        ],
    );
    source.strangers.push(100);
    let mut holds = ProcessHolds::default();
    let got = named_by(&mut holds, &mut source);
    assert_eq!(got.reading, reading(Observed::Running, 200));
    assert_eq!(got.named, Named::Held);
    assert_eq!(held_pids(&holds), vec![200]);
    assert_eq!(count(&log, "close(100)"), 1);
}

#[skuld::test]
fn a_stranger_is_not_confused_with_a_process_that_has_exited() {
    // The two answers lead to opposite drains: a gone id finishes the wait, a
    // live stranger must not.
    let log = Log::default();
    let mut gone = Script::new(&log, vec![reading(Observed::Running, 100)]);
    gone.gone.push(100);
    assert_eq!(
        named_by(&mut ProcessHolds::default(), &mut gone).named,
        Named::NoSuchProcess
    );
    let mut stranger = Script::new(&log, steady(Observed::Running, 100));
    stranger.strangers.push(100);
    assert_eq!(
        named_by(&mut ProcessHolds::default(), &mut stranger).named,
        Named::NotTheService
    );
}

#[skuld::test]
fn a_look_that_names_no_process_names_nothing() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::Stopped, 100)]);
    assert_eq!(
        named_by(&mut ProcessHolds::default(), &mut source).named,
        Named::Nothing
    );
}

#[skuld::test]
fn a_failed_read_after_the_open_is_an_error_and_the_handle_is_let_go() {
    struct FailsSecondRead(Script, usize);
    impl ProcessSource for FailsSecondRead {
        type Process = Handle;
        fn read(&mut self) -> io::Result<Reading> {
            self.1 += 1;
            if self.1 == 2 {
                return Err(io::Error::other("query failed"));
            }
            self.0.read()
        }
        fn open(&mut self, pid: u32, basis: Basis) -> io::Result<Opened<Handle>> {
            self.0.open(pid, basis)
        }
        fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
            self.0.has_exited(process)
        }
    }
    let log = Log::default();
    let mut source = FailsSecondRead(Script::new(&log, vec![reading(Observed::Running, 100)]), 0);
    let mut holds = ProcessHolds::default();
    assert!(holds.hold_current(&mut source).is_err());
    assert!(held_pids(&holds).is_empty());
    assert_eq!(count(&log, "close(100)"), 1);
}

#[skuld::test]
fn only_a_state_with_a_process_names_one_to_hold() {
    // From the SCM's contract: STOPPED has no process (dwProcessId is 0);
    // START_PENDING, RUNNING and STOP_PENDING have one.
    assert_eq!(reading(Observed::Stopped, 0).process_to_hold(), None);
    assert_eq!(reading(Observed::Stopped, 7).process_to_hold(), None);
    for live in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        assert_eq!(reading(live, 7).process_to_hold(), Some(7), "{live:?}");
        assert_eq!(reading(live, 0).process_to_hold(), None, "{live:?} with no id");
    }
}

fn count(log: &Log, entry: &str) -> usize {
    log.borrow().iter().filter(|e| *e == entry).count()
}

fn look_of(source: &mut Script) -> (Look, ProcessHolds<Handle>) {
    let mut holds = ProcessHolds::default();
    let got = holds.look(source).unwrap();
    (got, holds)
}

fn steady(observed: Observed, pid: u32) -> Vec<Reading> {
    vec![reading(observed, pid), reading(observed, pid)]
}

#[skuld::test]
fn a_held_process_that_has_not_exited_is_alive_whatever_the_state() {
    for live in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, steady(live, 100));
        let (got, _) = look_of(&mut source);
        assert_eq!(
            got,
            Look {
                observed: live,
                fate: ProcessFate::Alive,
                held_alive: true,
                named_alive: true,
                ever_held: true
            },
            "{live:?}"
        );
    }
}

/// The SCM can still say RUNNING for a process that has gone; the held handle
/// is the ground truth. In START_PENDING and STOP_PENDING the id "may not be
/// valid", so the exit of the process held under it says nothing about the
/// service: the fate rests on the SCM's own transition.
#[skuld::test]
fn a_held_process_that_has_exited_is_an_exit_only_where_the_id_is_valid() {
    let table = [
        (Observed::Running, ProcessFate::Exited),
        (Observed::StartPending, ProcessFate::Unheld),
        (Observed::StopPending, ProcessFate::Unheld),
    ];
    for (stale, fate) in table {
        let log = Log::default();
        let mut source = Script::new(&log, steady(stale, 100));
        source.exited.push(100);
        let (got, holds) = look_of(&mut source);
        assert_eq!(
            got,
            Look {
                observed: stale,
                fate,
                held_alive: false,
                named_alive: false,
                ever_held: true
            },
            "{stale:?}"
        );
        // Still held: the final wait is on it.
        assert_eq!(held_pids(&holds), vec![100], "{stale:?}");
    }
}

/// RUNNING is a state whose id Microsoft documents as valid, so an id no
/// process has there is the service's process having exited.
#[skuld::test]
fn a_running_service_whose_named_id_no_process_has_is_exited() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::Running, 100)]);
    source.gone.push(100);
    let (got, holds) = look_of(&mut source);
    assert_eq!(got.fate, ProcessFate::Exited);
    assert!(held_pids(&holds).is_empty());
}

/// In START_PENDING and STOP_PENDING Microsoft documents that the id "may not be
/// valid", so an id no process has says nothing about the service's process,
/// which may be alive: the look rests on the SCM's own transition.
#[skuld::test]
fn a_pending_service_whose_named_id_no_process_has_is_unheld_not_exited() {
    for pending in [Observed::StartPending, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, vec![reading(pending, 100)]);
        source.gone.push(100);
        let (got, holds) = look_of(&mut source);
        assert_eq!(
            got,
            Look {
                observed: pending,
                fate: ProcessFate::Unheld,
                held_alive: false,
                named_alive: false,
                ever_held: false
            },
            "{pending:?}"
        );
        assert!(held_pids(&holds).is_empty(), "{pending:?}");
    }
}

/// The SCM reports STOPPED while the process it had named is still running;
/// a look that names nothing still says a hold is alive.
#[skuld::test]
fn a_stopped_service_whose_earlier_process_still_runs_has_a_live_hold() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::Stopped, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    let got = holds.look(&mut source).unwrap();
    assert_eq!(
        got,
        Look {
            observed: Observed::Stopped,
            fate: ProcessFate::Unheld,
            held_alive: true,
            named_alive: true,
            ever_held: true
        }
    );
}

#[skuld::test]
fn a_stopped_service_whose_earlier_process_has_exited_has_no_live_hold() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::Stopped, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    source.exited.push(100);
    let got = holds.look(&mut source).unwrap();
    assert_eq!(
        got,
        Look {
            observed: Observed::Stopped,
            fate: ProcessFate::Unheld,
            held_alive: false,
            named_alive: false,
            ever_held: true
        }
    );
}

/// One process of two held is enough: `held_alive` is about every hold, not the
/// one the latest look names.
#[skuld::test]
fn a_live_hold_other_than_the_one_named_keeps_the_look_alive() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::Running, 200),
            reading(Observed::Running, 200),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    source.exited.push(200);
    let got = holds.look(&mut source).unwrap();
    assert_eq!(got.fate, ProcessFate::Exited);
    assert!(got.held_alive, "the first process, 100, is still held and not exited");
}

#[skuld::test]
fn a_look_that_names_no_process_has_an_unheld_fate() {
    for (observed, pid) in [
        (Observed::Stopped, 0),
        (Observed::Stopped, 7),
        (Observed::Running, 0),
        (Observed::StartPending, 0),
        (Observed::StopPending, 0),
    ] {
        let log = Log::default();
        let mut source = Script::new(&log, vec![reading(observed, pid)]);
        let (got, _) = look_of(&mut source);
        assert_eq!(got.fate, ProcessFate::Unheld, "{observed:?} pid {pid}");
    }
}

/// A process held from an earlier look is the ground truth for a later look
/// that names the same id, where that id is valid.
#[skuld::test]
fn a_process_held_earlier_and_since_exited_is_exited_on_a_later_look_naming_a_valid_id() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    assert_eq!(holds.look(&mut source).unwrap().fate, ProcessFate::Alive);
    source.exited.push(100);
    source.reads.push_back(reading(Observed::Running, 100));
    let got = holds.look(&mut source).unwrap();
    assert_eq!(got.fate, ProcessFate::Exited);
}

/// Under an id that may not be valid the same exit says nothing about the
/// service.
#[skuld::test]
fn a_process_held_earlier_and_since_exited_is_unheld_on_a_later_look_naming_an_invalid_able_id() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    source.exited.push(100);
    source.reads.push_back(reading(Observed::StopPending, 100));
    let got = holds.look(&mut source).unwrap();
    assert_eq!(got.observed, Observed::StopPending);
    assert_eq!(got.fate, ProcessFate::Unheld);
    assert!(!got.held_alive);
}

#[skuld::test]
fn a_failed_exit_check_is_an_error() {
    struct FailsCheck(Script);
    impl ProcessSource for FailsCheck {
        type Process = Handle;
        fn read(&mut self) -> io::Result<Reading> {
            self.0.read()
        }
        fn open(&mut self, pid: u32, basis: Basis) -> io::Result<Opened<Handle>> {
            self.0.open(pid, basis)
        }
        fn has_exited(&mut self, _: &Handle) -> io::Result<bool> {
            Err(io::Error::other("wait failed"))
        }
    }
    let log = Log::default();
    let mut source = FailsCheck(Script::new(&log, steady(Observed::Running, 100)));
    assert!(ProcessHolds::default().look(&mut source).is_err());
}

// The per-failure table ===============================================================================================

/// What a probe that failed with `failure` resolves to, per basis. Written out
/// from the contract: the id of a RUNNING service is documented valid, so a
/// process the SCM names there that cannot be opened or read is one the
/// uninstall cannot let go of; where the id "may not be valid" a denial is a
/// stranger that reused it, but an unexpected failure is not; a blind scan of
/// the host has no prior that a process is the service's, so nothing but a
/// missing process is decided from a failure, and an unknown code is reported.
#[skuld::test]
fn the_verdict_for_every_basis_and_failure() {
    use ProbeFailure::{AccessDenied, NoSuchProcess, Other};
    use Verdict::{Fatal, Gone, NotOurs, Undetermined};
    let table = [
        (Basis::Named(ReportedPid::Valid), NoSuchProcess, Gone),
        (Basis::Named(ReportedPid::Valid), AccessDenied, Fatal),
        (Basis::Named(ReportedPid::Valid), Other, Fatal),
        (Basis::Named(ReportedPid::MayBeInvalid), NoSuchProcess, Gone),
        (Basis::Named(ReportedPid::MayBeInvalid), AccessDenied, NotOurs),
        (Basis::Named(ReportedPid::MayBeInvalid), Other, Fatal),
        (Basis::Scanned, NoSuchProcess, Gone),
        (Basis::Scanned, AccessDenied, NotOurs),
        (Basis::Scanned, Other, Undetermined),
    ];
    for (basis, failure, want) in table {
        assert_eq!(basis.verdict(failure), want, "{basis:?} {failure:?}");
    }
}

/// A state with no process names none, so a probe on that basis is a bug.
#[skuld::test]
#[should_panic(expected = "names no process")]
fn a_probe_on_a_state_that_names_no_process_is_a_contract_violation() {
    Basis::Named(ReportedPid::Never).verdict(ProbeFailure::AccessDenied);
}

fn typed(call: ScmCall, code: u32) -> io::Error {
    ScmCallError { call, code }.into_io()
}

#[skuld::test]
fn a_failure_is_classified_once_from_the_call_and_its_win32_code() {
    let table = [
        // OpenProcess answers a pid no process has with ERROR_INVALID_PARAMETER.
        (ScmCall::OpenProcess, 87, ProbeFailure::NoSuchProcess),
        (ScmCall::OpenProcess, 5, ProbeFailure::AccessDenied),
        (ScmCall::OpenProcessToken, 5, ProbeFailure::AccessDenied),
        (ScmCall::GetTokenInformation, 5, ProbeFailure::AccessDenied),
        (ScmCall::OpenProcess, 1, ProbeFailure::Other),
        // 87 from a call on a handle already open names no missing process.
        (ScmCall::OpenProcessToken, 87, ProbeFailure::Other),
        (ScmCall::GetTokenInformation, 87, ProbeFailure::Other),
    ];
    for (call, code, want) in table {
        assert_eq!(ProbeFailure::of_error(&typed(call, code)), want, "{call:?} {code}");
    }
    assert_eq!(
        ProbeFailure::of_error(&io::Error::other("untyped")),
        ProbeFailure::Other
    );
}

/// Every verdict becomes the outcome the hold acts on; only a fatal one is an
/// error, and it is the error the probe failed with.
#[skuld::test]
fn a_failed_probe_resolves_by_the_basis_table() {
    let valid = Basis::Named(ReportedPid::Valid);
    let may_be_invalid = Basis::Named(ReportedPid::MayBeInvalid);
    let denied = || typed(ScmCall::OpenProcess, 5);

    assert!(matches!(
        Opened::<()>::of_failure(valid, typed(ScmCall::OpenProcess, 87)),
        Ok(Opened::NoSuchProcess)
    ));
    assert!(matches!(
        Opened::<()>::of_failure(may_be_invalid, denied()),
        Ok(Opened::NotTheService)
    ));
    assert!(matches!(
        Opened::<()>::of_failure(Basis::Scanned, denied()),
        Ok(Opened::NotTheService)
    ));
    let fatal = Opened::<()>::of_failure(valid, denied()).expect_err("fatal");
    assert!(io_error_is_a_refused_process_open(&fatal), "{fatal}");
    assert!(matches!(
        Opened::<()>::of_failure(Basis::Scanned, typed(ScmCall::GetTokenInformation, 1)),
        Ok(Opened::Undetermined { code: Some(1) })
    ));
}

/// The id is a claim in proportion to the state it was read in, and the open
/// is told which.
#[skuld::test]
fn the_open_is_given_the_basis_of_the_state_the_id_was_read_in() {
    let table = [
        (Observed::Running, Basis::Named(ReportedPid::Valid)),
        (Observed::StartPending, Basis::Named(ReportedPid::MayBeInvalid)),
        (Observed::StopPending, Basis::Named(ReportedPid::MayBeInvalid)),
    ];
    for (observed, basis) in table {
        let log = Log::default();
        let mut source = Script::new(&log, steady(observed, 100));
        look_of(&mut source);
        assert_eq!(source.bases, vec![basis], "{observed:?}");
    }
}

/// A source whose every open fails the way a denied token read does.
struct DeniedToken(Script);

impl ProcessSource for DeniedToken {
    type Process = Handle;
    fn read(&mut self) -> io::Result<Reading> {
        self.0.read()
    }
    fn open(&mut self, _: u32, basis: Basis) -> io::Result<Opened<Handle>> {
        Opened::of_failure(basis, typed(ScmCall::OpenProcessToken, 5))
    }
    fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
        self.0.has_exited(process)
    }
}

/// A token the uninstall cannot read on a process the SCM names while the id is
/// valid fails the look with the open's own error, and holds nothing.
#[skuld::test]
fn a_denied_token_on_a_valid_id_ends_the_look_with_a_refused_open() {
    let log = Log::default();
    let mut source = DeniedToken(Script::new(&log, vec![reading(Observed::Running, 100)]));
    let mut holds = ProcessHolds::default();
    let error = holds.look(&mut source).expect_err("a denied token in RUNNING is fatal");
    assert!(io_error_is_a_refused_process_open(&error), "{error}");
    assert!(held_pids(&holds).is_empty());
}

/// Where the id may name a stranger, the same denial is that stranger.
#[skuld::test]
fn a_denied_token_on_an_id_that_may_be_invalid_is_a_stranger() {
    for pending in [Observed::StartPending, Observed::StopPending] {
        let log = Log::default();
        let mut source = DeniedToken(Script::new(&log, steady(pending, 100)));
        let got = ProcessHolds::default()
            .look(&mut source)
            .expect("a stranger is not an error");
        assert_eq!(got.fate, ProcessFate::Unheld, "{pending:?}");
    }
}

/// A scan-only outcome cannot come back for an id the SCM named.
#[skuld::test]
#[should_panic(expected = "Basis::verdict")]
fn an_undetermined_outcome_for_an_id_the_scm_named_is_a_contract_violation() {
    struct Undetermined;
    impl ProcessSource for Undetermined {
        type Process = Handle;
        fn read(&mut self) -> io::Result<Reading> {
            Ok(reading(Observed::Running, 100))
        }
        fn open(&mut self, _: u32, _: Basis) -> io::Result<Opened<Handle>> {
            Ok(Opened::Undetermined { code: Some(1) })
        }
        fn has_exited(&mut self, _: &Handle) -> io::Result<bool> {
            unreachable!()
        }
    }
    let _ = ProcessHolds::default().hold_current(&mut Undetermined);
}

// A live process that fails the SID check =============================================================================

/// Runs `f` under a per-test subscriber and returns what it logged.
fn logged_during(f: impl FnOnce()) -> String {
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = set_default_in_current_thread(subscriber);
    f();
    writer.snapshot()
}

/// In RUNNING the id is documented valid, so a live process there that is not
/// the service's means nothing of the service will be waited on: said once,
/// with the id and the state.
#[skuld::test]
fn a_valid_state_process_that_fails_the_sid_check_is_logged_with_its_pid_and_state() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 4242));
    source.strangers.push(4242);
    let logged = logged_during(|| {
        look_of(&mut source);
    });
    assert!(logged.contains("WARN"), "{logged:?}");
    assert!(logged.contains("4242"), "{logged:?}");
    assert!(logged.contains("Running"), "{logged:?}");
}

/// Where the id may name anything, a process that fails the check is the
/// expected case and says nothing.
#[skuld::test]
fn a_may_be_invalid_state_process_that_fails_the_sid_check_logs_nothing() {
    for pending in [Observed::StartPending, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, steady(pending, 4242));
        source.strangers.push(4242);
        let logged = logged_during(|| {
            look_of(&mut source);
        });
        assert_eq!(logged, "", "{pending:?}");
    }
}

// Holding what a scan finds ===========================================================================================

fn process(log: &Log, pid: u32) -> Handle {
    Handle { pid, log: log.clone() }
}

/// A process the scan adopts is one the holds have, so the next look sees it.
#[skuld::test]
fn a_process_adopted_from_a_scan_is_held_and_shows_in_the_next_look() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![reading(Observed::Stopped, 0), reading(Observed::Stopped, 0)]);
    let mut holds = ProcessHolds::default();
    let before = holds.look(&mut source).unwrap();
    assert!(!before.ever_held && !before.held_alive);

    holds.adopt(300, process(&log, 300));
    assert_eq!(held_pids(&holds), vec![300]);
    let after = holds.look(&mut source).unwrap();
    assert!(after.held_alive, "the adopted process has not exited");
    assert!(after.ever_held);
    assert_eq!(after.fate, ProcessFate::Unheld, "a STOPPED look names no process");
}

#[skuld::test]
fn a_process_adopted_twice_or_already_held_is_kept_once() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    holds.adopt(100, process(&log, 100));
    holds.adopt(300, process(&log, 300));
    holds.adopt(300, process(&log, 300));
    assert_eq!(held_pids(&holds), vec![100, 300]);
    // The redundant handles were let go, the held ones were not.
    assert_eq!(count(&log, "close(100)"), 1);
    assert_eq!(count(&log, "close(300)"), 1);
}

/// Having held something is remembered after it has exited.
#[skuld::test]
fn ever_held_outlasts_the_exit_of_everything_held() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::Stopped, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    source.exited.push(100);
    let got = holds.look(&mut source).unwrap();
    assert!(got.ever_held);
    assert!(!got.held_alive);
}

// Which held processes are orphans ====================================================================================

fn orphan_pids(holds: &ProcessHolds<Handle>) -> Vec<u32> {
    holds.orphans().map(|(pid, _)| pid).collect()
}

/// The service's own process, named while the SCM still said RUNNING, is told
/// to stop by the SCM and waited on whatever happens after; a process only a
/// scan found is nobody's to stop.
#[skuld::test]
fn only_a_process_a_scan_found_is_an_orphan() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    holds.adopt(300, process(&log, 300));
    assert_eq!(held_pids(&holds), vec![100, 300]);
    assert_eq!(orphan_pids(&holds), vec![300]);
}

/// The SCM naming a process a scan found first makes it the service's own.
#[skuld::test]
fn a_scanned_process_the_scm_names_later_is_not_an_orphan() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.adopt(100, process(&log, 100));
    holds.adopt(300, process(&log, 300));
    assert_eq!(orphan_pids(&holds), vec![100, 300]);
    holds.look(&mut source).unwrap();
    assert_eq!(
        held_pids(&holds),
        vec![100, 300],
        "the named process is the one already held"
    );
    assert_eq!(orphan_pids(&holds), vec![300]);
}

/// A scan that finds the process the SCM named does not demote it.
#[skuld::test]
fn a_named_process_a_scan_finds_again_stays_the_services() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    holds.adopt(100, process(&log, 100));
    assert!(orphan_pids(&holds).is_empty());
}

/// An id the SCM names in START_PENDING or STOP_PENDING "may not be valid": it
/// is a claim, so it does not make a process a scan found the service's own.
#[skuld::test]
fn a_scanned_process_named_in_a_pending_state_stays_an_orphan() {
    for pending in [Observed::StartPending, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, steady(pending, 100));
        let mut holds = ProcessHolds::default();
        holds.adopt(100, process(&log, 100));
        holds.look(&mut source).unwrap();
        assert_eq!(orphan_pids(&holds), vec![100], "{pending:?}");
    }
}

/// A look tells the processes the SCM named from the others: an orphan alive
/// leaves `held_alive` set and `named_alive` clear, and the other way round.
#[skuld::test]
fn a_look_tells_a_live_named_process_from_a_live_orphan() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::StopPending, 0),
            reading(Observed::StopPending, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    holds.adopt(300, process(&log, 300));

    source.exited.push(100);
    let only_orphan = holds.look(&mut source).unwrap();
    assert!(only_orphan.held_alive && !only_orphan.named_alive, "{only_orphan:?}");

    source.exited.clear();
    source.exited.push(300);
    let only_named = holds.look(&mut source).unwrap();
    assert!(only_named.held_alive && only_named.named_alive, "{only_named:?}");
}

/// A wait on the processes' own exit covers the ones the SCM told to stop; the
/// terminating wait covers every one.
#[skuld::test]
fn a_wait_covers_the_processes_its_kind_covers() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    holds.adopt(300, process(&log, 300));
    let pids = |wait| holds.awaited(wait).map(|handle| handle.pid).collect::<Vec<_>>();
    assert_eq!(pids(ExitWait::OnTheirOwn), vec![100]);
    assert_eq!(pids(ExitWait::TerminateOrphansThenWait), vec![100, 300]);
}

/// What a wait after `look` does to the holds: the pids it terminates, then
/// the pids it waits on. The same two reads `ServiceProcesses::await_exits`
/// makes, off the wait the look asks for.
fn wait_plan(holds: &ProcessHolds<Handle>, look: Look) -> (Vec<u32>, Vec<u32>) {
    let wait = look.exit_wait();
    let terminated = if wait.terminates_orphans() {
        orphan_pids(holds)
    } else {
        Vec::new()
    };
    let waited = holds.awaited(wait).map(|handle| handle.pid).collect();
    (terminated, waited)
}

/// A process first held on an id the SCM named in a pending state (an id that
/// "may not be valid") may be a SID-carrying stranger that took the id: it is
/// waited on while the service is not STOPPED, as the real service mid-stop
/// would be, and ended at STOPPED, when only process exit remains.
#[skuld::test]
fn a_process_held_on_a_pending_claim_is_waited_on_until_stopped_then_terminated() {
    for pending in [Observed::StartPending, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(
            &log,
            vec![
                // The first look reads twice (open, then confirm); a held id once.
                reading(pending, 100),
                reading(pending, 100),
                reading(pending, 100),
                reading(Observed::Stopped, 0),
            ],
        );
        let mut holds = ProcessHolds::default();
        let held = holds.look(&mut source).unwrap();
        assert_eq!(
            wait_plan(&holds, held),
            (vec![], vec![100]),
            "{pending:?} before STOPPED"
        );
        let again = holds.look(&mut source).unwrap();
        assert_eq!(
            wait_plan(&holds, again),
            (vec![], vec![100]),
            "{pending:?}, held already"
        );
        let stopped = holds.look(&mut source).unwrap();
        assert_eq!(stopped.observed, Observed::Stopped);
        assert_eq!(
            wait_plan(&holds, stopped),
            (vec![100], vec![100]),
            "{pending:?} at STOPPED: ended, then waited on"
        );
    }
}

/// A process held on a RUNNING claim, whose id is valid, is the service's own:
/// never terminated, at STOPPED or before.
#[skuld::test]
fn a_process_held_on_a_running_claim_is_never_terminated() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::Running, 100),
            reading(Observed::Running, 100),
            reading(Observed::Stopped, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    let running = holds.look(&mut source).unwrap();
    assert_eq!(wait_plan(&holds, running), (vec![], vec![100]));
    let stopped = holds.look(&mut source).unwrap();
    assert_eq!(wait_plan(&holds, stopped), (vec![], vec![100]));
}

/// A claim made in a pending state is settled by the valid one that follows
/// (START_PENDING, then RUNNING): the process is the service's own.
#[skuld::test]
fn a_pending_claim_is_settled_by_a_later_valid_one() {
    let log = Log::default();
    let mut source = Script::new(
        &log,
        vec![
            reading(Observed::StartPending, 100),
            reading(Observed::StartPending, 100),
            reading(Observed::Running, 100),
            reading(Observed::Stopped, 0),
        ],
    );
    let mut holds = ProcessHolds::default();
    holds.look(&mut source).unwrap();
    assert_eq!(orphan_pids(&holds), vec![100], "unproven while only claimed");
    holds.look(&mut source).unwrap();
    assert!(orphan_pids(&holds).is_empty(), "a valid claim makes it the service's");
    let stopped = holds.look(&mut source).unwrap();
    assert_eq!(wait_plan(&holds, stopped), (vec![], vec![100]));
}

// Whether anything held is still alive ================================================================================

#[skuld::test]
fn any_alive_is_true_while_a_held_process_has_not_exited() {
    let log = Log::default();
    let mut source = Script::new(&log, vec![]);
    let mut holds = ProcessHolds::default();
    assert!(
        !holds.any_alive(|p| source.has_exited(p)).unwrap(),
        "nothing held is nothing alive"
    );

    holds.adopt(100, process(&log, 100));
    holds.adopt(300, process(&log, 300));
    assert!(holds.any_alive(|p| source.has_exited(p)).unwrap());
    source.exited.push(100);
    assert!(
        holds.any_alive(|p| source.has_exited(p)).unwrap(),
        "one process exiting leaves the other alive"
    );
    source.exited.push(300);
    assert!(!holds.any_alive(|p| source.has_exited(p)).unwrap());
}

#[skuld::test]
fn a_failed_exit_check_ends_any_alive_with_that_error() {
    let log = Log::default();
    let mut holds = ProcessHolds::default();
    holds.adopt(100, process(&log, 100));
    let error = holds
        .any_alive(|_| Err(io::Error::other("no state")))
        .expect_err("the check failed");
    assert_eq!(error.to_string(), "no state");
}
