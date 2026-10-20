use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::*;

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
}

impl Script {
    fn new(log: &Log, reads: Vec<Reading>) -> Self {
        Self {
            log: log.clone(),
            reads: reads.into(),
            gone: vec![],
            strangers: vec![],
            exited: vec![],
        }
    }
}

impl ProcessSource for Script {
    type Process = Handle;

    fn read(&mut self) -> io::Result<Reading> {
        self.log.borrow_mut().push("read".into());
        Ok(self.reads.pop_front().expect("read script ran dry"))
    }

    fn open(&mut self, pid: u32) -> io::Result<Opened<Handle>> {
        self.log.borrow_mut().push(format!("open({pid})"));
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

#[skuld::test]
fn a_process_dropped_as_unconfirmed_stays_dropped_when_the_service_names_it_again() {
    // 100, then 200 (100 dropped), then 100 again after 200 was dropped too.
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
    assert_eq!(count(&log, "close(200)"), 1);
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
                held_alive: false
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
        fn open(&mut self, pid: u32) -> io::Result<Opened<Handle>> {
            self.0.open(pid)
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
                held_alive: true
            },
            "{live:?}"
        );
    }
}

/// The SCM can still say RUNNING or STOP_PENDING for a process that has gone;
/// the held handle is the ground truth.
#[skuld::test]
fn a_held_process_that_has_exited_is_exited_whatever_the_state_still_says() {
    for stale in [Observed::StartPending, Observed::Running, Observed::StopPending] {
        let log = Log::default();
        let mut source = Script::new(&log, steady(stale, 100));
        source.exited.push(100);
        let (got, holds) = look_of(&mut source);
        assert_eq!(
            got,
            Look {
                observed: stale,
                fate: ProcessFate::Exited,
                held_alive: false
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
                held_alive: false
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
            held_alive: true
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
            held_alive: false
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
/// that names the same id.
#[skuld::test]
fn a_process_held_earlier_and_since_exited_is_exited_on_a_later_look() {
    let log = Log::default();
    let mut source = Script::new(&log, steady(Observed::Running, 100));
    let mut holds = ProcessHolds::default();
    assert_eq!(holds.look(&mut source).unwrap().fate, ProcessFate::Alive);
    source.exited.push(100);
    source.reads.push_back(reading(Observed::StopPending, 100));
    let got = holds.look(&mut source).unwrap();
    assert_eq!(got.observed, Observed::StopPending);
    assert_eq!(got.fate, ProcessFate::Exited);
}

#[skuld::test]
fn a_failed_exit_check_is_an_error() {
    struct FailsCheck(Script);
    impl ProcessSource for FailsCheck {
        type Process = Handle;
        fn read(&mut self) -> io::Result<Reading> {
            self.0.read()
        }
        fn open(&mut self, pid: u32) -> io::Result<Opened<Handle>> {
            self.0.open(pid)
        }
        fn has_exited(&mut self, _: &Handle) -> io::Result<bool> {
            Err(io::Error::other("wait failed"))
        }
    }
    let log = Log::default();
    let mut source = FailsCheck(Script::new(&log, steady(Observed::Running, 100)));
    assert!(ProcessHolds::default().look(&mut source).is_err());
}
