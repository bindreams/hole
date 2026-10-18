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
/// or not the script still names it; `gone` lists ids that no process has.
struct Script {
    log: Log,
    reads: VecDeque<Reading>,
    gone: Vec<u32>,
}

impl Script {
    fn new(log: &Log, reads: Vec<Reading>) -> Self {
        Self {
            log: log.clone(),
            reads: reads.into(),
            gone: vec![],
        }
    }
}

impl ProcessSource for Script {
    type Process = Handle;

    fn read(&mut self) -> io::Result<Reading> {
        self.log.borrow_mut().push("read".into());
        Ok(self.reads.pop_front().expect("read script ran dry"))
    }

    fn open(&mut self, pid: u32) -> io::Result<Option<Handle>> {
        self.log.borrow_mut().push(format!("open({pid})"));
        if self.gone.contains(&pid) {
            return Ok(None);
        }
        Ok(Some(Handle {
            pid,
            log: self.log.clone(),
        }))
    }
}

fn reading(observed: Observed, pid: u32) -> Reading {
    Reading { observed, pid }
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
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
    let got = holds.hold_current(&mut source).unwrap();
    assert_eq!(got, reading(Observed::StopPending, 100));
    assert!(held_pids(&holds).is_empty());
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
        fn open(&mut self, pid: u32) -> io::Result<Option<Handle>> {
            self.0.open(pid)
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
