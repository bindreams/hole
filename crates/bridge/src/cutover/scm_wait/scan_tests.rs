use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::*;
use crate::cutover::scm_wait::hold::ProcessHolds;

/// What the fake host did, in order: `open(pid)`, `close(pid)`.
type Log = Rc<RefCell<Vec<String>>>;

struct Handle {
    pid: u32,
    log: Log,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.log.borrow_mut().push(format!("close({})", self.pid));
    }
}

/// What opening a pid gives, per pid.
enum Process {
    Gone,
    Stranger,
    Service,
    ServiceExited,
    Undetermined(u32),
}

/// A host: the processes it lists and what each one is.
struct Host {
    log: Log,
    this: u32,
    processes: BTreeMap<u32, Process>,
    /// The creation time the listing gives an id; 0 unless set.
    created: BTreeMap<u32, u64>,
}

impl Host {
    fn new(this: u32, processes: Vec<(u32, Process)>) -> Self {
        Self {
            log: Log::default(),
            this,
            processes: processes.into_iter().collect(),
            created: BTreeMap::new(),
        }
    }

    /// The process the listing names `pid` as.
    fn listed(&self, pid: u32) -> ListedProcess {
        ListedProcess {
            pid,
            created: self.created.get(&pid).copied().unwrap_or(0),
        }
    }

    /// The OS hands `pid` to a new process, which is `what` and was created at
    /// `created`.
    fn reuse(&mut self, pid: u32, created: u64, what: Process) {
        self.processes.insert(pid, what);
        self.created.insert(pid, created);
    }
}

/// A process listed with creation time 0, the fake host's default.
fn listed(pid: u32) -> ListedProcess {
    ListedProcess { pid, created: 0 }
}

fn listed_all(pids: &[u32]) -> Vec<ListedProcess> {
    pids.iter().copied().map(listed).collect()
}

impl ProcessEnumerator for Host {
    type Process = Handle;

    fn list(&mut self) -> io::Result<Vec<ListedProcess>> {
        Ok(self.processes.keys().map(|pid| self.listed(*pid)).collect())
    }

    fn this_process(&self) -> u32 {
        self.this
    }

    fn open(&mut self, pid: u32) -> io::Result<Opened<Handle>> {
        self.log.borrow_mut().push(format!("open({pid})"));
        let handle = || Handle {
            pid,
            log: self.log.clone(),
        };
        Ok(match &self.processes[&pid] {
            Process::Gone => Opened::NoSuchProcess,
            Process::Stranger => Opened::NotTheService,
            Process::Service | Process::ServiceExited => Opened::Service(handle()),
            Process::Undetermined(code) => Opened::Undetermined { code: Some(*code) },
        })
    }

    fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
        Ok(matches!(self.processes[&process.pid], Process::ServiceExited))
    }
}

fn alive_pids(result: &ScanResult<Handle>) -> Vec<u32> {
    result.alive.iter().map(|(pid, _)| *pid).collect()
}

/// The scan keeps what carries the service's token and has not exited, and
/// nothing else.
#[skuld::test]
fn the_scan_holds_the_live_processes_that_carry_the_token() {
    let mut host = Host::new(
        1,
        vec![
            (2, Process::Stranger),
            (3, Process::Service),
            (4, Process::Gone),
            (5, Process::Service),
        ],
    );
    let result = scan(&mut host, &[]).unwrap();
    assert_eq!(alive_pids(&result), vec![3, 5]);
    assert!(result.undetermined.is_empty());
}

/// An exiting process still opens and still carries its token; it is no longer
/// something to wait for.
#[skuld::test]
fn a_process_that_has_exited_is_dropped_not_held() {
    let mut host = Host::new(1, vec![(3, Process::ServiceExited), (5, Process::Service)]);
    let result = scan(&mut host, &[]).unwrap();
    assert_eq!(alive_pids(&result), vec![5]);
    drop(result);
    assert_eq!(*host.log.borrow(), vec!["open(3)", "close(3)", "open(5)", "close(5)"]);
}

/// A listed id that no process has any more at its probe, or whose process has
/// exited by then, may have started a process after the listing: neither is
/// something to wait for, and neither is a scan that found nothing.
#[skuld::test]
fn a_listed_process_gone_or_exited_by_its_probe_is_reported_vanished() {
    let mut host = Host::new(
        1,
        vec![
            (2, Process::Stranger),
            (3, Process::Gone),
            (4, Process::ServiceExited),
            (5, Process::Undetermined(1117)),
        ],
    );
    let result = scan(&mut host, &[]).unwrap();
    assert!(result.alive.is_empty());
    assert_eq!(result.vanished, listed_all(&[3, 4]));
}

/// An id the listing names and no probe ever opens (a listing that names more
/// than the host runs) is vanished once; listed and unopenable again on the
/// next scan, it is not the service's and no reason for another pass. Without
/// this the wait scans for ever.
#[skuld::test]
fn an_id_listed_again_that_still_does_not_open_is_not_vanished_a_second_time() {
    for never_opens in [Process::Gone, Process::ServiceExited] {
        let mut host = Host::new(1, vec![(7, never_opens), (3, Process::Stranger)]);
        let first = scan(&mut host, &[]).unwrap();
        assert_eq!(first.vanished, listed_all(&[7]));
        assert_eq!(first.finding(), ScanFinding::Vanished);

        let second = scan(&mut host, &first.vanished).unwrap();
        assert!(second.vanished.is_empty());
        assert_eq!(second.finding(), ScanFinding::Nothing);
    }
}

/// The exemption is for the id as it was listed twice running: an id that was
/// vanished and is not listed now carries nothing, and an id that opens as the
/// service's is waited on whatever it did before.
#[skuld::test]
fn what_vanished_before_exempts_only_an_id_that_still_does_not_open() {
    let mut host = Host::new(1, vec![(3, Process::Service), (4, Process::Gone)]);
    let result = scan(&mut host, &listed_all(&[3, 4, 9])).unwrap();
    assert_eq!(alive_pids(&result), vec![3]);
    assert!(result.vanished.is_empty(), "4 stays exempt, 9 is not listed");
    assert_eq!(
        result.unprobeable,
        listed_all(&[4]),
        "and 4 is carried to the next scan"
    );
}

/// The exemption is for the process, not the id: the OS hands an id to a new
/// process, which the listing tells by its creation time, and that process can
/// have started a child after the listing and exited before its probe.
#[skuld::test]
fn an_id_given_to_a_new_process_that_does_not_open_is_vanished_again() {
    let mut host = Host::new(1, vec![(7, Process::Gone)]);
    host.created.insert(7, 100);
    let first = scan(&mut host, &[]).unwrap();
    assert_eq!(first.vanished, vec![ListedProcess { pid: 7, created: 100 }]);

    host.reuse(7, 200, Process::ServiceExited);
    let second = scan(&mut host, &first.unprobeable).unwrap();
    assert_eq!(
        second.vanished,
        vec![ListedProcess { pid: 7, created: 200 }],
        "a different process under the same id is not the one the last scan lost"
    );
    assert_eq!(second.finding(), ScanFinding::Vanished);

    let third = scan(&mut host, &second.unprobeable).unwrap();
    assert_eq!(
        third.finding(),
        ScanFinding::Nothing,
        "listed again as itself, it is exempt"
    );
}

/// An exempt id stays exempt while it is listed, however many scans, and a
/// vanishing of another id in between does not lift it.
#[skuld::test]
fn an_exempt_id_stays_exempt_while_other_ids_vanish_around_it() {
    let mut holds = ProcessHolds::default();
    let mut host = Host::new(1, vec![(7, Process::Gone)]);
    assert_eq!(holds.hold_scanned(&mut host).unwrap().finding, ScanFinding::Vanished);

    host.processes.insert(8, Process::Gone);
    assert_eq!(
        holds.hold_scanned(&mut host).unwrap().finding,
        ScanFinding::Vanished,
        "8 is new"
    );

    host.processes.remove(&8);
    assert_eq!(
        holds.hold_scanned(&mut host).unwrap().finding,
        ScanFinding::Nothing,
        "7 is exempt still"
    );
}

/// Only a scan that probed every listed process and found none of the service's
/// alive may end a wait.
#[skuld::test]
fn only_a_scan_that_found_nothing_and_lost_no_process_ends_the_wait() {
    let finding = |processes: Vec<(u32, Process)>| scan(&mut Host::new(1, processes), &[]).unwrap().finding();
    assert_eq!(finding(vec![]), ScanFinding::Nothing);
    assert_eq!(
        finding(vec![(2, Process::Stranger), (5, Process::Undetermined(1117))]),
        ScanFinding::Nothing
    );
    assert_eq!(finding(vec![(2, Process::Service)]), ScanFinding::Alive);
    assert_eq!(finding(vec![(2, Process::Gone)]), ScanFinding::Vanished);
    assert_eq!(finding(vec![(2, Process::ServiceExited)]), ScanFinding::Vanished);
    // A live process takes precedence: it is waited on, and the next scan follows.
    assert_eq!(
        finding(vec![(2, Process::Service), (3, Process::Gone)]),
        ScanFinding::Alive
    );
    for (finding, ends) in [
        (ScanFinding::Nothing, true),
        (ScanFinding::Alive, false),
        (ScanFinding::Vanished, false),
    ] {
        assert_eq!(finding.ends_the_wait(), ends, "{finding:?}");
    }
}

/// The calling process can carry the service's token (the cutover child
/// inherits the bridge's): it must not wait on itself.
#[skuld::test]
fn the_calling_process_is_never_opened_or_held() {
    let mut host = Host::new(3, vec![(3, Process::Service), (5, Process::Service)]);
    let result = scan(&mut host, &[]).unwrap();
    assert_eq!(alive_pids(&result), vec![5]);
    assert!(!host.log.borrow().contains(&"open(3)".to_string()));
}

/// A code the table has no verdict for is neither fatal nor dropped: it is
/// reported with the pid it came from, and the scan goes on.
#[skuld::test]
fn an_undetermined_process_is_reported_with_its_pid_and_code_and_the_scan_goes_on() {
    let mut host = Host::new(
        1,
        vec![
            (2, Process::Undetermined(1117)),
            (3, Process::Service),
            (4, Process::Undetermined(6)),
        ],
    );
    let result = scan(&mut host, &[]).unwrap();
    assert_eq!(alive_pids(&result), vec![3]);
    assert_eq!(
        result.undetermined,
        vec![
            Undetermined {
                pid: 2,
                code: Some(1117)
            },
            Undetermined { pid: 4, code: Some(6) }
        ]
    );
}

#[skuld::test]
fn an_undetermined_process_is_logged_with_its_pid_and_code() {
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = set_default_in_current_thread(subscriber);
    let mut host = Host::new(1, vec![(2718, Process::Undetermined(1117))]);
    scan(&mut host, &[]).unwrap();
    let logged = writer.snapshot();
    assert!(logged.contains("WARN"), "{logged:?}");
    assert!(logged.contains("2718"), "{logged:?}");
    assert!(logged.contains("1117"), "{logged:?}");
}

#[skuld::test]
fn a_failure_that_is_not_a_verdict_ends_the_scan() {
    struct Fails;
    impl ProcessEnumerator for Fails {
        type Process = Handle;
        fn list(&mut self) -> io::Result<Vec<ListedProcess>> {
            Err(io::Error::other("cannot list"))
        }
        fn this_process(&self) -> u32 {
            1
        }
        fn open(&mut self, _: u32) -> io::Result<Opened<Handle>> {
            unreachable!()
        }
        fn has_exited(&mut self, _: &Handle) -> io::Result<bool> {
            unreachable!()
        }
    }
    assert_eq!(scan(&mut Fails, &[]).err().expect("fails").to_string(), "cannot list");
}

/// What the scan finds joins the holds, so the next look shows it alive and a
/// settled STOPPED waits for it.
#[skuld::test]
fn holding_the_scan_makes_what_it_found_show_in_the_next_look() {
    use crate::cutover::scm_wait::hold::{ProcessSource, Reading};
    use crate::cutover::scm_wait::Observed;

    struct Stopped;
    impl ProcessSource for Stopped {
        type Process = Handle;
        fn read(&mut self) -> io::Result<Reading> {
            Ok(Reading {
                observed: Observed::Stopped,
                pid: 0,
            })
        }
        fn open(&mut self, _: u32, _: crate::cutover::scm_wait::hold::Basis) -> io::Result<Opened<Handle>> {
            unreachable!("STOPPED names no process")
        }
        fn has_exited(&mut self, _: &Handle) -> io::Result<bool> {
            Ok(false)
        }
    }

    let mut host = Host::new(1, vec![(3, Process::Service), (5, Process::Undetermined(1117))]);
    let mut holds = ProcessHolds::default();
    let scanned = holds.hold_scanned(&mut host).unwrap();
    assert_eq!(scanned.finding, ScanFinding::Alive);
    let undetermined = scanned.undetermined;
    assert_eq!(
        undetermined,
        vec![Undetermined {
            pid: 5,
            code: Some(1117)
        }]
    );
    let look = holds.look(&mut Stopped).unwrap();
    assert!(look.held_alive && look.ever_held);
}

/// The holds remember what vanished at their last scan, so the exemption needs
/// nothing of the caller.
#[skuld::test]
fn holds_scanning_twice_end_on_an_id_that_never_opens() {
    let mut host = Host::new(1, vec![(7, Process::Gone)]);
    let mut holds = ProcessHolds::default();
    assert_eq!(holds.hold_scanned(&mut host).unwrap().finding, ScanFinding::Vanished);
    assert_eq!(holds.hold_scanned(&mut host).unwrap().finding, ScanFinding::Nothing);
    assert_eq!(holds.hold_scanned(&mut host).unwrap().finding, ScanFinding::Nothing);
}
