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
}

impl Host {
    fn new(this: u32, processes: Vec<(u32, Process)>) -> Self {
        Self {
            log: Log::default(),
            this,
            processes: processes.into_iter().collect(),
        }
    }
}

impl ProcessEnumerator for Host {
    type Process = Handle;

    fn pids(&mut self) -> io::Result<Vec<u32>> {
        Ok(self.processes.keys().copied().collect())
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
    let result = scan(&mut host).unwrap();
    assert_eq!(alive_pids(&result), vec![3, 5]);
    assert!(result.undetermined.is_empty());
}

/// An exiting process still opens and still carries its token; it is no longer
/// something to wait for.
#[skuld::test]
fn a_process_that_has_exited_is_dropped_not_held() {
    let mut host = Host::new(1, vec![(3, Process::ServiceExited), (5, Process::Service)]);
    let result = scan(&mut host).unwrap();
    assert_eq!(alive_pids(&result), vec![5]);
    drop(result);
    assert_eq!(*host.log.borrow(), vec!["open(3)", "close(3)", "open(5)", "close(5)"]);
}

/// The calling process can carry the service's token (the cutover child
/// inherits the bridge's): it must not wait on itself.
#[skuld::test]
fn the_calling_process_is_never_opened_or_held() {
    let mut host = Host::new(3, vec![(3, Process::Service), (5, Process::Service)]);
    let result = scan(&mut host).unwrap();
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
    let result = scan(&mut host).unwrap();
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
    scan(&mut host).unwrap();
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
        fn pids(&mut self) -> io::Result<Vec<u32>> {
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
    assert_eq!(scan(&mut Fails).err().expect("fails").to_string(), "cannot list");
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
    let undetermined = holds.hold_scanned(&mut host).unwrap();
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
