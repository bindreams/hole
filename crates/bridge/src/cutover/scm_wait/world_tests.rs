//! A host whose processes spawn and exit while a scan is under way: the model
//! the stop wait and the removed-service wait are run on, so that the question
//! asked of them is the one that matters, "is any process of the service still
//! alive when the wait returns".

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;

use super::hold::{Basis, Opened, ProcessHolds, ProcessSource, Reading};
use super::scan::ProcessEnumerator;
use super::Observed;

/// The moment an [`Act`] happens.
#[derive(Debug, Clone, Copy)]
pub enum When {
    /// Right after the `n`th listing of the host's processes (1-based).
    AfterSnapshot(usize),
    /// Right after a probe opened process `pid`.
    AfterOpen(u32),
}

/// What happens to the host.
#[derive(Debug, Clone, Copy)]
pub enum Act {
    /// A new live process that carries the service's token.
    Spawn(u32),
    /// The process exits; its id still opens, and its token still reads.
    Exit(u32),
    /// The process exits and its id is gone: nothing opens it.
    Vanish(u32),
}

#[derive(Default)]
struct State {
    /// Every process by id: whether it is alive.
    processes: BTreeMap<u32, bool>,
    script: Vec<(When, Act)>,
    snapshots: usize,
}

impl State {
    fn run(&mut self, now: When) {
        let (due, later): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.script)
                .into_iter()
                .partition(|(when, _)| match (when, now) {
                    (When::AfterSnapshot(n), When::AfterSnapshot(m)) => *n == m,
                    (When::AfterOpen(a), When::AfterOpen(b)) => *a == b,
                    (When::AfterSnapshot(_), When::AfterOpen(_)) => false,
                    (When::AfterOpen(_), When::AfterSnapshot(_)) => false,
                });
        self.script = later;
        for (_, act) in due {
            match act {
                Act::Spawn(pid) => {
                    self.processes.insert(pid, true);
                }
                Act::Exit(pid) => {
                    self.processes.insert(pid, false);
                }
                Act::Vanish(pid) => {
                    self.processes.remove(&pid);
                }
            }
        }
    }
}

/// The host. Cloning shares it.
#[derive(Clone)]
pub struct World(Rc<RefCell<State>>);

impl World {
    /// A host with these processes alive, and what happens to it.
    pub fn new(alive: &[u32], script: Vec<(When, Act)>) -> Self {
        let state = State {
            processes: alive.iter().map(|pid| (*pid, true)).collect(),
            script,
            snapshots: 0,
        };
        World(Rc::new(RefCell::new(state)))
    }

    /// Every process of the service that has not exited.
    pub fn alive(&self) -> Vec<u32> {
        let state = self.0.borrow();
        state
            .processes
            .iter()
            .filter(|(_, alive)| **alive)
            .map(|(pid, _)| *pid)
            .collect()
    }

    pub fn host(&self) -> Host {
        Host(self.clone())
    }

    /// The event a wait on `pids` is for: they exit.
    pub fn exit_all(&self, pids: impl IntoIterator<Item = u32>) {
        let mut state = self.0.borrow_mut();
        for pid in pids {
            state.processes.insert(pid, false);
        }
    }
}

/// An open process of the model host.
pub struct Handle(pub u32);

pub struct Host(World);

impl ProcessEnumerator for Host {
    type Process = Handle;

    fn pids(&mut self) -> io::Result<Vec<u32>> {
        let mut state = (self.0).0.borrow_mut();
        state.snapshots += 1;
        assert!(state.snapshots < 1000, "the wait scans for ever");
        // A process that has exited is no longer listed.
        let listed = state
            .processes
            .iter()
            .filter(|(_, alive)| **alive)
            .map(|(pid, _)| *pid)
            .collect();
        let now = When::AfterSnapshot(state.snapshots);
        state.run(now);
        Ok(listed)
    }

    fn this_process(&self) -> u32 {
        1
    }

    fn open(&mut self, pid: u32) -> io::Result<Opened<Handle>> {
        let mut state = (self.0).0.borrow_mut();
        if !state.processes.contains_key(&pid) {
            return Ok(Opened::NoSuchProcess);
        }
        state.run(When::AfterOpen(pid));
        Ok(Opened::Service(Handle(pid)))
    }

    fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
        Ok(!(self.0).0.borrow().processes.get(&process.0).copied().unwrap_or(false))
    }
}

/// A service that is STOPPED, with the processes held so far.
pub struct StoppedService {
    pub world: World,
    pub holds: ProcessHolds<Handle>,
}

impl StoppedService {
    pub fn new(world: &World) -> Self {
        Self {
            world: world.clone(),
            holds: ProcessHolds::default(),
        }
    }

    pub fn look(&mut self) -> io::Result<super::hold::Look> {
        let mut source = Stopped(self.world.host());
        self.holds.look(&mut source)
    }

    /// Wait for every held process to exit: they do.
    pub fn await_exits(&mut self) {
        let alive: Vec<u32> = self.holds.processes().map(|process| process.0).collect();
        self.world.exit_all(alive);
    }
}

struct Stopped(Host);

impl ProcessSource for Stopped {
    type Process = Handle;

    fn read(&mut self) -> io::Result<Reading> {
        Ok(Reading {
            observed: Observed::Stopped,
            pid: 0,
        })
    }

    fn open(&mut self, _: u32, _: Basis) -> io::Result<Opened<Handle>> {
        unreachable!("STOPPED names no process")
    }

    fn has_exited(&mut self, process: &Handle) -> io::Result<bool> {
        self.0.has_exited(process)
    }
}
