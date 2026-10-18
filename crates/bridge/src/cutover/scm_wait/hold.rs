//! Holding the processes a service shows, so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and
//! `dwProcessId` is 0 once it has, so a process is opened while the service
//! still names it. Opening by id is only safe if the id is still the service's
//! process when the open lands: [`ProcessHolds::hold_current`] reads the service
//! again after the open and keeps the handle only if the SCM still names that
//! process.

use std::io;

use super::Observed;

/// One look at a service: its state and the process id it names (0: none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub observed: Observed,
    pub pid: u32,
}

impl Reading {
    /// The process this look names, if it names one. A match over the state
    /// ([`Observed::names_a_process`]), so no call site decides it.
    pub fn process_to_hold(self) -> Option<u32> {
        (self.observed.names_a_process() && self.pid != 0).then_some(self.pid)
    }
}

/// The two OS reads holding a process needs.
pub trait ProcessSource {
    /// An open process; closes when dropped.
    type Process;
    /// Read the service's state and process id.
    fn read(&mut self) -> io::Result<Reading>;
    /// Open process `pid`; `None` when no process has that id.
    fn open(&mut self, pid: u32) -> io::Result<Option<Self::Process>>;
}

/// The processes held so far, each with the id it was opened under.
pub struct ProcessHolds<P> {
    held: Vec<(u32, P)>,
}

impl<P> Default for ProcessHolds<P> {
    fn default() -> Self {
        Self { held: Vec::new() }
    }
}

impl<P> ProcessHolds<P> {
    /// The held processes.
    pub fn processes(&self) -> impl Iterator<Item = &P> {
        self.held.iter().map(|(_, process)| process)
    }

    /// Read the service and hold the process it names.
    ///
    /// Open-then-confirm: read, open the named process, read again, and keep the
    /// handle only if the second look names the same process. Otherwise the
    /// handle is dropped and the second look is acted on as a first one, so a
    /// service that keeps changing is followed, one pass per real change, with no
    /// count. Returns the last look.
    ///
    /// The one premise: the SCM keeps the process's handle while it reports the
    /// service non-STOPPED with that pid, so the pid cannot be reused under a
    /// confirmed open.
    pub fn hold_current<S: ProcessSource<Process = P>>(&mut self, source: &mut S) -> io::Result<Reading> {
        let mut reading = source.read()?;
        loop {
            let Some(pid) = reading.process_to_hold() else {
                return Ok(reading);
            };
            if self.held.iter().any(|(held, _)| *held == pid) {
                return Ok(reading);
            }
            // No process has this id: it has exited, and there is nothing to hold.
            let Some(process) = source.open(pid)? else {
                return Ok(reading);
            };
            let again = source.read()?;
            if again.process_to_hold() == Some(pid) {
                self.held.push((pid, process));
                return Ok(again);
            }
            reading = again;
        }
    }
}

#[cfg(test)]
#[path = "hold_tests.rs"]
mod hold_tests;
