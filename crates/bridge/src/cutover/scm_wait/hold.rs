//! Holding the processes a service shows, so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and
//! `dwProcessId` is 0 once it has, so a process is opened while the service
//! still names it. An id the SCM names is a claim, not an identity (see
//! [`ProcessHolds::hold_current`]): a process is held only if the source
//! proves it is the service's own.

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

/// Whether the process a look names is alive, by the process itself and not by
/// what the SCM says about it: the SCM's status can lag a process's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessFate {
    /// The look names no process to hold (STOPPED, or a live state with no id),
    /// or the holder keeps none.
    Unheld,
    /// A held process that has not exited.
    Alive,
    /// The named process has exited: a held one that is signalled, whatever
    /// state the SCM still reports, or an id no process has in a state whose id
    /// is valid ([`Observed::reported_pid`]).
    Exited,
}

/// A look at a service with the fate of the process it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    pub observed: Observed,
    pub fate: ProcessFate,
}

/// What opening a process id found.
#[derive(Debug)]
pub enum Opened<P> {
    /// No process has that id.
    NoSuchProcess,
    /// A live process that is not the service's: its token lacks the service
    /// SID. The source closes it before returning this, so it is never held.
    NotTheService,
    /// A live process of the service, proven by its token.
    Service(P),
}

/// What the process a look names came to, once [`ProcessHolds::hold_current`]
/// has dealt with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    /// The look names no process.
    Nothing,
    /// The process is held.
    Held,
    /// No process has the id. Whether that is the service's exit depends on the
    /// state the id was read in ([`Named::fate`]).
    NoSuchProcess,
    /// A live process has the id and it is not the service's. It is not held
    /// and is never waited on; whether anything of the service is left is not
    /// known from it.
    NotTheService,
}

impl Named {
    /// The fate of the process named in `observed`. `held_has_exited` is a
    /// state read of the held handle, called only for [`Named::Held`].
    fn fate(self, observed: Observed, held_has_exited: impl FnOnce() -> io::Result<bool>) -> io::Result<ProcessFate> {
        Ok(match self {
            Named::Nothing => ProcessFate::Unheld,
            Named::Held => {
                if held_has_exited()? {
                    ProcessFate::Exited
                } else {
                    ProcessFate::Alive
                }
            }
            Named::NoSuchProcess => {
                if observed.reported_pid().gone_id_is_an_exit() {
                    ProcessFate::Exited
                } else {
                    ProcessFate::Unheld
                }
            }
            Named::NotTheService => ProcessFate::Unheld,
        })
    }
}

/// The last look [`ProcessHolds::hold_current`] took, and what its named
/// process came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    pub reading: Reading,
    pub named: Named,
}

/// The OS reads holding a process needs.
pub trait ProcessSource {
    /// An open process of the service; closes when dropped.
    type Process;
    /// Read the service's state and process id.
    fn read(&mut self) -> io::Result<Reading>;
    /// Open process `pid` and prove it is the service's own by its token, not
    /// by the id (see [`ProcessHolds::hold_current`]).
    fn open(&mut self, pid: u32) -> io::Result<Opened<Self::Process>>;
    /// Whether `process` has exited. A state read, never a wait.
    fn has_exited(&mut self, process: &Self::Process) -> io::Result<bool>;
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
    /// The id is a claim, not an identity. Microsoft documents it
    /// ([`QueryServiceStatusEx`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex#remarks)):
    ///
    /// > The process identifier returned in the SERVICE_STATUS_PROCESS structure
    /// > is valid provided that the state of the service is one of SERVICE_RUNNING,
    /// > SERVICE_PAUSE_PENDING, SERVICE_PAUSED, or SERVICE_CONTINUE_PENDING. If
    /// > the service is in a SERVICE_START_PENDING or SERVICE_STOP_PENDING state,
    /// > however, the process identifier may not be valid, and if the service is
    /// > in the SERVICE_STOPPED state, it is never valid.
    ///
    /// START_PENDING and STOP_PENDING are states this code acts on, so a pid
    /// read in either may name a process that is not the service's, and an id
    /// may be reused. What makes a hold safe is not the state but the process:
    /// [`ProcessSource::open`] keeps a process only if its token carries the
    /// service SID (`NT SERVICE\<name>`, enabled by
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`), which the SCM puts only on a process
    /// it started as this service. A reused id fails that in every state, and
    /// a restarted instance of the same service passes it, which is correct: it
    /// is still the service's.
    ///
    /// Open-then-confirm: read, open the named process, read again, and act on
    /// the open only if the second look names the same id. Otherwise the handle
    /// is dropped and the second look is acted on as a first one, so a service
    /// that keeps changing is followed, one pass per real change, with no count.
    /// A process that fails the SID check is dropped the same way and reported
    /// as [`Named::NotTheService`]; it is never held. Returns the last look.
    pub fn hold_current<S: ProcessSource<Process = P>>(&mut self, source: &mut S) -> io::Result<Hold> {
        let mut reading = source.read()?;
        loop {
            let Some(pid) = reading.process_to_hold() else {
                return Ok(Hold {
                    reading,
                    named: Named::Nothing,
                });
            };
            if self.held.iter().any(|(held, _)| *held == pid) {
                return Ok(Hold {
                    reading,
                    named: Named::Held,
                });
            }
            // `None`: a live process that is not the service's, already closed.
            let candidate = match source.open(pid)? {
                // No process has this id, so there is nothing to hold.
                Opened::NoSuchProcess => {
                    return Ok(Hold {
                        reading,
                        named: Named::NoSuchProcess,
                    });
                }
                Opened::NotTheService => None,
                Opened::Service(process) => Some(process),
            };
            let again = source.read()?;
            if again.process_to_hold() != Some(pid) {
                reading = again;
                continue;
            }
            let named = match candidate {
                Some(process) => {
                    self.held.push((pid, process));
                    Named::Held
                }
                None => Named::NotTheService,
            };
            return Ok(Hold { reading: again, named });
        }
    }

    /// [`hold_current`](Self::hold_current), and the fate of the process the
    /// last look names, read off the process itself: the SCM's status can lag
    /// a process's exit, a process handle cannot.
    ///
    /// A look that names a process this holds is `Alive` or `Exited` by a
    /// state read of that handle. One that names an id no process has (the open
    /// found none) is `Exited` where the id is valid and `Unheld` where it may
    /// not be (START_PENDING, STOP_PENDING): the service's process may be alive
    /// under another id, so the wait rests on the SCM's own transition. One that
    /// names no process, or a process that is not the service's, is `Unheld`.
    pub fn look<S: ProcessSource<Process = P>>(&mut self, source: &mut S) -> io::Result<Look> {
        let Hold { reading, named } = self.hold_current(source)?;
        let fate = named.fate(reading.observed, || {
            let pid = reading.process_to_hold().expect("a held process was named");
            let (_, process) = self
                .held
                .iter()
                .find(|(held, _)| *held == pid)
                .expect("a process reported as held is held");
            source.has_exited(process)
        })?;
        Ok(Look {
            observed: reading.observed,
            fate,
        })
    }
}

#[cfg(test)]
#[path = "hold_tests.rs"]
mod hold_tests;
