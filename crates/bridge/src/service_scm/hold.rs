//! Holding the processes a service shows, so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and
//! `dwProcessId` is 0 once it has, so a process is opened while the service
//! still names it. An id the SCM names is a claim, not an identity (see
//! [`ProcessHolds::hold_current`]): a process is held only if the source
//! proves it is the service's own.

use std::io;

use tracing::warn;

use super::call_error::{scm_call_error, ScmCall, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
use super::scan::{scan, ListedProcess, ProcessEnumerator, ScanFinding, ScanResult, Undetermined};
use super::settle::ExitWait;
use super::{Observed, ReportedPid};

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
    /// the holder keeps none, or the id is one that "may not be valid"
    /// ([`Observed::reported_pid`]) and the process under it has gone: that
    /// says nothing about the service, which the SCM's own transition does.
    Unheld,
    /// A held process that has not exited.
    Alive,
    /// The named process has exited, in a state whose id is valid: a held one
    /// that is signalled, whatever state the SCM still reports, or an id no
    /// process has.
    Exited,
}

/// A look at a service with the fate of the process it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    pub observed: Observed,
    pub fate: ProcessFate,
    /// Whether any process held so far has not exited, the named one or not:
    /// a process outlives the STOPPED the SCM reports for it.
    pub held_alive: bool,
    /// Whether a held process the SCM named, validly or not (the service's own,
    /// or one held on a pending-state id), has not exited. Outside STOPPED only
    /// these are waited on: a process only a scan found has no Stop on its way
    /// and is dealt with once the SCM reports STOPPED.
    pub named_alive: bool,
    /// Whether anything has been held so far, alive or since exited. A marked
    /// service cannot be armed on, so once everything held has exited and a
    /// scan finds nothing, this is what says that the SCM's lagging state is
    /// about processes that are gone.
    pub ever_held: bool,
}

/// What opening a process id found.
#[derive(Debug)]
pub enum Opened<P> {
    /// No process has that id.
    NoSuchProcess,
    /// A live process that is not the service's: its token lacks the service
    /// SID, or the basis says a refusal to read it is a stranger's. The source
    /// closes it before returning this, so it is never held.
    NotTheService,
    /// A live process of the service, proven by its token.
    Service(P),
    /// A process of a host-wide scan that failed in a way the
    /// [`Basis::Scanned`] table does not decide ([`Verdict::Undetermined`]).
    /// Never the answer for an id the SCM named.
    Undetermined { code: Option<u32> },
}

impl<P> Opened<P> {
    /// What a failed probe resolves to under `basis`'s table
    /// ([`Basis::verdict`]); only a fatal verdict is an error, and it is the
    /// one the probe failed with.
    pub fn of_failure(basis: Basis, error: io::Error) -> io::Result<Opened<P>> {
        match basis.verdict(ProbeFailure::of_error(&error)) {
            Verdict::Gone => Ok(Opened::NoSuchProcess),
            Verdict::NotOurs => Ok(Opened::NotTheService),
            Verdict::Fatal => Err(error),
            Verdict::Undetermined => Ok(Opened::Undetermined {
                code: scm_call_error(&error).map(|typed| typed.code),
            }),
        }
    }
}

/// How a probe of a process failed, from the call and the Win32 code it failed
/// with. Classified here once; what each kind means is [`Basis::verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    /// `OpenProcess` found no process with the id.
    NoSuchProcess,
    /// The caller may not open the process or read its token.
    AccessDenied,
    /// Any other code.
    Other,
}

impl ProbeFailure {
    /// The kind `error` is. Only a typed [`ScmCallError`](super::call_error::ScmCallError)
    /// carries the call, and `ERROR_INVALID_PARAMETER` is a missing process
    /// only from `OpenProcess`: from a call on a handle already open it is
    /// not.
    pub fn of_error(error: &io::Error) -> Self {
        let Some(typed) = scm_call_error(error) else {
            return ProbeFailure::Other;
        };
        match (typed.call, typed.code) {
            (ScmCall::OpenProcess, ERROR_INVALID_PARAMETER) => ProbeFailure::NoSuchProcess,
            (_, ERROR_ACCESS_DENIED) => ProbeFailure::AccessDenied,
            _ => ProbeFailure::Other,
        }
    }
}

/// What a process being probed is known to be, which decides what a failed
/// probe of it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The SCM named the id, in a state whose id has this trust
    /// ([`Observed::reported_pid`]).
    Named(ReportedPid),
    /// The id came from listing every process on the host: there is no prior
    /// that it is the service's.
    Scanned,
}

/// What a failed probe means for the question "is this the service's
/// process, and is it alive".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// There is no such process.
    Gone,
    /// There is a process and it is not the service's.
    NotOurs,
    /// A process the retirement cannot let go of cannot be probed: the
    /// retirement fails.
    Fatal,
    /// Nothing can be said. The scan warns of it and goes on: the process is
    /// not waited on, and the scan does not fail.
    Undetermined,
}

impl Basis {
    /// The one table from a failed probe to what is done about it. It is
    /// derived from the documented error kinds; the whole-host probe
    /// (`--scan-sid`) is what confirms the rows.
    ///
    /// - Named, valid id (RUNNING): the SCM holds the service's process while
    ///   it reports it, so the id is not a stranger's; a process that cannot
    ///   be opened or read is the service's own and an uninstall must not
    ///   proceed past it. Fatal for a denial and for any other code.
    /// - Named, id that "may not be valid" (START_PENDING, STOP_PENDING): a
    ///   denial is a stranger that reused the id; any other code is unexpected
    ///   and fatal.
    /// - Scanned: a denial is a process of another principal; any other code
    ///   proves nothing either way and is reported.
    ///
    /// A missing process is [`Verdict::Gone`] on every basis.
    pub fn verdict(self, failure: ProbeFailure) -> Verdict {
        match self {
            Basis::Named(ReportedPid::Valid) => match failure {
                ProbeFailure::NoSuchProcess => Verdict::Gone,
                ProbeFailure::AccessDenied => Verdict::Fatal,
                ProbeFailure::Other => Verdict::Fatal,
            },
            Basis::Named(ReportedPid::MayBeInvalid) => match failure {
                ProbeFailure::NoSuchProcess => Verdict::Gone,
                ProbeFailure::AccessDenied => Verdict::NotOurs,
                ProbeFailure::Other => Verdict::Fatal,
            },
            Basis::Named(ReportedPid::Never) => {
                panic!("Basis::Named(Never) names no process, so there is nothing to probe")
            }
            Basis::Scanned => match failure {
                ProbeFailure::NoSuchProcess => Verdict::Gone,
                ProbeFailure::AccessDenied => Verdict::NotOurs,
                ProbeFailure::Other => Verdict::Undetermined,
            },
        }
    }

    /// Whether a live process that turns out not to be the service's is a
    /// surprise worth saying: only where the id is documented valid.
    pub fn expects_the_service(self) -> bool {
        match self {
            Basis::Named(ReportedPid::Valid) => true,
            Basis::Named(ReportedPid::MayBeInvalid) => false,
            Basis::Named(ReportedPid::Never) => false,
            Basis::Scanned => false,
        }
    }
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
                if !held_has_exited()? {
                    ProcessFate::Alive
                } else if observed.reported_pid().gone_id_is_an_exit() {
                    ProcessFate::Exited
                } else {
                    // The process held under an id that may not be valid has
                    // gone; the service's may be another.
                    ProcessFate::Unheld
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
    /// by the id (see [`ProcessHolds::hold_current`]). A failure is resolved
    /// by `basis` ([`Opened::of_failure`]).
    fn open(&mut self, pid: u32, basis: Basis) -> io::Result<Opened<Self::Process>>;
    /// Whether `process` has exited. A state read, never a wait.
    fn has_exited(&mut self, process: &Self::Process) -> io::Result<bool>;
}

/// How a held process came to be held: what the SCM did, or could have done,
/// about its exit. Every policy question about a held process is one match
/// here, never a match at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The SCM named it in a state whose id is valid ([`ReportedPid::Valid`]), so
    /// it is the service's own, the SCM's Stop is on its way to it, and its exit
    /// is the service's own.
    Named,
    /// The SCM named it in a state whose id "may not be valid"
    /// ([`ReportedPid::MayBeInvalid`]) and its token carries the service SID. It
    /// may be the real service mid-stop, or a SID-carrying process that took a
    /// stale id. Before STOPPED it is waited on, like [`Named`](Self::Named); at
    /// STOPPED the SCM's Stop is done and teardown with it, so it is ended like
    /// [`Scanned`](Self::Scanned). A valid claim on it later makes it `Named`.
    Claimed,
    /// Only a scan found it carrying the service's token: a plugin a crashed
    /// bridge left, a cutover child left suspended. The SCM never named it, so
    /// no Stop is on its way to it.
    Scanned,
}

impl Origin {
    /// The origin of a process first held on the SCM's claim `claim`. A state
    /// whose claim names no process holds nothing, so it never gets here.
    fn first_held_on(claim: ReportedPid) -> Self {
        match claim {
            ReportedPid::Valid => Origin::Named,
            ReportedPid::MayBeInvalid => Origin::Claimed,
            ReportedPid::Never => unreachable!("a state that names no process holds none"),
        }
    }

    /// The origin of this held process once the SCM names it again, on `claim`.
    fn after_claim(self, claim: ReportedPid) -> Self {
        let settles = claim.is_a_claim_about_the_service();
        match self {
            Origin::Named => Origin::Named,
            Origin::Claimed if settles => Origin::Named,
            Origin::Claimed => Origin::Claimed,
            Origin::Scanned if settles => Origin::Named,
            Origin::Scanned => Origin::Scanned,
        }
    }

    /// Whether a wait outside STOPPED covers a process held this way: the
    /// ones the SCM named, validly or not.
    fn is_awaited_before_stopped(self) -> bool {
        match self {
            Origin::Named => true,
            Origin::Claimed => true,
            Origin::Scanned => false,
        }
    }

    /// Whether the STOPPED wait ends a process held this way. The one place that
    /// says which held processes may be terminated.
    fn is_terminated_at_stopped(self) -> bool {
        match self {
            Origin::Named => false,
            Origin::Claimed => true,
            Origin::Scanned => true,
        }
    }
}

/// A held process with the id it was opened under. The handle keeps the id
/// from being reused, so the id names this process for as long as it is held.
struct Held<P> {
    pid: u32,
    process: P,
    origin: Origin,
}

/// The processes held so far.
pub struct ProcessHolds<P> {
    held: Vec<Held<P>>,
    /// The processes the last scan found gone or exited at their probe, which
    /// the next scan does not call vanished again ([`scan`]).
    vanished: Vec<ListedProcess>,
}

impl<P> Default for ProcessHolds<P> {
    fn default() -> Self {
        Self {
            held: Vec::new(),
            vanished: Vec::new(),
        }
    }
}

impl<P> ProcessHolds<P> {
    /// The held processes.
    pub fn processes(&self) -> impl Iterator<Item = &P> {
        self.held.iter().map(|held| &held.process)
    }

    /// The held processes a wait of this kind covers: the ones the SCM named,
    /// and the orphans only where the wait says so
    /// ([`ExitWait::waits_on_orphans`]).
    pub fn awaited(&self, wait: ExitWait) -> impl Iterator<Item = &P> {
        self.held
            .iter()
            .filter(move |held| held.origin.is_awaited_before_stopped() || wait.waits_on_orphans())
            .map(|held| &held.process)
    }

    /// The orphans, with their ids: the held processes the STOPPED wait ends,
    /// which the SCM never named, or named only in a state whose id may be
    /// invalid. A process named in a valid state is not one, however long it
    /// outlives STOPPED.
    pub fn orphans(&self) -> impl Iterator<Item = (u32, &P)> {
        self.held
            .iter()
            .filter(|held| held.origin.is_terminated_at_stopped())
            .map(|held| (held.pid, &held.process))
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
            if let Some(held) = self.held.iter_mut().find(|held| held.pid == pid) {
                // Held before this claim: it is the service's only if the SCM's
                // claim is evidence of it ([`Origin::after_claim`]).
                held.origin = held.origin.after_claim(reading.observed.reported_pid());
                return Ok(Hold {
                    reading,
                    named: Named::Held,
                });
            }
            // `None`: a live process that is not the service's, already closed.
            let candidate = match source.open(pid, Basis::Named(reading.observed.reported_pid()))? {
                // No process has this id, so there is nothing to hold.
                Opened::NoSuchProcess => {
                    return Ok(Hold {
                        reading,
                        named: Named::NoSuchProcess,
                    });
                }
                Opened::NotTheService => None,
                Opened::Service(process) => Some(process),
                Opened::Undetermined { .. } => {
                    unreachable!("an id the SCM named is never undetermined: Basis::verdict gives that only to a scan")
                }
            };
            let again = source.read()?;
            if again.process_to_hold() != Some(pid) {
                reading = again;
                continue;
            }
            let named = match candidate {
                Some(process) => {
                    self.held.push(Held {
                        pid,
                        process,
                        origin: Origin::first_held_on(again.observed.reported_pid()),
                    });
                    Named::Held
                }
                None => {
                    if Basis::Named(again.observed.reported_pid()).expects_the_service() {
                        warn!(
                            pid,
                            state = ?again.observed,
                            "the process the SCM names does not carry the service SID: it will not be waited on"
                        );
                    }
                    Named::NotTheService
                }
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
    ///
    /// `held_alive` is a state read of every held handle, not only the named
    /// one: a process outlives the STOPPED the SCM reports for it, and then
    /// the look names nothing.
    pub fn look<S: ProcessSource<Process = P>>(&mut self, source: &mut S) -> io::Result<Look> {
        let Hold { reading, named } = self.hold_current(source)?;
        let fate = named.fate(reading.observed, || {
            let pid = reading.process_to_hold().expect("a held process was named");
            let held = self
                .held
                .iter()
                .find(|held| held.pid == pid)
                .expect("a process reported as held is held");
            source.has_exited(&held.process)
        })?;
        let held_alive = self.any_alive(|process| source.has_exited(process))?;
        let named_alive = self.any_named_alive(|process| source.has_exited(process))?;
        Ok(Look {
            observed: reading.observed,
            fate,
            held_alive,
            named_alive,
            ever_held: !self.held.is_empty(),
        })
    }

    /// Whether any held process has not exited, by `has_exited` on each: a
    /// state read of the handle, never a wait.
    pub fn any_alive(&self, mut has_exited: impl FnMut(&P) -> io::Result<bool>) -> io::Result<bool> {
        for held in &self.held {
            if !has_exited(&held.process)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// [`any_alive`](Self::any_alive) over the processes the SCM named.
    pub fn any_named_alive(&self, mut has_exited: impl FnMut(&P) -> io::Result<bool>) -> io::Result<bool> {
        for process in self.awaited(ExitWait::OnTheirOwn) {
            if !has_exited(process)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Hold `process`, the process `pid` a scan found, unless it is held
    /// already; the redundant handle is dropped, and a process the SCM named
    /// stays the service's.
    pub fn adopt(&mut self, pid: u32, process: P) {
        if self.held.iter().all(|held| held.pid != pid) {
            self.held.push(Held {
                pid,
                process,
                origin: Origin::Scanned,
            });
        }
    }

    /// Hold every live process `enumerator` finds carrying the service's
    /// token, so the next [`look`](Self::look) shows it alive. Says what the
    /// scan itself found ([`ScanFinding`]), which the holds cannot: a process
    /// that exited between its probe and the next look is no longer held alive.
    pub fn hold_scanned<E: ProcessEnumerator<Process = P>>(&mut self, enumerator: &mut E) -> io::Result<Scanned> {
        let result = scan(enumerator, &self.vanished)?;
        let finding = result.finding();
        let ScanResult {
            alive,
            undetermined,
            unprobeable,
            ..
        } = result;
        self.vanished = unprobeable;
        for (pid, process) in alive {
            self.adopt(pid, process);
        }
        Ok(Scanned { finding, undetermined })
    }
}

/// What [`ProcessHolds::hold_scanned`] found.
#[derive(Debug, PartialEq, Eq)]
pub struct Scanned {
    pub finding: ScanFinding,
    /// The processes the scan could not decide, each already warned of by the
    /// scan. No wait reads this list.
    pub undetermined: Vec<Undetermined>,
}

#[cfg(test)]
#[path = "hold_tests.rs"]
mod hold_tests;
