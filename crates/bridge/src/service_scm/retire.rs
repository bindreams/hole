//! Retiring the bridge service in one SCM session: stop it, and optionally
//! deregister it, without trusting a state the SCM can change underneath, and
//! return only once no service process is left.
//!
//! The order is harden, settle, then delete last. The hardening writes the
//! record that the disable is ours ([`crate::disable_record`]) and then
//! disables the start type, so the SCM cannot start the service once it stops;
//! the settle loop ([`settle_stopped`]) is the one the update cutover runs; and
//! nothing touches the service handle after the delete. The record goes last,
//! after the start type is written back or the service is deleted, so a
//! retirement cut short at any call leaves a Disabled service we disabled with
//! its record.
//!
//! The session the real retirement runs on holds the machine-wide start-type
//! lock from before its first read to after its last write, so no repair,
//! enable or other retirement interleaves with it.

use std::io;

use tracing::{info, warn};

use super::call_error::{io_error_is_a_refused_process_open, service_gone, ServiceGone};
use super::scan::ScanFinding;
use super::settle::{settle_stopped, SettleError, StopActor};
use crate::disable_record::{ChangeMark, Changer, RecordState};
use crate::service_start::StartType;

/// What a retirement leaves behind once the service is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The service stays registered, stopped.
    StopOnly,
    /// The service is deleted.
    Deregister,
}

/// What opening a retirement's session found.
pub enum Opening<S, G> {
    /// The session, with its service handle.
    Opened(S),
    /// The SCM has no entry for the service: never registered, or removed. A
    /// process of it can still be running, which `G` waits out. `G` holds
    /// whatever the open took (the start-type lock), so that wait runs under
    /// it: an install cannot register and start the service meanwhile.
    Absent(G),
}

impl<S, G> Opening<S, G> {
    /// The same opening with its survivors replaced by `f` of them.
    pub fn map_absent<H>(self, f: impl FnOnce(G) -> H) -> Opening<S, H> {
        match self {
            Opening::Opened(session) => Opening::Opened(session),
            Opening::Absent(survivors) => Opening::Absent(f(survivors)),
        }
    }
}

/// A start type the retirement writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartWrite {
    Auto,
    Demand,
    Disabled,
}

/// The failure actions the retirement writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureActions {
    /// Restart nothing.
    None,
    /// What `install` configures: restart on failure.
    Restart,
}

/// What [`harden`] changed, which [`restore`] puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// The start type before it was disabled.
    pub observed: StartType,
    /// Whether the disable is the retirement's own. False only for a service
    /// found Disabled with no record, which an administrator disabled: it is
    /// put back Disabled, and no record is made or cleared for it.
    pub ours: bool,
}

impl Hardening {
    /// The start type to put back. The observed one, except that `Other` (a
    /// boot or system start, which a service of its own process never has)
    /// becomes `Auto`, and `Disabled` becomes `Auto` only where the disable is
    /// ours: it is what an interrupted retirement leaves, and the product
    /// treats it as broken.
    pub fn restored(self) -> StartWrite {
        match (self.observed, self.ours) {
            (StartType::Auto, true) => StartWrite::Auto,
            (StartType::Auto, false) => StartWrite::Auto,
            (StartType::Demand, true) => StartWrite::Demand,
            (StartType::Demand, false) => StartWrite::Demand,
            (StartType::Disabled, true) => StartWrite::Auto,
            (StartType::Disabled, false) => StartWrite::Disabled,
            (StartType::Other, true) => StartWrite::Auto,
            (StartType::Other, false) => StartWrite::Auto,
        }
    }

    /// What the hardening does about the record, from the start type and the
    /// record found. A record already there is stamped again with this
    /// retirement's identity, so a reader does not take the old stamp's dead
    /// process for an interrupted change while this one runs; one over a
    /// service that is not Disabled is stale, kept until [`restore`] or the
    /// delete sweeps it.
    fn plan(observed: StartType, record: RecordState) -> Plan {
        let (ours, record_write) = match (observed, record) {
            (StartType::Auto, RecordState::Absent) => (true, RecordWrite::Make),
            (StartType::Auto, RecordState::Present) => (true, RecordWrite::Restamp),
            (StartType::Demand, RecordState::Absent) => (true, RecordWrite::Make),
            (StartType::Demand, RecordState::Present) => (true, RecordWrite::Restamp),
            (StartType::Disabled, RecordState::Absent) => (false, RecordWrite::None),
            (StartType::Disabled, RecordState::Present) => (true, RecordWrite::Restamp),
            (StartType::Other, RecordState::Absent) => (true, RecordWrite::Make),
            (StartType::Other, RecordState::Present) => (true, RecordWrite::Restamp),
        };
        Plan {
            hardening: Hardening { observed, ours },
            record_write,
        }
    }
}

/// What a change to the start type does to the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordWrite {
    /// Nothing: the Disable is an administrator's.
    None,
    /// The record is not there: make it.
    Make,
    /// The record is there: stamp it again.
    Restamp,
}

impl RecordWrite {
    /// What a change that stamps whatever record it finds does: make it when
    /// absent, stamp it again when present.
    pub(super) fn over(record: RecordState) -> RecordWrite {
        match record {
            RecordState::Absent => RecordWrite::Make,
            RecordState::Present => RecordWrite::Restamp,
        }
    }

    /// Whether the call writes the record.
    fn writes(self) -> bool {
        match self {
            RecordWrite::None => false,
            RecordWrite::Make => true,
            RecordWrite::Restamp => true,
        }
    }

    /// Whether a failure after the write clears the record: only a record
    /// this call made is its own to remove; one that was there stays.
    pub(super) fn clears_on_failure(self) -> bool {
        match self {
            RecordWrite::None => false,
            RecordWrite::Make => true,
            RecordWrite::Restamp => false,
        }
    }
}

/// What [`harden`] is to do, decided once from what it found.
struct Plan {
    hardening: Hardening,
    record_write: RecordWrite,
}

/// A service's start type and the record that an uninstall disabled it: what a
/// retirement hardens and restores, and what a repair reads and resets.
pub trait StartConfig {
    /// The start type now.
    fn start_type(&mut self) -> io::Result<StartType>;
    /// Write the start type.
    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()>;
    /// Whether the record that an uninstall disabled the service is there.
    fn record_state(&mut self) -> RecordState;
    /// Remove the record.
    fn clear_record(&mut self) -> io::Result<()>;
    /// Write the record, stamped with the identity of the process changing the
    /// service, replacing a stamp already there.
    fn write_record(&mut self) -> io::Result<()>;
    /// Whether the process that stamped the record is still running: `None`
    /// when there is no record.
    fn record_changer(&mut self) -> Option<Changer>;
}

/// What the GUI's status read needs of the service: the start type and the
/// record's changer, and nothing it could write. A session that holds the
/// start-type lock reads through this too ([`StartConfig`]); the GUI's own
/// session does not hold it and implements nothing else.
pub trait StartRead {
    /// The start type now.
    fn read_start_type(&mut self) -> io::Result<StartType>;
    /// Whether the process that stamped the record is still running: `None`
    /// when there is no record.
    fn read_changer(&mut self) -> Option<Changer>;
    /// The change mark: the lock holder's, and a value that differs after any
    /// holder began or ended a change in between.
    fn read_mark(&mut self) -> ChangeMark;
}

impl<S: StartConfig> StartRead for S {
    fn read_start_type(&mut self) -> io::Result<StartType> {
        self.start_type()
    }

    fn read_changer(&mut self) -> Option<Changer> {
        self.record_changer()
    }

    /// Holding the lock, nothing changes under the reads.
    fn read_mark(&mut self) -> ChangeMark {
        ChangeMark::unchanging()
    }
}

/// The SCM operations a retirement needs on top of the stop wait, all through
/// one service handle opened before anything is changed, so the delete, which
/// only marks the service, cannot take it away.
pub trait ServiceSession: StopActor + StartConfig {
    /// Write the failure actions.
    fn set_failure_actions(&mut self, actions: FailureActions) -> io::Result<()>;
    /// `DeleteService`: mark the service for deletion.
    fn delete(&mut self) -> io::Result<()>;
}

/// Why a retirement failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RetireError {
    #[error("the record that the uninstall disables the service could not be written: {0}")]
    Record(io::Error),
    #[error("the service could not be hardened against a restart: {0}")]
    Harden(io::Error),
    #[error("the service's state could not be read: {0}")]
    Observe(io::Error),
    #[error("the service did not stop: {0}")]
    Stop(io::Error),
    #[error("the service's process could not be opened to wait for its exit: {0}")]
    Hold(io::Error),
    #[error("the service could not be deleted: {0}")]
    Delete(io::Error),
    #[error("the service's process could not be awaited: {0}")]
    Exit(io::Error),
}

impl RetireError {
    /// `error` as the failure of the step `step` names, unless it is the
    /// refusal to open the service's process: that is [`RetireError::Hold`]
    /// whichever step needed the process held, and is not the service failing
    /// to stop or to be read.
    pub(super) fn of_step(step: fn(io::Error) -> RetireError, error: io::Error) -> RetireError {
        if io_error_is_a_refused_process_open(&error) {
            RetireError::Hold(error)
        } else {
            step(error)
        }
    }
}

impl From<SettleError> for RetireError {
    fn from(error: SettleError) -> Self {
        match error {
            SettleError::Observe(e) => RetireError::of_step(RetireError::Observe, e),
            SettleError::Arm(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::Stop(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::AwaitChange(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::Scan(e) => RetireError::of_step(RetireError::Hold, e),
            SettleError::AwaitExit(e) => RetireError::of_step(RetireError::Exit, e),
        }
    }
}

/// What [`harden`] found.
pub(crate) enum Hardened {
    /// The start type is disabled, which [`restore`] undoes.
    Disabled(Hardening),
    /// The service is already marked for deletion by someone else's delete:
    /// nothing was changed, so there is nothing to put back and no delete to
    /// issue.
    Marked,
}

/// Whether `error` is the SCM answering that the service is marked for
/// deletion, from a call through the retirement's own handle.
fn answered_as_marked(error: &io::Error) -> bool {
    service_gone(error).is_some_and(ServiceGone::harden_goes_on_marked)
}

/// Write the record (stamped with this process), disable the start type, then
/// turn restart-on-failure off.
///
/// A disabled start type is what makes STOPPED final: the SCM's own restart of
/// a service it is about to restart starts it, and a disabled service cannot be
/// started ([`ChangeServiceConfig2W`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w#remarks):
/// "The service must be explicitly disabled to prevent it from restarting").
/// The change binds when the service stops. The record is written first, so a
/// retirement cut short after the start type is disabled has its record; a
/// failed write of it is the retirement's failure with nothing changed, and a
/// record that cannot be read counts as present (`RecordKey::state`).
/// A failed start-type write is the retirement's failure with only the record
/// this call wrote cleared, unless the SCM answers that the service is marked
/// for deletion ([`Hardened::Marked`]); a failed failure-actions write only
/// narrows what is queued, and is warned about.
pub(crate) fn harden<S: ServiceSession>(session: &mut S) -> Result<Hardened, RetireError> {
    let observed = match session.start_type() {
        Ok(observed) => observed,
        Err(error) if answered_as_marked(&error) => return Ok(marked(&error)),
        Err(error) => return Err(RetireError::Harden(error)),
    };
    let record = session.record_state();
    let Plan {
        hardening,
        record_write,
    } = Hardening::plan(observed, record);
    if record_write.writes() {
        session.write_record().map_err(RetireError::Record)?;
    }
    if let Err(error) = session.set_start_type(StartWrite::Disabled) {
        if record_write.clears_on_failure() {
            clear_record(session);
        }
        if answered_as_marked(&error) {
            return Ok(marked(&error));
        }
        return Err(RetireError::Harden(error));
    }
    if let Err(error) = session.set_failure_actions(FailureActions::None) {
        warn!(%error, "could not turn restart-on-failure off; the disabled start type still stops a restart");
    }
    Ok(Hardened::Disabled(hardening))
}

/// [`restore`] what a [`harden`] changed; a service found marked for deletion
/// was left as it was.
pub(crate) fn restore_hardened<S: ServiceSession>(session: &mut S, hardened: &Hardened) {
    match hardened {
        Hardened::Disabled(hardening) => restore(session, *hardening),
        Hardened::Marked => {}
    }
}

/// Remove the record. A failure is a warning: the next retirement, cutover or
/// install sweeps a record over a service that is not Disabled.
pub(super) fn clear_record<S: StartConfig>(session: &mut S) {
    if let Err(error) = session.clear_record() {
        warn!(%error, "could not clear the record that the uninstall disabled the service");
    }
}

fn marked(error: &io::Error) -> Hardened {
    info!(%error, "the service is marked for deletion; stopping it through the open handle");
    Hardened::Marked
}

/// Put back what [`harden`] changed: the failure actions as `install`
/// configures them, then the start type, so a failure of the first never
/// leaves the service disabled, then the record, only once the start type is
/// written: a failed write leaves the service Disabled and its record. Each
/// failure is a warning.
fn restore<S: ServiceSession>(session: &mut S, hardening: Hardening) {
    if let Err(error) = session.set_failure_actions(FailureActions::Restart) {
        warn!(%error, "could not put restart-on-failure back");
    }
    if let Err(error) = session.set_start_type(hardening.restored()) {
        warn!(%error, "could not put the start type back");
        return;
    }
    if hardening.ours {
        clear_record(session);
    }
}

/// Stop the service and, per `disposition`, delete it, and return once no
/// process of it is left.
///
/// 1. [`harden`]. A failure here changes nothing. A service found marked for
///    deletion skips the rest of the steps but the stop wait: it is stopped
///    through the open handle, and is neither restored nor deleted (a record
///    this call wrote is cleared).
/// 2. [`settle_stopped`]: stop on a RUNNING observation, wait on the held
///    process, and settle only when the SCM says STOPPED and a scan finds no
///    process carrying the service's token.
/// 3. `Deregister` deletes, and the service handle is not used again, then
///    the record is cleared; `StopOnly` restores the hardening. A failure
///    before the delete restores it and returns the step's own error.
///
/// `DeleteService` answering that the service is already marked is a success:
/// someone else's delete got there first.
pub fn retire<S: ServiceSession>(session: &mut S, disposition: Disposition) -> Result<(), RetireError> {
    let hardening = match harden(session)? {
        Hardened::Disabled(hardening) => hardening,
        Hardened::Marked => return settle_stopped(session).map_err(RetireError::from),
    };
    if let Err(error) = settle_stopped(session) {
        restore(session, hardening);
        return Err(error.into());
    }
    match disposition {
        Disposition::StopOnly => {
            restore(session, hardening);
            Ok(())
        }
        Disposition::Deregister => match session.delete() {
            Ok(()) => {
                deleted(session, hardening);
                Ok(())
            }
            Err(error) if service_gone(&error).is_some_and(ServiceGone::delete_is_done) => {
                info!("the service was already marked for deletion");
                deleted(session, hardening);
                Ok(())
            }
            Err(error) => {
                restore(session, hardening);
                Err(RetireError::Delete(error))
            }
        },
    }
}

/// The service is deleted: the record, if the disable was ours, has served.
fn deleted<S: ServiceSession>(session: &mut S, hardening: Hardening) {
    if hardening.ours {
        clear_record(session);
    }
}

/// What waiting out the processes of a service the SCM has no entry for needs.
pub trait Survivors {
    /// Scan for the live processes that carry the service's token, other than
    /// the calling one, and hold them. Says what the scan itself found.
    fn hold_scanned(&mut self) -> io::Result<ScanFinding>;
    /// Wait until every held process has exited.
    fn await_exits(&mut self) -> io::Result<()>;
}

/// Wait out every process that carries a removed service's token.
///
/// The SCM drops an entry once the service is not running, which is its state
/// and not its process, so a process can outlive its entry, and only a scan by
/// token sees it. The wait ends on a scan of its own that finds nothing alive
/// and loses no listed process ([`ScanFinding::Nothing`]): a process that
/// exited, or vanished before its probe, can have started another after the
/// listing, which the next scan finds. Every other iteration waits out the
/// held processes (a process exit, or nothing to wait on) and scans again.
pub fn wait_out_survivors<W: Survivors>(survivors: &mut W) -> Result<(), RetireError> {
    loop {
        let finding = survivors.hold_scanned().map_err(RetireError::Hold)?;
        if finding.ends_the_wait() {
            return Ok(());
        }
        survivors.await_exits().map_err(RetireError::Exit)?;
    }
}

/// [`retire`] on what opening the service found. `Ok(false)`: the SCM has no
/// entry, and the processes of it that outlived the entry (if any) were waited
/// out. `Ok(true)`: the retirement ran.
pub fn retire_over<S: ServiceSession, G: Survivors>(
    opening: Opening<S, G>,
    disposition: Disposition,
) -> Result<bool, RetireError> {
    match opening {
        Opening::Absent(mut survivors) => {
            wait_out_survivors(&mut survivors)?;
            Ok(false)
        }
        Opening::Opened(mut session) => {
            retire(&mut session, disposition)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod retire_tests;
