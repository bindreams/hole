//! The SCM handle behind the start-type repair, the enable and the elevated
//! read of whether the service is disabled, all under the start-type lock.

use std::io;

use windows::Win32::Foundation::ERROR_SERVICE_ALREADY_RUNNING;
use windows_service::service::{Service, ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::retire_session::{read_start_type, write_start_type};
use super::start_type_lock::{log_wait, Held, StartTypeLock};
use super::{open_error_is_absent, scm_failure, SERVICE_NAME};
use crate::disable_record::{Changer, RecordKey, RecordState};
use crate::service_scm::call_error::ScmCall;
use crate::service_scm::retire::{StartConfig, StartWrite};
use crate::service_start::StartType;

/// The rights a read of the start type needs, and all the GUI's status read
/// ([`StatusSession`](super::status_session::StatusSession)) asks for.
pub(super) const READ_ACCESS: ServiceAccess = ServiceAccess::QUERY_CONFIG;

/// The rights a repair needs: the start type read and written.
pub(super) const REPAIR_ACCESS: ServiceAccess = ServiceAccess::QUERY_CONFIG.union(ServiceAccess::CHANGE_CONFIG);

/// The rights a start needs: the start, and the status read that tells a service
/// already up from one on its way down.
const START_ACCESS: ServiceAccess = ServiceAccess::START.union(ServiceAccess::QUERY_STATUS);

/// An open `HoleBridge` service and the key its record lives in.
pub(super) struct RepairSession {
    service: Service,
    record: RecordKey,
    /// Held from before the first read to after the last write. Last, so it is
    /// released after everything above is closed.
    _held: Held,
}

impl RepairSession {
    /// Opens the service with `access`, or `None` when the SCM has no entry,
    /// once the start-type lock is held.
    pub(super) fn open(access: ServiceAccess) -> io::Result<Option<Self>> {
        Self::open_noting(&StartTypeLock::machine_wide(), access, log_wait)
    }

    /// [`open`](Self::open) over `lock`, calling `on_busy` if another holds it.
    pub(super) fn open_noting(
        lock: &StartTypeLock,
        access: ServiceAccess,
        on_busy: impl FnOnce(),
    ) -> io::Result<Option<Self>> {
        Self::open_holding(lock.acquire_noting_wait(on_busy)?, access)
    }

    /// Opens the service with `access` while `held`, which the session keeps
    /// until it is dropped; `None` (and the lock released) when the SCM has no
    /// entry.
    fn open_holding(held: Held, access: ServiceAccess) -> io::Result<Option<Self>> {
        Self::open_named_holding(held, SERVICE_NAME, access)
    }

    /// [`open_holding`](Self::open_holding) for the service called `name`.
    fn open_named_holding(held: Held, name: &str, access: ServiceAccess) -> io::Result<Option<Self>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        match manager.open_service(name, access) {
            Ok(service) => Ok(Some(Self {
                service,
                record: RecordKey::service(),
                _held: held,
            })),
            Err(e) if open_error_is_absent(&e) => Ok(None),
            Err(e) => Err(scm_failure(ScmCall::OpenService, e)),
        }
    }
}

/// Starts the service on a handle of its own, opened with the rights a start
/// needs. One already running, or starting, is success. Does not wait: one on
/// its way down, or stopped with its process not yet exited, is
/// [`StartFailure::NotServing`].
pub(super) fn start_service() -> io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
    let service = manager
        .open_service(SERVICE_NAME, START_ACCESS)
        .map_err(|e| scm_failure(ScmCall::OpenService, e))?;
    let Err(e) = service.start::<&str>(&[]) else {
        return Ok(());
    };
    if !already_running(&e) {
        return Err(scm_failure(ScmCall::StartService, e));
    }
    // "Already running" does not say which state the service is in.
    let state = service
        .query_status()
        .map(|status| status.current_state)
        .map_err(|e| io::Error::other(StartFailure::Status(scm_failure(ScmCall::QueryServiceStatusEx, e))))?;
    if is_up_or_coming_up(state) {
        Ok(())
    } else {
        Err(io::Error::other(StartFailure::NotServing(state)))
    }
}

/// Why a start that the SCM answered with "already running" failed. The CLI
/// logs the error with its sources (`gui-cli.log`, and the terminal through the
/// stderr layer); an MSI type-18 action captures no output, so the MSI log
/// holds only the exit code. The messages say what went wrong and carry no path
/// or address.
#[derive(Debug, thiserror::Error)]
enum StartFailure {
    #[error(
        "the SCM answered the start with \"already running\", but the service is {0:?}, not running or starting, and this start does not wait for it to change"
    )]
    NotServing(ServiceState),
    #[error("the SCM answered the start with \"already running\", and the service's status could not be read")]
    Status(#[source] io::Error),
}

/// Whether a service in `state` is the one the start was after: up, or on its
/// way up. The one place that decides it, because `ServiceState` is foreign.
fn is_up_or_coming_up(state: ServiceState) -> bool {
    match state {
        ServiceState::Running => true,
        ServiceState::StartPending => true,
        // On its way down; a start does not wait for the stop.
        ServiceState::StopPending => false,
        // The SCM's "already running" answer can precede the process's exit.
        ServiceState::Stopped => false,
        // Hole's service accepts neither pause nor continue.
        ServiceState::Paused => false,
        ServiceState::PausePending => false,
        ServiceState::ContinuePending => false,
    }
}

/// Whether a failed `StartService` says the service is already running
/// (`ERROR_SERVICE_ALREADY_RUNNING`).
pub(super) fn already_running(error: &windows_service::Error) -> bool {
    let windows_service::Error::Winapi(io) = error else {
        return false;
    };
    io.raw_os_error() == i32::try_from(ERROR_SERVICE_ALREADY_RUNNING.0).ok()
}

impl StartConfig for RepairSession {
    fn start_type(&mut self) -> io::Result<StartType> {
        read_start_type(&self.service)
    }

    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        write_start_type(&self.service, to)
    }

    fn record_state(&mut self) -> RecordState {
        self.record.state()
    }

    fn clear_record(&mut self) -> io::Result<()> {
        self.record.clear()
    }

    fn write_record(&mut self) -> io::Result<()> {
        self.record.write()
    }

    fn record_changer(&mut self) -> Option<Changer> {
        self.record.changer()
    }
}

#[cfg(test)]
#[path = "repair_session_tests.rs"]
mod repair_session_tests;
