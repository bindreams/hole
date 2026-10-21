//! The SCM handle behind the start-type repair, the enable, and the GUI's read
//! of whether the service is disabled.

use std::io;

use windows::Win32::Foundation::ERROR_SERVICE_ALREADY_RUNNING;
use windows_service::service::{Service, ServiceAccess};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::retire_session::{read_start_type, write_start_type};
use super::start_type_lock::{log_wait, Held, StartTypeLock};
use super::{open_error_is_absent, scm_failure, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::ScmCall;
use crate::cutover::scm_wait::retire::{StartConfig, StartWrite};
use crate::disable_record::{RecordKey, RecordState};
use crate::service_start::StartType;

/// The rights a read of the start type needs, and all an unprivileged caller
/// (the GUI) is asked for.
pub(super) const READ_ACCESS: ServiceAccess = ServiceAccess::QUERY_CONFIG;

/// The rights a repair needs: the start type read and written.
pub(super) const REPAIR_ACCESS: ServiceAccess = ServiceAccess::QUERY_CONFIG.union(ServiceAccess::CHANGE_CONFIG);

/// The rights an enable needs: a repair's, and the start.
pub(super) const ENABLE_ACCESS: ServiceAccess = REPAIR_ACCESS.union(ServiceAccess::START);

/// An open `HoleBridge` service and the key its record lives in.
pub(super) struct RepairSession {
    service: Service,
    record: RecordKey,
    /// Held from before the first read to after the last write. Last, so it is
    /// released after everything above is closed.
    _held: Held,
}

/// What the GUI's status read finds when it opens the service.
pub(super) enum Reading {
    /// Another thread holds the start-type lock: a change is in progress.
    InChange,
    /// The service opened (`Some`) or the SCM has no entry (`None`).
    Session(Option<RepairSession>),
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

    /// The GUI's open: without waiting for the start-type lock, which another
    /// thread holds while it changes the start type and the record.
    pub(super) fn open_unless_in_change(lock: &StartTypeLock, access: ServiceAccess) -> io::Result<Reading> {
        match lock.try_acquire()? {
            Some(held) => Self::open_holding(held, access).map(Reading::Session),
            None => Ok(Reading::InChange),
        }
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

    /// Starts the service. A service that is already running is the state the
    /// start was after, so it is success.
    pub(super) fn start(&self) -> io::Result<()> {
        match self.service.start::<&str>(&[]) {
            Ok(()) => Ok(()),
            Err(e) if already_running(&e) => Ok(()),
            Err(e) => Err(scm_failure(ScmCall::StartService, e)),
        }
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
}

#[cfg(test)]
#[path = "repair_session_tests.rs"]
mod repair_session_tests;
