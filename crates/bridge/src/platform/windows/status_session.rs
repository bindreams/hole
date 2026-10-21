//! The SCM handle behind the GUI's read of whether the service is disabled.
//!
//! It holds no start-type lock and cannot write: a change in progress is read
//! from the record's stamp ([`crate::disable_record`]), not from the lock,
//! which an unprivileged user has no right to open.

use std::io;

use windows_service::service::Service;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::repair_session::READ_ACCESS;
use super::retire_session::read_start_type;
use super::{open_error_is_absent, scm_failure, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::ScmCall;
use crate::cutover::scm_wait::retire::StartRead;
use crate::disable_record::{Changer, RecordKey};
use crate::service_start::StartType;

/// An open `HoleBridge` service and the key its record lives in, for reading.
pub(super) struct StatusSession {
    service: Service,
    record: RecordKey,
}

impl StatusSession {
    /// Opens the service for reading, or `None` when the SCM has no entry.
    pub(super) fn open() -> io::Result<Option<Self>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        match manager.open_service(SERVICE_NAME, READ_ACCESS) {
            Ok(service) => Ok(Some(Self {
                service,
                record: RecordKey::service(),
            })),
            Err(e) if open_error_is_absent(&e) => Ok(None),
            Err(e) => Err(scm_failure(ScmCall::OpenService, e)),
        }
    }
}

impl StartRead for StatusSession {
    fn read_start_type(&mut self) -> io::Result<StartType> {
        read_start_type(&self.service)
    }

    fn read_changer(&mut self) -> Option<Changer> {
        self.record.changer()
    }
}
