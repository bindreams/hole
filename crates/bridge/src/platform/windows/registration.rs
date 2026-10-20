//! The bridge service's SCM registration: how `install` configures a new
//! service, and what the running bridge repairs of its own.
//!
//! Each is one function that production and the privileged tests both call, so
//! a test that registers or starts a service runs the same steps and a step
//! dropped from either fails one.

use std::io;

use tracing::{info, warn};
use windows_service::service::Service;

use super::scm_failure;
use super::service_sid::{apply_service_sid, ensure_own_service_sid, SidRepairOutcome};
use super::SERVICE_DESCRIPTION;
use crate::cutover::scm_wait::call_error::ScmCall;

/// The configuration of a just-created service that `install` cannot do
/// without, so its failure fails the install: the description, and the service
/// SID type that lets an uninstall tell the service's process from a stranger
/// reusing its id (`ProcessHolds::hold_current`). Needs `CHANGE_CONFIG`.
pub fn configure_new_service(service: &Service) -> io::Result<()> {
    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| scm_failure(ScmCall::ChangeServiceConfig2, e))?;
    apply_service_sid(service)
}

/// What [`run_startup_repairs`] did, one field per repair.
#[derive(Debug)]
pub struct StartupRepairs {
    /// The service SID type, which only `bridge install` sets: a host updated
    /// in-app never got it.
    pub service_sid: io::Result<SidRepairOutcome>,
}

/// The repairs the `--service` bridge makes to its own registration at startup,
/// each logged here. A failure is a warning and never stops the start: these
/// gate only the uninstaller's wait, and a bridge that will not start for them
/// locks the user out. The SCM applies a repaired setting at the service's next
/// start.
///
/// Called first in `run_service`, before anything that can wedge or be stopped.
pub fn run_startup_repairs() -> StartupRepairs {
    let service_sid = ensure_own_service_sid();
    match &service_sid {
        Ok(SidRepairOutcome::Applied) => info!("set the service SID type; the next start of the service carries it"),
        Ok(SidRepairOutcome::AlreadySet) => {}
        Err(e) => warn!(error = %e, "could not set the service SID type"),
    }
    StartupRepairs { service_sid }
}
