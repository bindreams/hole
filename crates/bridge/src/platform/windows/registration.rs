//! The bridge service's SCM registration: how `install` configures a new
//! service, and what the running bridge repairs of its own.
//!
//! Each is one function that production and the privileged tests both call, so
//! a test that registers or starts a service runs the same steps and a step
//! dropped from either fails one. The order of the steps of `install` and of
//! the bridge's startup is one function over a trait of its steps
//! ([`install_service`], [`run_startup_steps`]), so a test runs the order with a
//! recording implementation.

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

/// The steps of `install`, in the order [`install_service`] takes them.
pub trait NewServiceSteps {
    /// What the service is, once created.
    type Service;
    /// Create the service.
    fn create(&mut self) -> io::Result<Self::Service>;
    /// What the install cannot do without ([`configure_new_service`]).
    fn configure(&mut self, service: &Self::Service) -> io::Result<()>;
    /// Restart-on-failure.
    fn failure_actions(&mut self, service: &Self::Service) -> io::Result<()>;
}

/// Create a service and configure it. The configuration is required and its
/// failure fails the install. Auto-restart is hardening, applied on the
/// just-created handle (no re-open, which can race SCM propagation right after
/// the create); its failure is a warning, since failing the whole install (an
/// MSI custom action) over it would be worse than shipping without it.
pub fn install_service<S: NewServiceSteps>(steps: &mut S) -> io::Result<()> {
    let service = steps.create()?;
    steps.configure(&service)?;
    if let Err(e) = steps.failure_actions(&service) {
        warn!(error = %e, "could not configure SCM restart-on-failure; service installed without auto-restart");
    }
    Ok(())
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

/// The steps the `--service` bridge takes at startup once it reports Running,
/// in the order [`run_startup_steps`] runs them. A step's failure is its own to
/// log; none stops the start.
// Run on the service's own runtime by `block_on`, never spawned, so the
// futures need no `Send` bound.
#[allow(async_fn_in_trait)]
pub trait StartupSteps {
    /// [`run_startup_repairs`].
    async fn repairs(&mut self);
    /// DNS recovery.
    async fn recover_dns(&mut self);
    /// Forward the SCM's Stop to the root cancellation token.
    fn forward_shutdown(&mut self);
    /// Route recovery, recording the result for the connect path.
    async fn recover_routes(&mut self);
    /// Reconcile the persisted target.
    async fn reconcile(&mut self);
    /// Reap the plugins a crashed bridge left recorded.
    async fn reap_plugins(&mut self);
    /// Sweep native-crash markers.
    async fn sweep_crash_markers(&mut self);
    /// Sweep `hole.exe.old-*` leftovers.
    async fn sweep_old_binaries(&mut self);
}

/// Run the startup steps in order.
///
/// - The repairs come first: a bridge wedged or stopped in any later step never
///   reaches a repair placed after it.
/// - DNS recovery runs first of the state recoveries.
/// - The Stop is forwarded before the reconcile, so a Stop that arrives mid-boot
///   abandons the auto-connect, and the reconcile follows the route recovery it
///   reads.
pub async fn run_startup_steps<S: StartupSteps>(steps: &mut S) {
    steps.repairs().await;
    steps.recover_dns().await;
    steps.forward_shutdown();
    steps.recover_routes().await;
    steps.reconcile().await;
    steps.reap_plugins().await;
    steps.sweep_crash_markers().await;
    steps.sweep_old_binaries().await;
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod registration_tests;
