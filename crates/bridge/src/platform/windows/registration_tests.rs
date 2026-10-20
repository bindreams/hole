use std::cell::RefCell;

use super::*;

type Log = RefCell<Vec<&'static str>>;

// install =============================================================================================================

/// A new service that records each step and fails the ones it is told to.
struct RecordingInstall<'a> {
    log: &'a Log,
    fail: &'static [&'static str],
}

impl RecordingInstall<'_> {
    fn step(&self, name: &'static str) -> io::Result<()> {
        self.log.borrow_mut().push(name);
        if self.fail.contains(&name) {
            return Err(io::Error::other(name));
        }
        Ok(())
    }
}

impl NewServiceSteps for RecordingInstall<'_> {
    type Service = ();

    fn create(&mut self) -> io::Result<()> {
        self.step("create")
    }
    fn configure(&mut self, _service: &()) -> io::Result<()> {
        self.step("configure")
    }
    fn failure_actions(&mut self, _service: &()) -> io::Result<()> {
        self.step("failure_actions")
    }
}

#[skuld::test]
fn a_new_service_is_created_then_configured_then_given_its_failure_actions() {
    let log = Log::default();
    install_service(&mut RecordingInstall { log: &log, fail: &[] }).unwrap();
    assert_eq!(*log.borrow(), ["create", "configure", "failure_actions"]);
}

/// The description and the service SID type are what the uninstall tells the
/// service's process from a stranger by: without them the install has failed.
#[skuld::test]
fn a_service_that_cannot_be_configured_fails_the_install_before_its_failure_actions() {
    let log = Log::default();
    let error = install_service(&mut RecordingInstall {
        log: &log,
        fail: &["configure"],
    })
    .expect_err("the configuration failed");
    assert_eq!(error.to_string(), "configure");
    assert_eq!(*log.borrow(), ["create", "configure"]);
}

/// A restart-on-failure that could not be written is not worth failing an MSI
/// custom action over: the service is installed without it.
#[skuld::test]
fn failure_actions_that_cannot_be_written_do_not_fail_the_install() {
    let log = Log::default();
    install_service(&mut RecordingInstall {
        log: &log,
        fail: &["failure_actions"],
    })
    .unwrap();
    assert_eq!(*log.borrow(), ["create", "configure", "failure_actions"]);
}

#[skuld::test]
fn a_service_that_cannot_be_created_is_configured_in_no_way() {
    let log = Log::default();
    install_service(&mut RecordingInstall {
        log: &log,
        fail: &["create"],
    })
    .expect_err("the create failed");
    assert_eq!(*log.borrow(), ["create"]);
}

// startup =============================================================================================================

/// A startup that records each step as it runs.
struct RecordingStartup<'a> {
    log: &'a Log,
}

impl StartupSteps for RecordingStartup<'_> {
    async fn repairs(&mut self) {
        self.log.borrow_mut().push("repairs");
    }
    async fn recover_dns(&mut self) {
        self.log.borrow_mut().push("recover_dns");
    }
    fn forward_shutdown(&mut self) {
        self.log.borrow_mut().push("forward_shutdown");
    }
    async fn recover_routes(&mut self) {
        self.log.borrow_mut().push("recover_routes");
    }
    async fn reconcile(&mut self) {
        self.log.borrow_mut().push("reconcile");
    }
    async fn reap_plugins(&mut self) {
        self.log.borrow_mut().push("reap_plugins");
    }
    async fn sweep_crash_markers(&mut self) {
        self.log.borrow_mut().push("sweep_crash_markers");
    }
    async fn sweep_old_binaries(&mut self) {
        self.log.borrow_mut().push("sweep_old_binaries");
    }
}

fn startup_order() -> Vec<&'static str> {
    let log = Log::default();
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(run_startup_steps(&mut RecordingStartup { log: &log }));
    log.into_inner()
}

fn at(order: &[&str], step: &str) -> usize {
    order
        .iter()
        .position(|s| *s == step)
        .unwrap_or_else(|| panic!("{step} must run: {order:?}"))
}

#[skuld::test]
fn every_startup_step_runs_exactly_once() {
    let mut order = startup_order();
    let mut steps = vec![
        "repairs",
        "recover_dns",
        "forward_shutdown",
        "recover_routes",
        "reconcile",
        "reap_plugins",
        "sweep_crash_markers",
        "sweep_old_binaries",
    ];
    order.sort_unstable();
    steps.sort_unstable();
    assert_eq!(order, steps);
}

/// A bridge wedged or stopped in any later step never reaches a repair placed
/// after it, and a repair gates only the uninstaller's wait: it comes first.
#[skuld::test]
fn the_startup_repairs_come_before_every_step_that_can_stop_the_bridge() {
    let order = startup_order();
    assert_eq!(order[0], "repairs", "{order:?}");
}

/// DNS recovery is the first of the state recoveries.
#[skuld::test]
fn dns_is_recovered_before_the_routes() {
    let order = startup_order();
    assert!(at(&order, "recover_dns") < at(&order, "recover_routes"), "{order:?}");
}

/// The reconcile reads what the recoveries repaired, and a Stop that arrives
/// during it must be able to abandon the auto-connect.
#[skuld::test]
fn the_reconcile_follows_the_route_recovery_and_the_shutdown_forwarding() {
    let order = startup_order();
    assert!(at(&order, "recover_routes") < at(&order, "reconcile"), "{order:?}");
    assert!(at(&order, "forward_shutdown") < at(&order, "reconcile"), "{order:?}");
}
