// Windows: service management via windows-service crate.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::cutover::scm_wait::call_error::{ScmCall, ServiceGone};
use crate::cutover::scm_wait::repair::{self, InstallStart, RepairStep};
use crate::cutover::scm_wait::retire::{retire_over, Disposition};
use crate::disable_record::DisabledBy;
use crate::service_ctrl::{self, Control, ControlResult, StatusHandle};
use crate::service_stop::{self, StopPhase, StopProgress};

#[path = "windows/retire_session.rs"]
mod retire_session;
pub use crate::cutover::scm_wait::retire::Opening;
pub use retire_session::{GoneSession, RetireSession};
#[path = "windows/stop_session.rs"]
mod stop_session;
pub use stop_session::StopSession;
#[path = "windows/repair_session.rs"]
mod repair_session;
use repair_session::{RepairSession, ENABLE_ACCESS, READ_ACCESS, REPAIR_ACCESS};
#[path = "windows/registration.rs"]
pub mod registration;
#[path = "windows/service_processes.rs"]
mod service_processes;
pub use service_processes::scan_service_processes;
#[path = "windows/service_sid.rs"]
mod service_sid;
pub use service_sid::{ServiceSid, SidRepair, SidRepairOutcome};

// Constants ===========================================================================================================

pub const SERVICE_NAME: &str = "HoleBridge";
pub const SERVICE_DISPLAY_NAME: &str = "Hole Bridge";
pub const SERVICE_DESCRIPTION: &str = "Transparent proxy bridge for the Hole application";

// Service entry =======================================================================================================

/// Socket path override set by the CLI before service dispatch.
static SOCKET_PATH_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// State directory override set by the CLI before service dispatch.
static STATE_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// Log directory override set by the CLI before service dispatch.
/// Used by diagnostic artefacts to land alongside `bridge.log` in the
/// same directory.
static LOG_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// GUI build version override set by the CLI before service dispatch. The
/// `bind` runs inside `service_main` (a SCM callback with no access to
/// `run`'s args), so the version is threaded through this static.
static VERSION_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Run as a Windows Service (called by the service control manager).
pub fn run(socket_path: &Path, state_dir: &Path, log_dir: &Path, version: &str) -> std::io::Result<()> {
    let default = hole_common::protocol::default_bridge_socket_path();
    if socket_path != default {
        SOCKET_PATH_OVERRIDE.set(socket_path.to_owned()).ok();
    }
    STATE_DIR_OVERRIDE.set(state_dir.to_owned()).ok();
    LOG_DIR_OVERRIDE.set(log_dir.to_owned()).ok();
    VERSION_OVERRIDE.set(version.to_owned()).ok();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| scm_failure(ScmCall::StartServiceCtrlDispatcher, e))
}

/// `error`, which a `windows_service` call returned, as `call`'s typed failure.
/// `windows_service::Error::Winapi` displays only as "IO error in winapi call",
/// keeping the OS error as its source, so a failure that reaches a log through
/// `{e}` loses both the call and the Win32 code unless it is re-typed here.
fn scm_failure(call: ScmCall, error: windows_service::Error) -> std::io::Error {
    match error {
        windows_service::Error::Winapi(os) => call.failed_with(&os),
        other => std::io::Error::other(format!("{} failed: {other}", call.name())),
    }
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "service failed");
    }
}

/// What [`register_stop_handler`] registered.
pub struct RegisteredStop<F> {
    pub status_handle: StatusHandle,
    pub progress: std::sync::Arc<StopProgress<F>>,
}

/// Register the control handler of a `HoleBridge` service process and return
/// its status handle with the shared stop progress. A Stop or Shutdown reports
/// StopPending through `send` first, so the SCM stops seeing `Running` the
/// moment the Stop lands whatever the main task is still awaiting, then
/// signals `shutdown_tx`. `observe` sees every control before it is handled;
/// it runs on the SCM's handler thread outside the panic catch, so it must
/// return promptly and must not panic. A second call in one process is an
/// `AlreadyExists` error (see `service_ctrl::register`).
///
/// `StopPending` is reported from the handler (an SCM thread) as well as from
/// the main task, so the progress is shared and the status handle, which only
/// exists once `register` returns, is filled in afterwards. The SCM delivers no
/// Stop before `Running`, which the caller reports after this returns.
///
/// Shared with the `test_service` helper, so the privileged tests run this
/// wiring.
pub fn register_stop_handler<S>(
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    send: S,
    observe: impl Fn(Control) + Send + Sync + 'static,
) -> std::io::Result<RegisteredStop<impl Fn(StopPhase) -> std::io::Result<()>>>
where
    S: Fn(&StatusHandle, StopPhase) -> std::io::Result<()> + Send + Sync + 'static,
{
    let status_cell: std::sync::Arc<OnceLock<StatusHandle>> = std::sync::Arc::new(OnceLock::new());
    let stop = std::sync::Arc::new(StopProgress::new(service_stop::scm_reporter(
        std::sync::Arc::clone(&status_cell),
        send,
    )));

    let handler_stop = std::sync::Arc::clone(&stop);
    let event_handler = move |control: Control| -> ControlResult {
        observe(control);
        control.handle(|| service_stop::stop_control(&handler_stop, &shutdown_tx))
    };

    let status_handle = service_ctrl::register(SERVICE_NAME, event_handler)?;
    let _ = status_cell.set(status_handle);
    Ok(RegisteredStop {
        status_handle,
        progress: stop,
    })
}

/// Report `phase` to the SCM as StopPending: the bridge's `send` for
/// [`register_stop_handler`].
pub fn report_stop_pending(handle: &StatusHandle, phase: StopPhase) -> std::io::Result<()> {
    handle.set_service_status(&stop_pending_status(phase))
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    let RegisteredStop {
        status_handle,
        progress: stop,
    } = register_stop_handler(shutdown_tx, report_stop_pending, |_| {})?;

    // Report StartPending, NOT Running: the cutover child exits on the SCM
    // `Running` edge, so `Running` is deferred until after the socket binds AND
    // the marker is swept (`sweep_marker_then_ready`) — so a healthy update never
    // presents "marker present + dead driver". No controls accepted while starting.
    status_handle.set_service_status(&ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })?;

    info!("Windows service starting");

    // Build and run the tokio runtime
    let rt = tokio::runtime::Runtime::new()?;
    // `StatusHandle` is Copy (a raw SCM handle wrapper); capture it for the
    // deferred `Running` report inside the async block.
    let status_handle_ready = status_handle;
    let stop_progress = std::sync::Arc::clone(&stop);
    let run_result: Result<(), Box<dyn std::error::Error>> = rt.block_on(async move {
        let state_dir = STATE_DIR_OVERRIDE
            .get()
            .cloned()
            .unwrap_or_else(hole_common::paths::default_state_dir);
        let log_dir = LOG_DIR_OVERRIDE.get().cloned().unwrap_or_else(service_log_dir);

        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::proxy_manager::ProxyManager::new(
                crate::proxy::ShadowsocksProxy::new(),
                tun_engine::routing::SystemRouting::new(state_dir.clone(), None),
            )
            .with_state_dir(state_dir.clone()),
        ));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        let socket_path = SOCKET_PATH_OVERRIDE
            .get()
            .cloned()
            .unwrap_or_else(hole_common::protocol::default_bridge_socket_path);
        // Bind BEFORE the liveness acquire and BEFORE recovery — a second
        // instance's bind() fails before it can touch routing state or contend
        // on the liveness lock, matching crate::liveness's documented invariant
        // (BridgeLiveness::acquire's doc: "a second real bridge instance never
        // reaches this call — the IPC socket bind already refuses it first").
        // Route recovery is offloaded via spawn_blocking so a hung netsh/route
        // command cannot wedge the runtime while the IPC socket is bound but
        // not yet serving.
        let version = VERSION_OVERRIDE.get().cloned().unwrap_or_else(|| "unknown".to_string());
        // The `--service` daemon runs as SYSTEM and its dirs are SYSTEM-owned by
        // design; no real user to chown writes back to. (chown is a macOS no-op
        // anyway, but pass `None` to keep the daemon contract explicit.)
        let server = crate::ipc::IpcServer::bind_with_dirs(
            &socket_path,
            proxy,
            &version,
            log_dir.clone(),
            state_dir.clone(),
            None,
        )?;

        // Held for this bridge's entire run — see crate::liveness's module
        // doc and foreground.rs's identical acquisition.
        let state_dir_liveness = state_dir.clone();
        let _liveness =
            tokio::task::spawn_blocking(move || crate::liveness::BridgeLiveness::acquire(&state_dir_liveness, None))
                .await??;
        // Socket is bound: sweep the marker, then report Running (see sweep_marker_then_ready).
        sweep_marker_then_ready(&log_dir, || {
            status_handle_ready.set_service_status(&ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::ZERO,
                process_id: None,
            })
        })?;
        info!("Windows service started");
        // Root cancellation token for the SCM service, fed by the same
        // `shutdown_rx` oneshot the control handler signals; the startup forwards
        // the Stop to it before reconciling, so an SCM Stop arriving mid-boot
        // abandons the auto-connect rather than racing it.
        #[allow(clippy::disallowed_methods)]
        // Service entry point — see clippy.toml's CancellationToken::new list.
        let shutdown = tokio_util::sync::CancellationToken::new();
        registration::run_startup_steps(&mut ServiceStartup {
            state_dir: state_dir.clone(),
            log_dir: log_dir.clone(),
            proxy: std::sync::Arc::clone(&proxy_shutdown),
            shutdown: shutdown.clone(),
            stop_progress: std::sync::Arc::clone(&stop_progress),
            shutdown_rx: Some(shutdown_rx),
        })
        .await;

        // Capture WFP + NDIS state after recovery; see
        // `diagnostics::{wfp,ndis}`.
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::wfp::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "wfp startup snapshot task panicked");
        }
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::ndis::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "ndis startup snapshot task panicked");
        }

        // Always-on ETW consumer, held for the service's run lifetime; Drop
        // may abandon rather than join its processing thread if reclaim
        // can't be confirmed (see `etw.rs` module doc, "Drain on Drop").
        let etw_guard = match crate::diagnostics::etw::start_consumer() {
            Ok(g) => Some(g),
            Err(e) => {
                tracing::error!(error = %e, "etw consumer failed to start");
                None
            }
        };

        // Returns once the connection tasks are gone, so the proxy manager's
        // last handle is the one dropped in `DropResources`.
        if let Err(e) = server.run_until(shutdown.cancelled()).await {
            error!(error = %e, "IPC server error");
        }
        info!("shutdown signal received");

        // Clean shutdown: stop proxy before exiting. Neither event is a user
        // disconnect, so the target is left unchanged either way; only the
        // event differs, distinguishing an update cutover from a plain
        // machine shutdown for anyone reading the log/history.
        service_stop::tear_down_service(
            &stop_progress,
            proxy_shutdown,
            || crate::foreground::shutdown_reason(hole_common::update_marker::is_present(&log_dir)),
            etw_guard,
            (_liveness, shutdown),
        )
        .await;

        Ok(())
    });

    if let Err(e) = &run_result {
        error!(error = %e, "bridge runtime error");
    }

    // Dropping the runtime joins blocking tasks, so `Stopped` follows it. Report
    // stopped even on error; non-zero exit code if the runtime failed.
    let exit_code = if run_result.is_err() { 1 } else { 0 };
    service_stop::finish_stop(
        &stop,
        || drop(rt),
        || status_handle.set_service_status(&stopped_status(exit_code)),
    );

    run_result
}

/// The startup steps of the real service, taken in the order
/// [`registration::run_startup_steps`] gives.
struct ServiceStartup<F> {
    state_dir: PathBuf,
    log_dir: PathBuf,
    proxy: std::sync::Arc<tokio::sync::Mutex<crate::proxy_manager::ProxyManager>>,
    shutdown: tokio_util::sync::CancellationToken,
    stop_progress: std::sync::Arc<StopProgress<F>>,
    /// Taken by [`forward_shutdown`](registration::StartupSteps::forward_shutdown),
    /// which runs once.
    shutdown_rx: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl<F> registration::StartupSteps for ServiceStartup<F>
where
    F: Fn(StopPhase) -> std::io::Result<()> + Send + Sync + 'static,
{
    async fn repairs(&mut self) {
        // A failure never stops this start (see `run_startup_repairs`).
        if let Err(e) = tokio::task::spawn_blocking(registration::run_startup_repairs).await {
            warn!(error = %e, "startup repairs task panicked");
        }
    }

    async fn recover_dns(&mut self) {
        // DNS recovery runs first of the state recoveries; see crate::dns::recovery
        // docs for ordering.
        let state_dir = self.state_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir)).await
        {
            tracing::warn!(error = %e, "recover_dns_config task panicked");
        }
    }

    fn forward_shutdown(&mut self) {
        let shutdown_rx = self
            .shutdown_rx
            .take()
            .expect("the startup forwards the Stop once, so the receiver is still here");
        let shutdown = self.shutdown.clone();
        let stop_progress = std::sync::Arc::clone(&self.stop_progress);
        tokio::spawn(async move {
            service_stop::forward_stop(&stop_progress, shutdown_rx, || shutdown.cancel()).await;
        });
    }

    async fn recover_routes(&mut self) {
        crate::route_recovery::recover_and_record(&self.state_dir, &self.proxy).await;
    }

    async fn reconcile(&mut self) {
        // Reconcile the persisted target now, before any GUI or client has had a
        // chance to connect (narrows, does not close, #617's boot->first-connect
        // gap: a failed connect engages nothing) — must run after recovery above, see
        // crate::reconciler::reconcile_once's own doc.
        crate::reconciler::reconcile_once(&self.state_dir, None, &self.proxy, &self.shutdown).await;
    }

    async fn reap_plugins(&mut self) {
        let state_dir = self.state_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::plugin_recovery::reap_recorded_plugins(&state_dir)).await
        {
            tracing::warn!(error = %e, "reap_recorded_plugins task panicked");
        }
    }

    async fn sweep_crash_markers(&mut self) {
        // Native-crash observability (bindreams/hole#438): sweep crash
        // markers left by a previously-crashed service bridge. Markers land
        // in the service log dir (C:\ProgramData\hole\logs), NOT state_dir.
        let log_dir = self.log_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir)).await {
            tracing::warn!(error = %e, "crash sweep task panicked");
        }
    }

    async fn sweep_old_binaries(&mut self) {
        // Sweep `hole.exe.old-*` left by a prior cutover swap's best-effort delete
        // (it fails while an old process still maps the renamed inode).
        if let Err(e) = tokio::task::spawn_blocking(sweep_old_binaries_in_install_dir).await {
            tracing::warn!(error = %e, "old-binary sweep task panicked");
        }
    }
}

/// The `StopPending` status reported while `phase` is in progress.
fn stop_pending_status(phase: StopPhase) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: phase.checkpoint(),
        wait_hint: phase.wait_hint(),
        process_id: None,
    }
}

/// The terminal `Stopped` status.
fn stopped_status(exit_code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

/// Clear a stale update-in-progress marker on the new bridge's post-bind sweep.
/// The marker's presence is co-extensive with "a cutover during which no bridge
/// answered"; once this bridge binds, the cutover is done. Remove-by-path so a
/// from->to schema bump across the cutover cannot strand it.
pub(crate) fn sweep_marker(log_dir: &Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(error = %e, "failed to clear update-in-progress marker");
    }
}

/// Sweep the completed cutover's marker, verify it is gone, THEN report `Running`
/// so the cutover child (which exits on the `Running` edge) exits only after the
/// marker is gone. A healthy update therefore never presents "marker present plus
/// driver dead" — before this the child is alive (Mask), after it the marker is
/// already swept (PassThrough).
///
/// The `read().is_some()` re-check guards the reachable case of an external
/// process holding the marker open without `FILE_SHARE_DELETE`: reporting
/// `Running` with a stale marker would false-fail the healthy update, so the start
/// fails instead (SCM restarts and retries the sweep).
fn sweep_marker_then_ready<R: FnOnce() -> std::io::Result<()>>(
    log_dir: &Path,
    report_running: R,
) -> std::io::Result<()> {
    sweep_marker_then_ready_with(|| sweep_marker(log_dir), log_dir, report_running)
}

/// [`sweep_marker_then_ready`] with the sweep injected so the marker-survives-sweep
/// branch is unit-testable (a no-op sweep leaves the marker present).
fn sweep_marker_then_ready_with<S: FnOnce(), R: FnOnce() -> std::io::Result<()>>(
    sweep: S,
    log_dir: &Path,
    report_running: R,
) -> std::io::Result<()> {
    sweep();
    if hole_common::update_marker::is_present(log_dir) {
        return Err(std::io::Error::other(
            "cutover marker still present after sweep; refusing to report Running",
        ));
    }
    report_running()
}

/// Prefix of a rename-away leftover from a cutover swap (`<file>.old-<ver>`); see
/// `cutover::os::windows::old_name`.
const OLD_BINARY_PREFIX: &str = "hole.exe.old-";

/// Sweep `hole.exe.old-*` leftovers from the install dir. The cutover swap renames
/// the live binary aside and tries a best-effort delete, which fails while an old
/// GUI/bridge still maps the inode; the next bridge start (once nothing maps it)
/// removes the survivors. A still-mapped file's delete fails and is left for a
/// later start. No delete cap — the set is bounded by the number of past updates.
pub(crate) fn sweep_old_binaries(install_dir: &Path) {
    let entries = match std::fs::read_dir(install_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, dir = %install_dir.display(), "old-binary sweep: read_dir failed");
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(OLD_BINARY_PREFIX) {
            continue;
        }
        if let Err(e) = std::fs::remove_file(entry.path()) {
            // Still mapped by a live process — expected; a later start retries.
            tracing::debug!(error = %e, file = %name, "old-binary sweep: still mapped, deferring");
        }
    }
}

/// Resolve the install dir from `current_exe` and sweep its `hole.exe.old-*`
/// leftovers. Thin wrapper so the dir-scanning core (`sweep_old_binaries`) stays
/// table-testable.
fn sweep_old_binaries_in_install_dir() {
    match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        Some(install_dir) => sweep_old_binaries(&install_dir),
        None => tracing::warn!("old-binary sweep: could not resolve install dir from current_exe"),
    }
}

// Install/uninstall ===================================================================================================

/// System log directory for the Windows service (`C:\ProgramData\hole\logs`).
/// Deduped to the single cross-privilege resolver the GUI also reads from.
fn service_log_dir() -> PathBuf {
    hole_common::update_marker::service_log_dir()
}

/// Install the bridge as a Windows Service.
///
/// The service is registered to run
/// `<binary_path> bridge run --service --log-dir <log> --state-dir <state>`
/// with auto-start, then `apply_failure_actions` writes the restart-on-failure
/// SCM config directly on the just-created handle — best-effort (warn-and-continue),
/// since a SCM hiccup must not fail the install itself. This deliberately avoids
/// `ensure_failure_actions` (which re-opens the service and propagates errors);
/// that stricter re-open path is reserved for the cutover child's post-update
/// refresh (see `cutover::run_detached`), which also brings an install base that
/// predates this config up to date — so a bare `install()` is not the only path
/// that provisions it.
pub fn install(binary_path: &Path) -> std::io::Result<()> {
    install_as(binary_path, InstallStart::Automatic)
}

/// [`install`] with the start type the service is registered with.
pub fn install_as(binary_path: &Path, start: InstallStart) -> std::io::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;

    let log_dir = service_log_dir();
    let state_dir = crate::cutover::service_state_dir();
    // Create log + state dirs during install (running elevated) so the service
    // itself (running as LocalSystem) can write to them on its first run.
    let _ = std::fs::create_dir_all(&log_dir);
    let _ = std::fs::create_dir_all(&state_dir);

    let service_info = service_info(binary_path, start, log_dir, state_dir);

    registration::install_service(&mut NewService {
        manager: &manager,
        info: &service_info,
    })?;
    info!("Windows service installed");
    Ok(())
}

/// What `install` registers: the bridge as `LocalSystem`, running
/// `<binary_path> bridge run --service --log-dir <log> --state-dir <state>`.
fn service_info(binary_path: &Path, start: InstallStart, log_dir: PathBuf, state_dir: PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: match start {
            InstallStart::Automatic => ServiceStartType::AutoStart,
            InstallStart::LeaveDisabled => ServiceStartType::Disabled,
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path.to_path_buf(),
        launch_arguments: vec![
            "bridge".into(),
            "run".into(),
            "--service".into(),
            "--log-dir".into(),
            log_dir.into_os_string(),
            "--state-dir".into(),
            state_dir.into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    }
}

/// The steps of [`install`] against the SCM.
struct NewService<'a> {
    manager: &'a ServiceManager,
    info: &'a ServiceInfo,
}

impl registration::NewServiceSteps for NewService<'_> {
    type Service = windows_service::service::Service;

    fn create(&mut self) -> std::io::Result<Self::Service> {
        self.manager
            .create_service(self.info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .map_err(|e| scm_failure(ScmCall::CreateService, e))
    }

    /// The description and the service SID type (what lets an uninstall tell the
    /// service's process from a stranger that reuses its id) are required: their
    /// failure fails the install.
    fn configure(&mut self, service: &Self::Service) -> std::io::Result<()> {
        registration::configure_new_service(service)
    }

    fn failure_actions(&mut self, service: &Self::Service) -> std::io::Result<()> {
        apply_failure_actions(service)
    }
}

/// Restart-on-failure SCM actions. Fires on a crash / non-zero exit, not a
/// graceful `Stopped(0)`. `reset_period` is finite so a run of crashes keeps
/// restarting (the counter resets after a day without a failure).
fn restart_failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: std::time::Duration::from_secs(1),
        }]),
    }
}

/// The rights a handle needs for [`apply_failure_actions`]: `CHANGE_CONFIG` for
/// `ChangeServiceConfig2W`, and `START` because the actions include a restart
/// ([`ChangeServiceConfig2W`, `SERVICE_CONFIG_FAILURE_ACTIONS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)):
/// "If the service controller handles the SC_ACTION_RESTART action, hService
/// must have the SERVICE_START access right."
const FAILURE_ACTIONS_ACCESS: ServiceAccess = ServiceAccess::CHANGE_CONFIG.union(ServiceAccess::START);

/// Write the restart-on-failure SCM config to an open `HoleBridge` handle (needs
/// [`FAILURE_ACTIONS_ACCESS`]): the `Restart` action plus the non-crash-failures flag (so a
/// graceful `Stopped(1)` from a failed bind is restarted too, while a clean
/// `Stopped(0)` user/cutover stop is not).
fn apply_failure_actions(service: &windows_service::service::Service) -> std::io::Result<()> {
    service
        .update_failure_actions(restart_failure_actions())
        .and_then(|()| service.set_failure_actions_on_non_crash_failures(true))
        .map_err(|e| scm_failure(ScmCall::ChangeServiceConfig2, e))
}

/// Open the installed `HoleBridge` service and apply the restart-on-failure
/// config. Idempotent (a re-apply re-writes the same config). Called by the
/// cutover child so an install base predating this config is brought up to date
/// as part of the update itself.
pub fn ensure_failure_actions() -> std::io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
    let service = manager
        .open_service(SERVICE_NAME, FAILURE_ACTIONS_ACCESS)
        .map_err(|e| scm_failure(ScmCall::OpenService, e))?;
    apply_failure_actions(&service)
}

/// Stop and uninstall the bridge Windows Service.
///
/// The stop is FATAL here, not best-effort. `DeleteService` against a
/// still-running service *succeeds*: it only marks the entry for deletion, and
/// the service keeps running until stopped. The registration is the handle a
/// later attempt has, so keeping it over a failed stop is what makes the
/// uninstall retryable instead of terminal.
///
/// The stop, the delete and the check after it are one SCM session
/// ([`retire`](crate::cutover::scm_wait::retire::retire)), because the service
/// carries restart-on-failure: a service the SCM is about to restart reads
/// STOPPED, and separate probes and acts each decided on a state the SCM could
/// change under them. A service already
/// marked for deletion still opens, and is stopped through its handle.
pub fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
    if retire_service(Disposition::Deregister)? {
        info!("Windows service uninstalled");
    }
    Ok(())
}

/// Stop the bridge service *without* deregistering it, tolerating a host where
/// SCM has nothing to stop.
///
/// The uninstall orchestration calls this unconditionally, before it consults
/// any registration record: whether a bridge is running and whether SCM still
/// has a row for it are independent facts, and the fail-closed covers are held
/// by the live process, not by the row. See `setup::uninstall_bridge_with`.
///
/// An absent entry (never registered) is `Ok`: there is nothing here to fail
/// over. A service marked for deletion by a prior `DeleteService` still opens,
/// so it is stopped like any other; if it has nothing to wait on and its state
/// is live, that is an error. The cover release that follows carries the real
/// guarantee; it holds the bridge's own liveness lock and refuses outright if a
/// bridge is still alive.
pub fn ensure_stopped() -> Result<(), Box<dyn std::error::Error>> {
    retire_service(Disposition::StopOnly).map(|_| ())
}

/// [`retire_over`] on a fresh session. `Ok(false)` when the SCM has no entry to
/// act on, after waiting out any process of it that outlived the entry;
/// `Ok(true)` when the retirement ran.
fn retire_service(disposition: Disposition) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(retire_over(RetireSession::open()?, GoneSession::default, disposition)?)
}

/// Whether an `open_service` failure means the entry does not exist.
fn open_error_is_absent(e: &windows_service::Error) -> bool {
    let windows_service::Error::Winapi(io) = e else {
        return false;
    };
    io.raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .and_then(ServiceGone::of_code)
        .is_some_and(ServiceGone::is_absent_at_open)
}

/// Puts the service's start type right before an elevated path starts it, and
/// says what it found ([`repair::repair`]): the Disabled start type an
/// interrupted uninstall left is reset to automatic and the record cleared; a
/// Disabled start type with no record is an administrator's and is left, and
/// the caller does not start the service. With no service registered there is
/// nothing to repair: the record lived in the service's key.
pub fn repair_interrupted_uninstall() -> std::io::Result<RepairStep> {
    let Some(mut session) = RepairSession::open(REPAIR_ACCESS)? else {
        return Ok(RepairStep::Nothing);
    };
    let step = repair::repair(&mut session).map_err(std::io::Error::other)?;
    match step {
        RepairStep::Nothing => {}
        RepairStep::ClearRecordOnly => {
            info!("swept a record that an uninstall disabled a service that is not disabled")
        }
        RepairStep::ResetThenClear => {
            info!("an interrupted uninstall had left the service disabled; set it to automatic")
        }
        RepairStep::LeaveDisabled => info!("the service is disabled on this computer, and is left disabled"),
    }
    Ok(step)
}

/// Who disabled the service, if it is disabled, for an elevated caller: an
/// unreadable start type is its error, because the caller acts on it.
/// A record that cannot be read counts as present.
pub fn disabled_by() -> std::io::Result<Option<DisabledBy>> {
    let Some(mut session) = RepairSession::open(READ_ACCESS)? else {
        return Ok(None);
    };
    let step = repair::observe(&mut session).map_err(std::io::Error::other)?;
    Ok(step.disabled_by())
}

/// [`disabled_by`] for a reader that must never fail (the GUI's status, which
/// runs unprivileged). A service it cannot open or read is "not disabled", and
/// the reason is logged, the convention of [`is_installed`].
pub fn disabled_state() -> Option<DisabledBy> {
    let mut session = match RepairSession::open(READ_ACCESS) {
        Ok(Some(session)) => session,
        Ok(None) => return None,
        Err(e) => {
            warn!(error = %e, "could not open the service to read whether it is disabled");
            return None;
        }
    };
    let observed = repair::observe(&mut session);
    if let Err(e) = &observed {
        warn!(error = %e, "could not read whether the service is disabled");
    }
    repair::for_display(observed)
}

/// Sets the service's start type to automatic, clears the record, and starts
/// it: the administrator's explicit request to undo a disable, whoever made
/// it. A service already running is success.
pub fn enable() -> std::io::Result<()> {
    let Some(mut session) = RepairSession::open(ENABLE_ACCESS)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "the Hole service is not installed",
        ));
    };
    repair::enable(&mut session).map_err(std::io::Error::other)?;
    session.start()?;
    info!("Windows service enabled and started");
    Ok(())
}

// Start/stop ==========================================================================================================

/// Start the Windows Service via SCM.
pub fn start() -> std::io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .map_err(|e| scm_failure(ScmCall::OpenService, e))?;
    service
        .start::<&str>(&[])
        .map_err(|e| scm_failure(ScmCall::StartService, e))?;
    info!("Windows service started");
    Ok(())
}

// Query ===============================================================================================================

/// Check whether the service is registered in SCM.
pub fn is_installed() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok()
}

/// Check whether the service is registered and currently running.
pub fn is_running() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false;
    };
    let Ok(status) = service.query_status() else {
        return false;
    };
    status.current_state == ServiceState::Running
}

/// A valid marker for the post-bind-sweep test.
#[cfg(test)]
fn test_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        driver: cosca::identity::ProcessId::current()
            .to_record()
            .expect("persist this process's identity"),
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
