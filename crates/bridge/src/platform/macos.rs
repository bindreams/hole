// macOS: launchd bridge management.

use std::path::{Path, PathBuf};
use tracing::info;

use crate::plugin_repair::{EmbeddedPlugin, PluginDirLayout, Prepared, RepairOutcome, RepairVerdict};
use crate::proxy::PluginSource;

// Constants ===========================================================================================================

pub const LAUNCHD_LABEL: &str = "com.hole.bridge";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hole.bridge.plist";
pub const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.hole.bridge";
pub const SERVICE_LOG_DIR: &str = "/var/log/hole";
/// System state directory for the launchd daemon (Apple convention:
/// `/var/db/<daemon>`). Holds the bridge crash-recovery state files
/// (DNS, routes, plugins).
pub const SERVICE_STATE_DIR: &str = "/var/db/hole/state";
/// The folder only root can write, holding the plugins `hole` carries. The service makes it hold exactly those at
/// every start; `hole` itself stays at [`HELPER_PATH`].
pub const PLUGIN_DIR: &str = "/Library/Application Support/Hole";
/// A folder only root can write, where a plugin that extracts itself at run time puts what it extracts. Outside
/// [`PLUGIN_DIR`] on purpose: repair removes what it does not recognize there.
pub const SERVICE_RUNTIME_DIR: &str = "/var/run/hole";

/// The service's plugin folder and its owner, root.
fn plugin_dir_layout() -> PluginDirLayout {
    PluginDirLayout {
        dir: PathBuf::from(PLUGIN_DIR),
        owner: (0, 0),
    }
}

/// Where the service finds its plugins: [`PLUGIN_DIR`], not derived from the executable, once `verdict` says the
/// repair of this start made it hold what `hole` carries.
pub fn service_plugin_source(verdict: RepairVerdict) -> PluginSource {
    PluginSource::Managed {
        layout: plugin_dir_layout(),
        runtime_dir: PathBuf::from(SERVICE_RUNTIME_DIR),
        verdict,
    }
}

/// Where a foreground bridge started with `--plugin-dir DIR` finds its plugins: `DIR`, read and never written, and
/// only if its layout stamp is current. An error unless `DIR` names a directory.
pub fn explicit_plugin_source(dir: PathBuf) -> std::io::Result<PluginSource> {
    Ok(PluginSource::ExplicitStamped {
        dir: crate::proxy::plugin_source::absolute_plugin_dir(dir)?,
    })
}

// Plist generation ====================================================================================================

/// Generate the launchd plist XML for the bridge.
///
/// Note: we deliberately do NOT set `StandardOutPath` / `StandardErrorPath`.
/// The bridge installs an FD-level stdio redirect in
/// [`hole_common::logging::init`] that captures FD 1 and FD 2 into the
/// `tracing` pipeline and writes them to the rolling daily file under
/// `{log_dir}/bridge.log`. A launchd-side capture would only produce
/// duplicate files.
pub fn generate_plist(binary_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
        <string>bridge</string>
        <string>run</string>
        <string>--service</string>
        <string>--log-dir</string>
        <string>{log_dir}</string>
        <string>--state-dir</string>
        <string>{state_dir}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        binary_path = binary_path,
        log_dir = SERVICE_LOG_DIR,
        state_dir = SERVICE_STATE_DIR,
    )
}

// launchctl helper ====================================================================================================

/// Run `launchctl` with captured stdout/stderr. Logs captured output via
/// tracing on both success (debug level) and failure (level chosen by
/// caller). Returns Ok iff the exit status was success; the caller gets a
/// structured `io::Error::other(...)` with the operation label baked in.
///
/// Output is captured (not inherited) so launchctl errors (bad plist,
/// permissions, missing service) land in bridge.log instead of a terminal
/// nobody sees in service mode.
///
/// Every call site is fail-loud, because at every one of them a non-zero exit
/// IS the failure. `ensure_stopped`'s bootout is the caller that is not —
/// launchd exits non-zero there both for a refusal and for a job it does not
/// have — so it does not come through here; it runs
/// [`launchctl_status`] and classifies what launchd has afterwards.
fn run_launchctl(label: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    let output = util::system_tool::SystemTool::Launchctl
        .command()?
        .args(args)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        tracing::error!(
            %stdout,
            %stderr,
            status = ?output.status,
            "launchctl {label} failed",
        );
        return Err(std::io::Error::other(format!("launchctl {label} failed: {stderr}")));
    }
    tracing::debug!(%stdout, "launchctl {label} ok");
    Ok(output)
}

/// Run `launchctl` with captured output and hand back its exit status WITHOUT
/// judging it, for the one caller whose non-zero status is not yet a failure.
/// `Ok(None)` is launchctl killed by a signal; `Err` is a spawn failure.
///
/// The output is logged at `info`, which the bridge's default global `info`
/// filter lets through: on the path that fails an uninstall,
/// [`ensure_stopped_verdict`] over [`Registration::Loaded`], launchd's own words
/// are the only account of why the stop was refused. The level is the same for
/// every outcome, because a non-zero bootout is a refusal or an absent job and
/// the code does not say which; severity is [`ensure_stopped_verdict`]'s, which
/// knows the cause.
fn launchctl_status(label: &str, args: &[&str]) -> std::io::Result<Option<i32>> {
    let output = util::system_tool::SystemTool::Launchctl
        .command()?
        .args(args)
        .output()?;
    info!(
        stdout = %String::from_utf8_lossy(&output.stdout),
        stderr = %String::from_utf8_lossy(&output.stderr),
        status = ?output.status,
        "launchctl {label} finished",
    );
    Ok(output.status.code())
}

// Install/uninstall ===================================================================================================

/// Install the bridge: copy binary to a stable location and register with launchd.
///
/// The binary is copied atomically to `/Library/PrivilegedHelperTools/com.hole.bridge`
/// and the plist references that stable path.
pub fn install(source_binary: &Path) -> std::io::Result<()> {
    let helper_dir = Path::new("/Library/PrivilegedHelperTools");
    std::fs::create_dir_all(helper_dir)?;

    // Create the service log + state dirs (running elevated here, so
    // LaunchDaemons can write to them later).
    std::fs::create_dir_all(SERVICE_LOG_DIR)?;
    std::fs::create_dir_all(SERVICE_STATE_DIR)?;

    // Atomic copy: write to temp file, then rename
    let tmp_path = helper_dir.join("com.hole.bridge.tmp");
    std::fs::copy(source_binary, &tmp_path)?;

    // Preserve executable permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;

    std::fs::rename(&tmp_path, HELPER_PATH)?;

    let plist = generate_plist(HELPER_PATH);
    std::fs::write(PLIST_PATH, plist)?;

    // Use modern launchctl bootstrap (replaces deprecated `load -w`)
    run_launchctl("bootstrap", &["bootstrap", "system", PLIST_PATH])?;

    info!("launchd bridge installed and loaded");
    Ok(())
}

/// launchd's "could not find the specified service" status, as `launchctl`
/// exits with it. Measured against the running OS by
/// `launchd_answers_no_such_service_for_a_label_it_does_not_know` rather than
/// taken on trust — it is the one code that means "there is no job here",
/// and the whole absent-vs-failed classification hangs on it.
const LAUNCHD_NO_SUCH_SERVICE: i32 = 113;

/// What launchd says about the bridge's job, keyed on the cause it reported.
///
/// The macOS counterpart of `windows::open_error_is_absent`: there are three
/// answers, not two, and the third must never be folded into either of the
/// others. See [`ensure_stopped_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Registration {
    /// launchd has the job loaded.
    Loaded,
    /// launchd does not know this label: there is nothing to stop.
    Absent,
    /// launchd could not be asked, or answered something neither of the above.
    /// Says nothing about the job either way.
    Unknown(String),
}

/// Classify `launchctl print system/<label>`'s result. Pure, so the rule is
/// table-tested without spawning anything.
///
/// `Ok(None)` is launchctl killed by a signal — an answer about launchctl, not
/// about the job — and `Err` is a spawn failure. Both are [`Registration::Unknown`].
fn classify_registration(status: std::io::Result<Option<i32>>) -> Registration {
    match status {
        Ok(Some(0)) => Registration::Loaded,
        Ok(Some(LAUNCHD_NO_SUCH_SERVICE)) => Registration::Absent,
        Ok(Some(code)) => Registration::Unknown(format!("launchctl print exited {code}")),
        Ok(None) => Registration::Unknown("launchctl print was terminated by a signal".to_string()),
        Err(e) => Registration::Unknown(format!("could not run launchctl print: {e}")),
    }
}

/// Ask launchd whether it still has the bridge's job.
fn probe_registration() -> Registration {
    classify_registration(
        util::system_tool::SystemTool::Launchctl
            .command()
            .and_then(|mut c| {
                c.args(["print", &format!("system/{LAUNCHD_LABEL}")])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
            })
            .map(|s| s.code()),
    )
}

/// Stop the bridge *without* removing its plist, tolerating a host where
/// launchd has no job to stop.
///
/// The uninstall orchestration calls this unconditionally, before it consults
/// any registration record — see `setup::uninstall_bridge_with` for why the
/// two are independent.
///
/// Issue the stop, then classify by cause what it left behind, as the Windows
/// arm does. No probe first, and the bootout's exit code is not read as the
/// answer; why is in the stop step of "The order of an uninstall" in
/// `docs/contributing/architecture/kill-switch-uninstall.md`.
///
/// `bootout`, not [`stop`]'s SIGTERM: the plist sets `KeepAlive`, so launchd
/// relaunches a bare-signalled daemon.
pub fn ensure_stopped() -> std::io::Result<()> {
    let system_label = format!("system/{LAUNCHD_LABEL}");
    ensure_stopped_with(
        || launchctl_status("bootout", &["bootout", &system_label]),
        probe_registration,
    )
}

/// [`ensure_stopped`]'s ordering, with the act and the post-act probe injected
/// so the sequence is testable without launchd.
fn ensure_stopped_with(
    bootout: impl FnOnce() -> std::io::Result<Option<i32>>,
    registration: impl FnOnce() -> Registration,
) -> std::io::Result<()> {
    if let Ok(Some(0)) = bootout() {
        info!("launchd booted out the bridge job");
        return Ok(());
    }
    ensure_stopped_verdict(registration())
}

/// Whether a [`Registration`] lets the stop report success. Pure, so the arm
/// that must never report it is testable without launchd.
///
/// `Unknown` is an error, not a success: `setup::uninstall_bridge_with` gates
/// deregistration on this call. Deleting the plist over a still-loaded job
/// leaves a running bridge with no registration naming it, and a bridge left
/// running holds the liveness lock, so the cover release refuses against it. The
/// registration is the only handle a later attempt has on a job it could not
/// confirm stopped.
///
/// `Loaded` is reached whenever the bootout did not succeed and launchd still
/// has the job — the real refusal, as opposed to the bootout that failed
/// because there was nothing left to boot out.
fn ensure_stopped_verdict(registration: Registration) -> std::io::Result<()> {
    match registration {
        Registration::Absent => {
            info!("launchd has no bridge job to stop");
            Ok(())
        }
        Registration::Loaded => Err(std::io::Error::other(format!(
            "launchd still has {LAUNCHD_LABEL} loaded after the stop"
        ))),
        Registration::Unknown(why) => Err(std::io::Error::other(format!(
            "could not ask launchd whether {LAUNCHD_LABEL} is loaded ({why}); refusing to report the bridge stopped"
        ))),
    }
}

/// Stop, unload, and remove the bridge.
///
/// The stop is FATAL here, not best-effort. The removals below delete the plist, the registration, over whatever
/// launchd still holds; a bridge not confirmed stopped keeps its liveness lock, so the cover release refuses against it.
/// `has_anything_to_uninstall()` gates only those removals, never the stop.
pub fn uninstall() -> std::io::Result<()> {
    ensure_stopped()?;

    // Every removal is attempted: one that always fails (an immutable folder, a mount point) must not keep the
    // registration from going, or the uninstall could never finish.
    let layout = plugin_dir_layout();
    remove_all([
        (
            "remove the plugin folder",
            crate::plugin_repair::apply::remove_folder(&layout.dir, layout.owner),
        ),
        (
            "remove the plugin runtime folder",
            crate::plugin_repair::apply::remove_folder(Path::new(SERVICE_RUNTIME_DIR), layout.owner),
        ),
        ("remove the launchd plist", remove_if_present(PLIST_PATH)),
        ("remove the helper", remove_if_present(HELPER_PATH)),
    ])?;

    info!("launchd bridge uninstalled");
    Ok(())
}

/// Removes `path` if it is there.
fn remove_if_present(path: &str) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Ok if every removal went, else one error naming each that did not.
fn remove_all(removals: impl IntoIterator<Item = (&'static str, std::io::Result<()>)>) -> std::io::Result<()> {
    let failures: Vec<String> = removals
        .into_iter()
        .filter_map(|(what, result)| result.err().map(|e| format!("{what}: {e}")))
        .collect();
    if failures.is_empty() {
        return Ok(());
    }
    Err(std::io::Error::other(failures.join("; ")))
}

// Start/stop ==========================================================================================================

/// Start the bridge (bootstrap the plist if not already loaded).
pub fn start() -> std::io::Result<()> {
    run_launchctl("bootstrap", &["bootstrap", "system", PLIST_PATH])?;
    info!("launchd bridge started");
    Ok(())
}

/// Stop the bridge without unregistering it.
pub fn stop() -> std::io::Result<()> {
    let system_label = format!("system/{LAUNCHD_LABEL}");
    run_launchctl("kill", &["kill", "SIGTERM", &system_label])?;
    info!("launchd bridge stopped");
    Ok(())
}

// Query ===============================================================================================================

/// Check whether the bridge plist is installed.
pub fn is_installed() -> bool {
    Path::new(PLIST_PATH).exists()
}

/// Whether anything Hole installed is still on this machine: the registration, or a file or folder an uninstall that
/// failed part-way left. Gates the uninstall's removals, so one that failed after the plist went can be retried; a
/// status readout asks [`is_installed`], which a leftover folder must not turn into "installed".
pub fn has_anything_to_uninstall() -> bool {
    any_present(&[
        Path::new(PLIST_PATH),
        Path::new(HELPER_PATH),
        Path::new(PLUGIN_DIR),
        Path::new(SERVICE_RUNTIME_DIR),
    ])
}

/// Whether something is at any of `paths`, a link as itself. A path that cannot be looked at counts: the removal is
/// attempted and says why it cannot.
fn any_present(paths: &[&Path]) -> bool {
    paths.iter().any(|path| match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    })
}

/// What [`hold_start_type`] returns.
pub struct StartTypeHold;

/// launchd has no start type, so a change to it has nothing to hold.
pub fn hold_start_type() -> std::io::Result<StartTypeHold> {
    Ok(StartTypeHold)
}

/// launchd has no start type to disable: there is nothing to repair.
pub fn repair_interrupted_change() -> std::io::Result<crate::service_start::RepairStep> {
    Ok(crate::service_start::RepairStep::Nothing)
}

/// launchd has no start type to disable, so the bridge is never disabled.
pub fn disabled_by() -> std::io::Result<Option<crate::disable_record::DisabledBy>> {
    Ok(None)
}

/// [`disabled_by`] for the GUI's status.
pub fn disabled_state() -> crate::disable_record::DisabledState {
    crate::disable_record::DisabledState::NotDisabled
}

/// launchd has no disabled start type to undo, so `hole bridge enable` has no
/// macOS meaning.
pub fn enable() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the macOS bridge has no start type to enable",
    ))
}

/// Check whether the bridge is currently running.
///
/// Its one caller is `setup::bridge_install_status`, a cosmetic status
/// readout, so an unanswerable probe collapses to `false` here, with a warning.
/// [`ensure_stopped`], which acts on the answer, does not come through here.
pub fn is_running() -> bool {
    match probe_registration() {
        Registration::Loaded => true,
        Registration::Absent => false,
        Registration::Unknown(why) => {
            tracing::warn!(%why, "could not ask launchd whether the bridge is running; reporting it as not running");
            false
        }
    }
}

/// Run the bridge directly (called by launchd).
///
/// `log_dir` is the directory the crash-marker sweep reads (markers land
/// next to `bridge.log`).
///
/// `plugins` are the plugin binaries `hole` carries; the service makes [`PLUGIN_DIR`] hold exactly those before it
/// serves anything.
pub fn run(
    socket_path: &std::path::Path,
    state_dir: &std::path::Path,
    log_dir: &std::path::Path,
    version: &str,
    plugins: &'static [EmbeddedPlugin],
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // The repair of this start writes it; the plugin source reads it.
        let verdict = RepairVerdict::default();
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::proxy_manager::ProxyManager::new(
                crate::proxy::ShadowsocksProxy::new(),
                // No owner: the launchd daemon runs as root and its dirs are root-owned by design.
                tun_engine::routing::SystemRouting::new(state_dir.to_path_buf(), None),
            )
            .with_plugin_source(service_plugin_source(verdict.clone())),
        ));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        // Bind BEFORE the liveness acquire and BEFORE recovery — a second
        // instance's bind() fails before it can touch routing state or
        // contend on the liveness lock, matching crate::liveness's documented
        // invariant. Recovery that runs external commands is offloaded via
        // spawn_blocking so a hung command cannot wedge the runtime while the IPC
        // socket is bound but not yet serving.
        let server = crate::ipc::IpcServer::bind_with_log_dir(socket_path, proxy, version, log_dir.to_path_buf())?;

        // Held for this bridge's entire run — see crate::liveness's module
        // doc and foreground.rs's identical acquisition.
        let state_dir_liveness = state_dir.to_path_buf();
        let _liveness =
            tokio::task::spawn_blocking(move || crate::liveness::BridgeLiveness::acquire(&state_dir_liveness, None))
                .await??;
        // Repairs come first: a bridge wedged or stopped in any later step never reaches a repair placed after it
        // (Windows does the same, `registration::run_startup_steps`). Nothing is served yet, and the one bridge that
        // holds the liveness lock is the only repairer.
        prepare_plugins(
            plugin_dir_layout(),
            PathBuf::from(SERVICE_RUNTIME_DIR),
            plugins,
            &verdict,
        )
        .await;
        // DNS recovery runs next; see crate::dns::recovery docs for ordering.
        let state_dir_dns = state_dir.to_path_buf();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir_dns)).await
        {
            tracing::warn!(error = &e as &dyn std::error::Error, "recover_dns_config task panicked");
        }
        // Root cancellation token for the launchd service, wired to the same
        // SIGINT/SIGTERM source `serve_until_signal` consumes below. Created
        // before reconciliation so a stop arriving mid-boot abandons the
        // auto-connect rather than racing it.
        #[allow(clippy::disallowed_methods)]
        // Service entry point — see clippy.toml's CancellationToken::new list.
        let shutdown = tokio_util::sync::CancellationToken::new();
        {
            // Called on the current task, not inside the spawn: registration is
            // eager in `shutdown_signal()` itself, and `tokio::spawn` only
            // queues. See the same comment in `foreground::run_inner`.
            let signal = crate::foreground::shutdown_signal();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                signal.await;
                shutdown.cancel();
            });
        }

        // Reconcile the persisted target before any client can connect (narrows,
        // does not close, the boot->first-connect gap).
        crate::boot::recover_then_reconcile(&proxy_shutdown, &shutdown).await;
        // Sweep crash markers left by a previously-crashed bridge. Offloaded to a
        // blocking thread to match the sibling recover_* calls.
        let log_dir_sweep = log_dir.to_path_buf();
        if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir_sweep)).await {
            tracing::warn!(error = &e as &dyn std::error::Error, "crash sweep task panicked");
        }
        // The new bridge is authoritative once it has bound: any update marker is
        // a completed cutover, so clear it unconditionally (remove-by-path).
        let log_dir_marker = log_dir.to_path_buf();
        if let Err(e) = tokio::task::spawn_blocking(move || sweep_marker(&log_dir_marker)).await {
            tracing::warn!(error = &e as &dyn std::error::Error, "marker sweep task panicked");
        }

        // launchd stops the daemon with SIGTERM; awaiting only ctrl_c (SIGINT)
        // here would skip the pm.stop() teardown below and leak routes/DNS.
        // `shutdown_signal()` handles SIGINT *and* SIGTERM (foreground.rs).
        let shutdown_wait = shutdown.clone();
        serve_until_signal(server.run(), async move { shutdown_wait.cancelled().await }).await;

        // Clean shutdown: stop proxy before exiting. Neither event is a user
        // disconnect, so the target is left unchanged either way; only the
        // event differs, distinguishing an update cutover from a plain
        // machine shutdown for anyone reading the log/history.
        let mut pm = proxy_shutdown.lock().await;
        let event = crate::foreground::shutdown_reason(hole_common::update_marker::is_present(log_dir));
        if let Err(e) = pm.stop_with(event).await {
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "error stopping proxy during shutdown"
            );
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

/// Makes the plugin folder hold what `hole` carries and the runtime folder exist, on a blocking thread, and records
/// how the repair went in `verdict`. Never stops the start: a bridge whose plugins cannot be repaired still serves,
/// and a connect that needs them says why.
async fn prepare_plugins(
    layout: PluginDirLayout,
    runtime_dir: PathBuf,
    plugins: &'static [EmbeddedPlugin],
    verdict: &RepairVerdict,
) {
    let started = std::time::Instant::now();
    let joined = tokio::task::spawn_blocking(move || {
        let outcome = crate::plugin_repair::apply::repair(&layout, plugins);
        let runtime = crate::plugin_repair::apply::make_runtime_dir(&runtime_dir, layout.owner);
        (outcome, runtime)
    })
    .await;
    match joined {
        Ok((outcome, runtime)) => {
            // The runtime folder is part of what a plugin may run with, so its failure is part of the verdict.
            let prepared = Prepared::new(outcome, runtime);
            prepared.log();
            verdict.record(prepared);
            // A measurement of what the repair costs on a start: hashing the plugins on every start, writing them on
            // the first start after an install or an update.
            info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "plugin folder prepared"
            );
        }
        Err(e) => {
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "plugin folder repair task panicked"
            );
            verdict.record(Prepared::new(
                RepairOutcome::Degraded {
                    notes: Vec::new(),
                    failures: vec!["the repair task panicked".to_owned()],
                },
                Ok(()),
            ));
        }
    }
}

/// Clear a stale update-in-progress marker on the new bridge's post-bind sweep.
/// The marker's presence is co-extensive with "a cutover during which no bridge
/// answered"; once this bridge binds, the cutover is done. Remove-by-path so a
/// from->to schema bump across the cutover cannot strand it.
pub(crate) fn sweep_marker(log_dir: &std::path::Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "failed to clear update-in-progress marker"
        );
    }
}

/// Drive the IPC server until it finishes or a shutdown signal arrives,
/// whichever comes first. Extracted from `run` so the select can be
/// unit-tested without delivering real OS signals.
pub(crate) async fn serve_until_signal(
    server: impl std::future::Future<Output = std::io::Result<()>>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!(error = &e as &dyn std::error::Error, "IPC server error");
            }
        }
        _ = shutdown => {
            info!("received shutdown signal");
        }
    }
}

/// A valid marker for the post-bind-sweep test.
#[cfg(test)]
fn test_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        driver: cosca::identity::ProcessId::current()
            .to_record()
            .expect("persist this process's identity"),
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
