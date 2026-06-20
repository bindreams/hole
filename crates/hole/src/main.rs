// Prevent console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// In test mode the bin's `main` becomes a skuld test runner, which makes all
// the regular GUI functions appear unused to clippy.
#![cfg_attr(test, allow(dead_code))]

mod autostart;
mod bridge_client;
#[macro_use]
mod cli_log;
mod cli;
mod commands;
mod dashboard;
mod elevation;
mod log_collector;
mod logging;
mod orphan_sweep;
mod path_management;
mod platform;
mod setup;
mod state;
mod tray;
mod ui_ready;
mod ui_settings;

use std::sync::atomic::{AtomicBool, Ordering};

use state::AppState;
use tauri::Manager;

/// Set when an explicit `AppHandle::exit(N)` is in progress, so the
/// last-window-closed `RunEvent::ExitRequested { code: None }` callback
/// (which fires after we destroy the dashboard from the `code: Some(_)`
/// arm of `handle_run_event`) does not call `prevent_exit` and abort the
/// exit we just initiated. See `handle_run_event` and issue #144.
static EXITING: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
fn main() {
    let cli = cli::parse_args();
    match cli.command {
        Some(cmd) => {
            if cli.show_dashboard {
                eprintln!("error: --show-dashboard cannot be combined with a subcommand");
                std::process::exit(2);
            }
            cli::dispatch(cmd);
        }
        None => launch_gui(cli.show_dashboard),
    }
}

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}

fn launch_gui(show_dashboard: bool) {
    // BEFORE logging redirects stdout into the (lossy) log relay: if we were
    // relaunched to take over a stale predecessor (version self-heal, or
    // post-update), signal READY over the inherited stdout pipe and wait for
    // the predecessor to exit, so the single-instance plugin acquires the
    // `com.hole.app` lock uncontested. Routing READY through the relay could
    // drop it and hang the handshake, so it must happen pre-`logging::init`.
    // No-op (returns immediately) for an ordinary launch — the env marker is
    // unset, so no console/stdout is touched. No subscriber yet, so report a
    // (rare) failure to stderr.
    if let Err(e) = hole::relaunch::await_predecessor() {
        eprintln!("hole: await_predecessor failed; launching anyway: {e}");
    }

    // Determine paths
    let config_dir = dirs::config_dir().expect("no config directory found").join("hole");
    let config_path = config_dir.join("config.json");
    let log_dir = hole_common::logging::default_log_dir();

    let _log_guard = logging::init(&log_dir);

    // Native-crash observability (bindreams/hole#438): report any crash
    // marker a previously-crashed GUI/foreground-bridge left in this dir.
    // GUI startup is synchronous and pre-event-loop, so sweep inline (no
    // spawn_blocking — there is no runtime worker to protect yet).
    tombstone::sweep(&log_dir);

    // Snapshot the installed image identity now, before any later update can
    // rename it — the self-heal compares against it on a version mismatch.
    hole::selfheal::init_startup();

    tauri::Builder::default()
        // `UiReady` is registered on the builder (not in `.setup`) so
        // it is available to command handlers at first dispatch — the
        // dashboard webview begins navigation during `.build()`, and
        // `ui/main.ts::init()` may fire `signal_ui_ready` before the
        // setup hook runs.
        .manage(ui_ready::UiReady::default())
        // `tauri-plugin-single-instance` must be registered first per
        // upstream guidance: the duplicate-instance process exits during
        // this plugin's init, so any plugin registered earlier would do
        // startup work in vain (and `tauri-plugin-autostart::init` touches
        // the Windows registry / macOS LaunchAgent plist, which would race
        // against the live first instance). The callback fires on a
        // plugin-owned thread; `WebviewWindowBuilder::build` and Cocoa UI
        // work require the main thread, so dispatch via
        // `run_on_main_thread`. `argv` and `cwd` are intentionally ignored
        // — whether the user typed `hole`, `hole --show-dashboard`, or
        // double-clicked the desktop shortcut, the only useful response
        // is to reveal the existing UI (same as a tray click). See #360.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let handle = app.clone();
            if let Err(e) = app.run_on_main_thread(move || {
                tray::open_settings_window(&handle);
            }) {
                tracing::warn!(error = %e, "single-instance: failed to dispatch to main thread");
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_dialog::init())
        // `.skip_logger()` is critical: `tracing-subscriber 0.3`'s default
        // features include `tracing-log`, which installs `LogTracer` as the
        // global `log` dispatcher during `logging::init()` earlier in
        // `launch_gui`. `tauri-plugin-log`
        // by default *also* calls `log::set_boxed_logger`, which would
        // collide — a second install fails. `skip_logger` makes the plugin
        // only handle JS→Rust IPC: incoming JS `info!`/`error!` calls become
        // Rust `log::*` events that flow through `LogTracer` into our
        // existing `tracing` subscriber → `gui.log`.
        .plugin(tauri_plugin_log::Builder::new().skip_logger().build())
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::save_config,
            commands::import_servers_from_file,
            commands::delete_server,
            commands::get_proxy_status,
            commands::get_metrics,
            commands::get_diagnostics,
            commands::get_public_ip,
            commands::test_server,
            commands::mark_validated_by_proxy_start,
            commands::reload_proxy_filters,
            commands::evaluate_filter,
            tray::start_proxy,
            tray::stop_proxy,
            tray::cancel_proxy,
            tray::get_autostart,
            tray::set_autostart,
            ui_ready::signal_ui_ready,
            ui_ready::wait_ui_ready,
        ])
        .setup(move |app| {
            // Manage shared state here (instead of pre-`.setup()`) so that
            // `AppState` has access to a real `tauri::AppHandle` for emitting
            // events from commands like `test_server`.
            let (config_store, config, recovery) =
                hole_common::config_store::ConfigStore::load(config_path.clone(), time::OffsetDateTime::now_utc());
            app.manage(AppState::new(config_store, config, app.handle().clone()));
            if let Some(recovery) = recovery {
                // Non-blocking: `blocking_show` must not run on the main
                // thread, and setup must not stall the event loop.
                use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
                app.dialog()
                    .message(hole::config_recovery::recovery_dialog_message(&recovery))
                    .title(hole::config_recovery::RECOVERY_DIALOG_TITLE)
                    .kind(MessageDialogKind::Error)
                    .show(|_| {});
            }
            app.manage(hole::update::UpdateState::default());
            app.manage(tray::TransitionSlot::new());
            app.manage(dashboard::DashboardWindow::new());
            tray::create_tray(app)?;
            // Tray + webview follow the ProxyStateCell; the reconciler's
            // immediate first tick is the startup resync against the
            // bridge's actual state (#462).
            tray::spawn_proxy_state_sync(app.handle());
            // Record the persisted "On startup" intent (#458); the status
            // reconciler applies it (silently — no install/elevation/error modal)
            // the first time the bridge is reachable, so a cold-boot race against
            // the bridge's socket bind can't drop it.
            tray::arm_startup_auto_connect(app.handle());
            tray::spawn_status_reconciler(app.handle());
            platform::on_setup(app)?;
            if show_dashboard {
                tray::open_settings_window(app.handle());
            }
            // Best-effort sweep of `hole-install-*` temp directories left
            // behind by failed elevated installs (`run_elevated` detaches
            // its TempDir on failure so the user can attach the log to
            // support; this cleans those up after a few days). Non-
            // blocking; failures are logged at `warn` only.
            orphan_sweep::spawn_default();
            hole::update::start_update_checker(app.handle().clone(), |app, _info| {
                // Rebuild the tray menu to include the "Install Update" item.
                // `UpdateState` is already populated when this fires; the
                // rebuild reads the info from it on the main thread.
                tray::rebuild_tray_menu(app);
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building Hole")
        .run(handle_run_event);
}

/// Tauri run-event handler. Implements the Tauri 2 equivalent of Qt's
/// `QApplication::setQuitOnLastWindowClosed(false)` and a destroy-then-exit
/// dance that works around tao calling `std::process::exit` at the
/// end of `EventLoop::run` (which bypasses every `Drop` in the wry/Tauri
/// tree).
///
/// The wry runtime fires `RunEvent::ExitRequested` from two places:
///
///   - `code: None`  — last window destroyed (the user clicked X on the
///     dashboard). We want the app to keep running for the tray icon, so
///     we call `prevent_exit`.
///
///   - `code: Some(N)` — `AppHandle::exit(N)` was called explicitly (tray
///     Exit menu, dashboard File→Exit menu, post-MSI install exit). We
///     need to destroy any remaining webview windows here, BEFORE letting
///     the exit through. Otherwise the dashboard's `Chrome_WidgetWin_0`
///     HWND survives to AtExit time and Chromium logs
///     `Failed to unregister class Chrome_WidgetWin_0. Error = 1412`
///     (issue #144).
///
/// Calling `WebviewWindow::destroy()` from this callback is safe on the
/// main thread: the wry runtime intercepts
/// `Event::UserEvent(Message::Window(_, WindowMessage::Destroy))` with a
/// direct call to `on_window_close`, avoiding the `WindowMessage::Destroy`
/// arm in `handle_user_message` (which panics on the main thread). The
/// destroy message we enqueue is processed by the next event loop
/// iteration; tao's `runner.handling_events()` guard defers the
/// `ControlFlow::Exit` break until we have returned to Idle, so the
/// destroy completes before the loop actually exits and `process::exit`
/// runs.
///
/// After our destroys empty the window store, the runtime fires
/// `RunEvent::ExitRequested { code: None }` again — that is the re-entry
/// the `EXITING` flag at the top of this file guards against. Without the
/// flag, the `None` arm would call `prevent_exit` and abort the explicit
/// exit we just initiated.
fn handle_run_event(app: &tauri::AppHandle, event: tauri::RunEvent) {
    let tauri::RunEvent::ExitRequested { code, api, .. } = event else {
        return;
    };

    match code {
        None => {
            if EXITING.load(Ordering::SeqCst) {
                // Re-entered from the destroys we triggered in the
                // `Some(_)` arm. Let the natural shutdown proceed; do
                // not call `prevent_exit`.
                return;
            }
            api.prevent_exit();
            #[cfg(target_os = "macos")]
            platform::hide_dock_icon(app);
        }
        Some(_) => {
            EXITING.store(true, Ordering::SeqCst);
            for window in app.webview_windows().values() {
                if let Err(e) = window.destroy() {
                    // Use eprintln rather than tracing::warn here.
                    // tracing-subscriber writes through an async
                    // appender, and tao's `EventLoop::run` is about to
                    // call `std::process::exit` which bypasses the
                    // WorkerGuard's flush-on-drop. eprintln hits stderr
                    // synchronously so dev-mode users (the only ones who
                    // have a console at all, since release builds use
                    // windows_subsystem) actually see the failure. If
                    // destroy fails, the original ERROR_CLASS_HAS_WINDOWS
                    // bug recurs — surfacing the warning loudly is
                    // important so the regression is diagnosable.
                    eprintln!(
                        "warning: failed to destroy webview window {:?} on exit: {e}",
                        window.label(),
                    );
                }
            }
        }
    }
}
