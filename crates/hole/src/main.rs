// Prevent console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// In test mode the bin's `main` becomes a skuld test runner, which makes all
// the regular GUI functions appear unused to clippy.
#![cfg_attr(test, allow(dead_code))]

// A release build must serve the bundled frontend over the custom protocol.
// Without `tauri/custom-protocol` (default-on) the dashboard webview points at
// `devUrl` and a shipped binary shows "localhost refused to connect".
// `tauri::is_dev()` is const, so this is a build failure, not a runtime
// surprise.
const _: () = assert!(
    !(cfg!(not(debug_assertions)) && tauri::is_dev()),
    "release builds of hole must enable `tauri/custom-protocol`"
);

mod autostart;
mod bridge_client;
#[macro_use]
mod cli_log;
mod cli;
mod commands;
mod elevation;
#[cfg(target_os = "macos")]
mod embedded_plugins;
mod import_dialog;
mod log_collector;
mod logging;
mod orphan_sweep;
mod path_management;
mod platform;
mod setup;
mod state;
mod tray;
mod ui_settings;
mod window_menu;

use std::sync::atomic::{AtomicBool, Ordering};

use state::AppState;
use tauri::Manager;

/// Set by `destroy_windows_before_exit` once an explicit `AppHandle::exit(N)` is in progress.
///
/// Destroying the last window fires `ExitRequested { code: None }` again, and the
/// destroys are processed on a later event-loop iteration. While this is set,
/// `keep_running_for_tray` must not `prevent_exit` (it would abort the exit in
/// progress), and a macOS reopen must not build a window on a process about to
/// `process::exit` past every `Drop`.
static EXITING: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
fn main() {
    let cli = cli::parse_args();
    // Read both before the match: it moves `command` out, and a partially moved
    // `cli` cannot be borrowed by a `&self` method.
    let dashboard_flag_present = cli.show_dashboard_flag_present();
    let show_dashboard = cli::resolve_show_dashboard(
        dashboard_flag_present,
        cli.show_dashboard(),
        std::env::var_os(hole::launch::NO_DASHBOARD_ENV).is_some(),
    );
    match cli.command {
        Some(cmd) => {
            if dashboard_flag_present {
                eprintln!("error: dashboard flags cannot be combined with a subcommand");
                std::process::exit(2);
            }
            cli::dispatch(cmd);
        }
        None => launch_gui(show_dashboard),
    }
}

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/`.
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
    let log_dir = hole_common::logging::resolve_log_dir(None);

    let _log_guard = logging::init(&log_dir);

    // Native-crash observability: report any crash
    // marker a previously-crashed GUI/foreground-bridge left in this dir.
    // GUI startup is synchronous and pre-event-loop, so sweep inline (no
    // spawn_blocking — there is no runtime worker to protect yet).
    tombstone::sweep(&log_dir);

    // Snapshot the installed image identity now, before any later update can
    // rename it — the self-heal compares against it on a version mismatch.
    hole::selfheal::init_startup();

    tauri::Builder::default()
        // `tauri-plugin-single-instance` must be registered first per
        // upstream guidance: the duplicate-instance process exits during
        // this plugin's init, so any plugin registered earlier would do
        // startup work in vain (and `tauri-plugin-autostart::init` touches
        // the Windows registry / macOS LaunchAgent plist, which would race
        // against the live first instance). The callback fires on a
        // plugin-owned thread; `WebviewWindowBuilder::build` and Cocoa UI
        // work require the main thread, so dispatch via
        // `run_on_main_thread`. `argv` decides whether to reveal: an autostart
        // entry landing on a running instance forwards `--no-show-dashboard` and
        // must stay quiet, while any other launch is a user asking for the UI.
        // `cwd` is irrelevant.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !cli::show_dashboard_from_argv(&args) {
                return;
            }
            let handle = app.clone();
            if let Err(e) = app.run_on_main_thread(move || {
                tray::open_settings_window(&handle);
            }) {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "single-instance: failed to dispatch to main thread"
                );
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![hole::launch::NO_SHOW_DASHBOARD]),
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
            import_dialog::import_from_dialog,
            import_dialog::import_dropped_files,
        ])
        .menu(window_menu::build)
        .on_menu_event(window_menu::handle_event)
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
            app.manage(hole::dashboard::DashboardWindow::new());
            app.manage(std::sync::Arc::new(import_dialog::ImportFlow::default()));
            tray::create_tray(app)?;
            // Tray + webview follow the ProxyStateCell; the reconciler's
            // immediate first tick is the startup resync against the
            // bridge's actual state.
            tray::spawn_proxy_state_sync(app.handle());
            // Startup auto-connect is the bridge's own decision, applied from its
            // persisted `on_startup` preference at each bridge boot; the GUI
            // arms nothing.
            platform::on_setup(app)?;
            // Registrations written before the dashboard flag existed carry no
            // arguments and would open a window at login. Best-effort: never
            // block startup. The detail may embed a filesystem path, so it stays
            // in gui.log rather than a toast.
            match hole::autostart_registration::migrate(&app.package_info().name, hole::launch::NO_SHOW_DASHBOARD) {
                Ok(outcome) => tracing::debug!(?outcome, "autostart argument migration"),
                Err(e) => tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "autostart argument migration failed"
                ),
            }
            let settled = tray::apply_launch_window(app.handle(), show_dashboard);
            tray::spawn_status_reconciler(app.handle(), settled);
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
        .build(tauri::tauri_build_context!())
        .expect("error building Hole")
        .run(handle_run_event);
}

/// Dispatches Tauri run events: tray persistence, macOS reopen, and the exit contract.
fn handle_run_event(app: &tauri::AppHandle, event: tauri::RunEvent) {
    match event {
        // No new process is spawned on reopen, so single-instance never fires;
        // this is the only signal. `has_visible_windows` is ignored: reveal-or-build
        // also covers a minimized dashboard.
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } if !EXITING.load(Ordering::SeqCst) => tray::open_settings_window(app),
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => {}

        tauri::RunEvent::ExitRequested { code: None, api, .. } => keep_running_for_tray(app, &api),
        tauri::RunEvent::ExitRequested { code: Some(_), .. } => destroy_windows_before_exit(app),

        _ => {}
    }
}

/// Keeps the app running for the tray icon after the last window is destroyed
/// (`ExitRequested { code: None }`).
fn keep_running_for_tray(app: &tauri::AppHandle, api: &tauri::ExitRequestApi) {
    if EXITING.load(Ordering::SeqCst) {
        return;
    }
    api.prevent_exit();
    #[cfg(target_os = "macos")]
    platform::hide_dock_icon(app);
    #[cfg(not(target_os = "macos"))]
    let _ = app;
}

/// Destroys every webview window before an explicit `AppHandle::exit(N)`
/// (`ExitRequested { code: Some(_) }`) and sets `EXITING`. Needed because tao calls `process::exit` at the
/// end of `EventLoop::run`, bypassing every `Drop` in the wry/Tauri tree: a
/// window left alive survives to AtExit, where Chromium logs `Failed to
/// unregister class Chrome_WidgetWin_0. Error = 1412`.
fn destroy_windows_before_exit(app: &tauri::AppHandle) {
    EXITING.store(true, Ordering::SeqCst);
    for window in app.webview_windows().values() {
        // Safe on the main thread: wry routes this to `on_window_close`, not to the
        // `WindowMessage::Destroy` arm of `handle_user_message`, which panics there.
        // On Windows, tao's `runner.handling_events()` guard defers the
        // `ControlFlow::Exit` until the destroy has been processed.
        if let Err(e) = window.destroy() {
            // stderr, not `tracing`: the async appender is not flushed before
            // `process::exit`. Only dev builds have a console to show it.
            eprintln!(
                "warning: failed to destroy webview window {:?} on exit: {e}",
                window.label(),
            );
        }
    }
}
