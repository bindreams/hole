// Prevent console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// In test mode the bin's `main` becomes a skuld test runner, which makes all
// the regular GUI functions appear unused to clippy.
#![cfg_attr(test, allow(dead_code))]

mod bridge_client;
#[macro_use]
mod cli_log;
mod cli;
mod commands;
mod elevation;
mod log_collector;
mod logging;
mod path_management;
mod platform;
mod setup;
mod state;
mod tray;

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

#[cfg(test)]
fn main() {
    skuld::run_all();
}

fn launch_gui(show_dashboard: bool) {
    // Determine paths
    let config_dir = dirs::config_dir().expect("no config directory found").join("hole");
    let config_path = config_dir.join("config.json");
    let log_dir = hole_common::logging::default_log_dir();

    let _log_guard = logging::init(&log_dir);

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_dialog::init())
        // `.skip_logger()` is critical: `tracing-subscriber 0.3`'s default
        // features include `tracing-log`, which installs `LogTracer` as the
        // global `log` dispatcher during `try_init` above. `tauri-plugin-log`
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
            commands::get_proxy_status,
            commands::get_metrics,
            commands::get_diagnostics,
            commands::get_public_ip,
            commands::test_server,
            commands::mark_validated_by_proxy_start,
            commands::reload_proxy_filters,
            tray::toggle_proxy,
            tray::cancel_proxy,
        ])
        .setup(move |app| {
            // Manage shared state here (instead of pre-`.setup()`) so that
            // `AppState` has access to a real `tauri::AppHandle` for emitting
            // events from commands like `test_server`.
            app.manage(AppState::new(config_path.clone(), app.handle().clone()));
            app.manage(hole::update::UpdateState::default());
            tray::create_tray(app)?;
            platform::on_setup(app)?;
            if show_dashboard {
                tray::open_settings_window(app.handle());
            }
            setup::check_bridge_on_launch(app.handle().clone());
            hole::update::start_update_checker(app.handle().clone(), |app, info| {
                // Rebuild tray menu to include the "Install Update" item.
                if let Some(tray_icon) = app.tray_by_id("main") {
                    let enabled = app.state::<AppState>().config.lock().unwrap().enabled;
                    match tray::build_tray_menu(app, Some(info), enabled) {
                        Ok(menu) => {
                            // Re-sync checkbox state from config before applying new menu.
                            tray::sync_menu_state(app, &menu);
                            tray_icon.set_menu(Some(menu)).ok();
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to rebuild tray menu with update");
                        }
                    }
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building Hole")
        .run(handle_run_event);
}

/// Tauri run-event handler. Implements the Tauri 2 equivalent of Qt's
/// `QApplication::setQuitOnLastWindowClosed(false)` and a destroy-then-exit
/// dance that works around tao 0.34.8 calling `std::process::exit` at the
/// end of `EventLoop::run` (which bypasses every `Drop` in the wry/Tauri
/// tree).
///
/// The wry runtime fires `RunEvent::ExitRequested` from two places
/// (verified in tauri-runtime-wry-2.10.1/src/lib.rs):
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
