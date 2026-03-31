// Prevent console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cli;
mod commands;
mod daemon_client;
mod elevation;
mod log_collector;
mod logging;
mod path_management;
mod platform;
mod setup;
mod state;
mod tray;

use state::AppState;
use tauri::Manager;

fn main() {
    // Any argument at all routes to clap (subcommands, --version, --help).
    // No arguments launches the GUI.
    if std::env::args().len() > 1 {
        cli::dispatch();
    }

    launch_gui();
}

fn launch_gui() {
    // Determine paths
    let config_dir = dirs::config_dir().expect("no config directory found").join("hole");
    let config_path = config_dir.join("config.json");
    let log_dir = dirs::data_local_dir()
        .expect("no local data directory found")
        .join("hole")
        .join("logs");

    let _log_guard = logging::init(&log_dir);

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new(config_path))
        .manage(hole_gui::update::UpdateState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::save_config,
            commands::import_servers_from_file,
            commands::get_proxy_status,
            tray::toggle_proxy,
        ])
        .on_window_event(|window, event| {
            #[cfg(target_os = "macos")]
            if matches!(event, tauri::WindowEvent::Destroyed) {
                if window.app_handle().webview_windows().is_empty() {
                    platform::hide_dock_icon(window.app_handle());
                }
            }
            let _ = (window, event); // suppress unused on non-macOS
        })
        .setup(|app| {
            tray::create_tray(app)?;
            platform::on_setup(app)?;
            setup::check_daemon_on_launch(app.handle().clone());
            hole_gui::update::start_update_checker(app.handle().clone(), |app, info| {
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
        .run(tauri::generate_context!())
        .expect("error running Hole");
}
