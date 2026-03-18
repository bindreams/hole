// Prevent console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod daemon_client;
mod logging;
mod platform;
mod state;
mod tray;

use state::AppState;

fn main() {
    // Determine paths
    let config_dir = dirs::config_dir().expect("no config directory found").join("Hole");
    let config_path = config_dir.join("config.json");
    let log_dir = dirs::data_local_dir()
        .expect("no local data directory found")
        .join("Hole")
        .join("logs");

    let _log_guard = logging::init(&log_dir);

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new(config_path))
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::save_config,
            commands::import_servers_from_file,
            commands::get_proxy_status,
        ])
        .on_window_event(|window, event| {
            #[cfg(target_os = "macos")]
            if matches!(event, tauri::WindowEvent::Destroyed) {
                use tauri::Manager;
                if window.app_handle().webview_windows().is_empty() {
                    platform::hide_dock_icon(window.app_handle());
                }
            }
            let _ = (window, event); // suppress unused on non-macOS
        })
        .setup(|app| {
            tray::create_tray(app)?;
            platform::on_setup(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running Hole");
}
