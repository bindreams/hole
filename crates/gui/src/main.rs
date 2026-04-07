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

use state::AppState;
use tauri::Manager;

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
        .manage(AppState::new(config_path))
        .manage(hole_gui::update::UpdateState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::save_config,
            commands::import_servers_from_file,
            commands::get_proxy_status,
            commands::get_metrics,
            commands::get_diagnostics,
            commands::get_public_ip,
            tray::toggle_proxy,
        ])
        .on_window_event(|window, event| {
            // Intercept the close button on the dashboard so it hides into the
            // tray instead of destroying the window (and exiting the app, since
            // it's currently the only window). Other windows — should any be
            // added later — fall through to the default Tauri behavior.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "settings" {
                    api.prevent_close();
                    window.hide().ok();
                    #[cfg(target_os = "macos")]
                    platform::hide_dock_icon(window.app_handle());
                }
            }
        })
        .setup(move |app| {
            tray::create_tray(app)?;
            platform::on_setup(app)?;
            if show_dashboard {
                tray::open_settings_window(app.handle());
            }
            setup::check_bridge_on_launch(app.handle().clone());
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
