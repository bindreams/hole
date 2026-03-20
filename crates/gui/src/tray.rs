// System tray icon and menu.

use crate::commands::build_proxy_config;
use crate::state::AppState;
use hole_common::protocol::{DaemonRequest, DaemonResponse};
use tauri::menu::{CheckMenuItem, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tracing::{error, info, warn};

// Menu IDs =====

const ID_ENABLE: &str = "enable";
const ID_AUTOSTART: &str = "autostart";
const ID_SETTINGS: &str = "settings";
const ID_EXIT: &str = "exit";
#[cfg(target_os = "macos")]
const ID_UNINSTALL_HELPER: &str = "uninstall_helper";
const ID_ABOUT: &str = "about";

// Tray creation =====

/// Create and register the system tray icon with its menu.
pub fn create_tray(app: &tauri::App) -> Result<TrayIcon, tauri::Error> {
    let enable = CheckMenuItem::with_id(app, ID_ENABLE, "Enable", true, false, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(app, ID_AUTOSTART, "Start at Login", true, false, None::<&str>)?;
    let settings = MenuItem::with_id(app, ID_SETTINGS, "Settings...", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, ID_EXIT, "Exit", true, None::<&str>)?;

    let menu = tauri::menu::Menu::with_items(app, &[&enable, &autostart, &sep1, &settings, &sep2, &exit])?;

    let tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("Hole")
        .on_menu_event(handle_menu_event)
        .build(app)?;

    // Sync initial state from config
    let state = app.state::<AppState>();
    let config = state.config.lock().unwrap();
    enable.set_checked(config.enabled).ok();

    Ok(tray)
}

// Event handler =====

fn handle_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        ID_ENABLE => {
            info!("tray: enable toggled");
            let state = app.state::<AppState>();

            // Toggle enabled flag and build proxy config
            let (enabled, proxy_config) = {
                let mut config = state.config.lock().unwrap();
                config.enabled = !config.enabled;
                config.save(&state.config_path).ok();
                let enabled = config.enabled;
                let pc = build_proxy_config(&config);
                (enabled, pc)
            };

            if enabled {
                let Some(proxy_config) = proxy_config else {
                    error!("tray: no server selected, cannot enable");
                    // Revert the toggle
                    let mut config = state.config.lock().unwrap();
                    config.enabled = false;
                    config.save(&state.config_path).ok();
                    return;
                };

                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app_handle.state::<AppState>();
                    let ok = match state.daemon_send(DaemonRequest::Start { config: proxy_config }).await {
                        Ok(DaemonResponse::Ack) => {
                            info!("proxy started");
                            true
                        }
                        Ok(DaemonResponse::Error { message }) if message.contains("already running") => {
                            info!("proxy already running");
                            true
                        }
                        Ok(DaemonResponse::Error { message }) => {
                            error!("daemon error: {message}");
                            false
                        }
                        Ok(_) => {
                            warn!("unexpected response from daemon");
                            false
                        }
                        Err(e) => {
                            error!("failed to send start: {e}");
                            false
                        }
                    };
                    if !ok {
                        // Revert config on failure
                        let mut config = state.config.lock().unwrap();
                        config.enabled = false;
                        config.save(&state.config_path).ok();
                    }
                });
            } else {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app_handle.state::<AppState>();
                    let ok = match state.daemon_send(DaemonRequest::Stop).await {
                        Ok(DaemonResponse::Ack) => {
                            info!("proxy stopped");
                            true
                        }
                        Ok(DaemonResponse::Error { message }) => {
                            error!("daemon error: {message}");
                            false
                        }
                        Ok(_) => {
                            warn!("unexpected response from daemon");
                            false
                        }
                        Err(e) => {
                            error!("failed to send stop: {e}");
                            false
                        }
                    };
                    if !ok {
                        // Revert config on failure
                        let mut config = state.config.lock().unwrap();
                        config.enabled = true;
                        config.save(&state.config_path).ok();
                    }
                });
            }
        }
        ID_AUTOSTART => {
            info!("tray: autostart toggled");
            use tauri_plugin_autostart::ManagerExt;
            let autostart = app.autolaunch();
            match autostart.is_enabled() {
                Ok(true) => {
                    if let Err(e) = autostart.disable() {
                        error!("failed to disable autostart: {e}");
                    }
                }
                Ok(false) => {
                    if let Err(e) = autostart.enable() {
                        error!("failed to enable autostart: {e}");
                    }
                }
                Err(e) => error!("failed to check autostart: {e}"),
            }
        }
        ID_SETTINGS => {
            info!("tray: opening settings");
            open_settings_window(app);
        }
        ID_EXIT => {
            info!("tray: exit requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<AppState>();
                // Best-effort stop
                let _ = state.daemon_send(DaemonRequest::Stop).await;
                app_handle.exit(0);
            });
        }
        #[cfg(target_os = "macos")]
        ID_UNINSTALL_HELPER => {
            info!("tray: uninstall helper requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_uninstall_helper(app_handle).await;
            });
        }
        ID_ABOUT => {
            info!("menu: about dialog");
            use tauri_plugin_dialog::DialogExt;
            app.dialog()
                .message(format!("Hole {}", hole_gui::version::VERSION))
                .title("About Hole")
                .blocking_show();
        }
        _ => {}
    }
}

#[cfg(target_os = "macos")]
async fn handle_uninstall_helper(app: AppHandle) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let confirmed = app
        .dialog()
        .message("This will stop and remove the Hole daemon service.\n\nContinue?")
        .title("Uninstall Helper")
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Uninstall".into(),
            "Cancel".into(),
        ))
        .blocking_show();

    if !confirmed {
        return;
    }

    let exe = match crate::setup::daemon_binary_path() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot resolve binary path: {e}");
            return;
        }
    };

    let result = tokio::task::spawn_blocking(move || crate::setup::run_elevated(&exe, &["daemon", "uninstall"])).await;

    match result {
        Ok(Ok(status)) if status.success() => {
            app.dialog()
                .message("Daemon helper has been uninstalled.")
                .title("Uninstall Helper")
                .blocking_show();
        }
        Ok(Err(crate::setup::SetupError::Cancelled)) => {
            info!("user cancelled uninstall elevation");
        }
        Ok(Err(e)) => {
            error!("uninstall failed: {e}");
            app.dialog()
                .message(format!("Uninstall failed: {e}"))
                .title("Error")
                .blocking_show();
        }
        Ok(Ok(status)) => {
            let code = status.code().unwrap_or(-1);
            error!("uninstall exited with code {code}");
        }
        Err(e) => {
            error!("spawn_blocking failed: {e}");
        }
    }
}

fn open_settings_window(app: &AppHandle) {
    // Reuse existing window if it's already open
    if let Some(window) = app.get_webview_window("settings") {
        window.set_focus().ok();
        return;
    }

    #[allow(unused_mut)]
    let mut builder = WebviewWindowBuilder::new(app, "settings", WebviewUrl::default())
        .title("Hole Settings")
        .inner_size(600.0, 400.0)
        .resizable(true);

    // Menu bar (all platforms) -----
    {
        use tauri::menu::{Menu, Submenu};

        let about_item =
            MenuItem::with_id(app, ID_ABOUT, "About Hole", true, None::<&str>).expect("failed to create menu item");
        let help_submenu = Submenu::with_items(app, "Help", true, &[&about_item]).expect("failed to create submenu");

        #[cfg(not(target_os = "macos"))]
        let menu = Menu::with_items(app, &[&help_submenu]).expect("failed to create menu");

        #[cfg(target_os = "macos")]
        let menu = {
            let uninstall_item = MenuItem::with_id(app, ID_UNINSTALL_HELPER, "Uninstall Helper...", true, None::<&str>)
                .expect("failed to create menu item");
            let hole_submenu =
                Submenu::with_items(app, "Hole", true, &[&uninstall_item]).expect("failed to create submenu");
            Menu::with_items(app, &[&hole_submenu, &help_submenu]).expect("failed to create menu")
        };

        builder = builder.menu(menu).on_menu_event(|window, event| {
            handle_menu_event(window.app_handle(), event);
        });
    }

    match builder.build() {
        Ok(_window) => {
            #[cfg(target_os = "macos")]
            crate::platform::show_dock_icon(app);
        }
        Err(e) => {
            error!(error = %e, "failed to open settings window");
        }
    }
}

#[cfg(test)]
#[path = "tray_tests.rs"]
mod tray_tests;
