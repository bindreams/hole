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
const ID_INSTALL_UPDATE: &str = "install_update";
const ID_CHECK_UPDATE: &str = "check_update";

// Tray creation =====

/// Build the tray menu, optionally including an "Install Update" item.
pub fn build_tray_menu(
    app: &AppHandle,
    update: Option<&hole_gui::update::UpdateInfo>,
) -> Result<tauri::menu::Menu<tauri::Wry>, tauri::Error> {
    let enable = CheckMenuItem::with_id(app, ID_ENABLE, "Enable", true, false, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(app, ID_AUTOSTART, "Start at Login", true, false, None::<&str>)?;
    let settings = MenuItem::with_id(app, ID_SETTINGS, "Settings...", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, ID_EXIT, "Exit", true, None::<&str>)?;

    if let Some(info) = update {
        let update_item = MenuItem::with_id(
            app,
            ID_INSTALL_UPDATE,
            format!("Install Update (v{})", info.version),
            true,
            None::<&str>,
        )?;
        let sep3 = PredefinedMenuItem::separator(app)?;
        tauri::menu::Menu::with_items(
            app,
            &[&enable, &autostart, &sep1, &settings, &sep2, &update_item, &sep3, &exit],
        )
    } else {
        tauri::menu::Menu::with_items(app, &[&enable, &autostart, &sep1, &settings, &sep2, &exit])
    }
}

/// Sync tray menu checkbox states from the current config.
pub fn sync_menu_state(app: &AppHandle, menu: &tauri::menu::Menu<tauri::Wry>) {
    let state = app.state::<AppState>();
    let config = state.config.lock().unwrap();
    if let Some(item) = menu.get(ID_ENABLE) {
        if let Some(check) = item.as_check_menuitem() {
            check.set_checked(config.enabled).ok();
        }
    }
}

/// Create and register the system tray icon with its menu.
pub fn create_tray(app: &tauri::App) -> Result<TrayIcon, tauri::Error> {
    let menu = build_tray_menu(app.handle(), None)?;

    let tray = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip("Hole")
        .on_menu_event(handle_menu_event)
        .build(app)?;

    sync_menu_state(app.handle(), &menu);

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
        ID_INSTALL_UPDATE => {
            info!("tray: install update requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_install_update_from_tray(app_handle).await;
            });
        }
        ID_CHECK_UPDATE => {
            info!("menu: check for updates");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_check_for_updates(app_handle).await;
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

async fn handle_install_update_from_tray(app: AppHandle) {
    use tauri_plugin_dialog::DialogExt;

    // Get update info from update state.
    let update_state = app.state::<hole_gui::update::UpdateState>();
    let update_info = update_state.rx.borrow().clone();

    let Some(info) = update_info else {
        warn!("install update clicked but no update info available");
        return;
    };

    let download_dir = std::env::temp_dir().join("hole-update");
    if let Err(e) = std::fs::create_dir_all(&download_dir) {
        error!("failed to create temp dir: {e}");
        return;
    }
    let dest = download_dir.join(&info.asset_name);
    let asset_url = info.asset_url.clone();
    let dest_for_download = dest.clone();

    // Download on blocking thread.
    let download_result =
        tokio::task::spawn_blocking(move || hole_gui::update::download_asset(&asset_url, &dest_for_download)).await;

    match download_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("download failed: {e}");
            app.dialog()
                .message(format!("Download failed: {e}"))
                .title("Update Error")
                .blocking_show();
            return;
        }
        Err(e) => {
            error!("download task panicked: {e}");
            return;
        }
    }

    // Run installer (interactive mode).
    let dest_clone = dest.clone();
    let install_result = tokio::task::spawn_blocking(move || hole_gui::update::run_installer(&dest_clone, false)).await;

    match install_result {
        Ok(Ok(())) => {
            // On Windows, exit app to let MSI complete.
            // On macOS, the installer already copied the app.
            let _ = std::fs::remove_file(&dest);
            app.exit(0);
        }
        Ok(Err(e)) => {
            error!("installation failed: {e}");
            let _ = std::fs::remove_file(&dest);
            app.dialog()
                .message(format!("Installation failed: {e}"))
                .title("Update Error")
                .blocking_show();
        }
        Err(e) => {
            error!("install task panicked: {e}");
        }
    }
}

async fn handle_check_for_updates(app: AppHandle) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let result = tokio::task::spawn_blocking(hole_gui::update::check_for_update).await;

    match result {
        Ok(Ok(Some(info))) => {
            let confirmed = app
                .dialog()
                .message(format!(
                    "Version {} is available.\n\nWould you like to install it now?",
                    info.version
                ))
                .title("Update Available")
                .buttons(MessageDialogButtons::OkCancelCustom("Install".into(), "Later".into()))
                .blocking_show();

            if confirmed {
                // Store the update info and reuse the install handler.
                let update_state = app.state::<hole_gui::update::UpdateState>();
                update_state.tx.send_replace(Some(info));
                handle_install_update_from_tray(app).await;
            }
        }
        Ok(Ok(None)) => {
            app.dialog()
                .message(format!(
                    "You're running the latest version ({}).",
                    hole_gui::version::VERSION
                ))
                .title("No Updates Available")
                .blocking_show();
        }
        Ok(Err(e)) => {
            app.dialog()
                .message(format!("Failed to check for updates: {e}"))
                .title("Update Error")
                .blocking_show();
        }
        Err(e) => {
            error!("update check task panicked: {e}");
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

        let check_update_item = MenuItem::with_id(app, ID_CHECK_UPDATE, "Check for Updates...", true, None::<&str>)
            .expect("failed to create menu item");
        let about_item =
            MenuItem::with_id(app, ID_ABOUT, "About Hole", true, None::<&str>).expect("failed to create menu item");
        let help_submenu = Submenu::with_items(app, "Help", true, &[&check_update_item, &about_item])
            .expect("failed to create submenu");

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
