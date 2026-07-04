// Platform-specific behavior (macOS dock icon toggling).

/// Single owner of the macOS dock/menu-bar activation policy. `dock_visible`
/// true → Regular (Dashboard open); false → Accessory (menu-bar only). The
/// bundle's LSUIElement=true is the Accessory default; this drives the runtime
/// transitions and the unbundled/dev fallback.
#[cfg(target_os = "macos")]
fn set_menu_bar_mode(app: &tauri::AppHandle, dock_visible: bool) {
    let policy = if dock_visible {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    if let Err(e) = app.set_activation_policy(policy) {
        tracing::warn!(error = %e, dock_visible, "failed to set macOS activation policy");
    }
}

/// Called during Tauri setup.
pub fn on_setup(_app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        // Dock shows the Hole icon whenever the app is Regular (Dashboard open),
        // including unbundled runs with no Info.plist icon.
        let mtm = objc2::MainThreadMarker::new().expect("contract: Tauri setup runs on the main thread");
        hole::dock_icon::set_dock_icon(mtm);
        set_menu_bar_mode(_app.handle(), false);
    }
    Ok(())
}

/// Show dock icon (call when settings window opens).
#[cfg(target_os = "macos")]
pub fn show_dock_icon(app: &tauri::AppHandle) {
    set_menu_bar_mode(app, true);
}

/// Hide dock icon (call when settings window closes).
#[cfg(target_os = "macos")]
pub fn hide_dock_icon(app: &tauri::AppHandle) {
    set_menu_bar_mode(app, false);
}
