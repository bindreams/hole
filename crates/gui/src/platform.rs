// Platform-specific behavior (macOS dock icon toggling).

/// Called during Tauri setup.
pub fn on_setup(_app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        // Hide dock icon on startup (tray-only mode)
        _app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    }
    Ok(())
}

/// Show dock icon (call when settings window opens).
#[cfg(target_os = "macos")]
pub fn show_dock_icon(app: &tauri::AppHandle) {
    app.set_activation_policy(tauri::ActivationPolicy::Regular);
}

/// Hide dock icon (call when settings window closes).
#[cfg(target_os = "macos")]
pub fn hide_dock_icon(app: &tauri::AppHandle) {
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}
