//! Tray icon image loading and platform-specific theme handling.

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("tray icons not yet supported on this platform");

use tauri::image::Image;

/// Which visual state the tray icon should display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Enabled,
    Disabled,
}

impl From<bool> for TrayState {
    fn from(enabled: bool) -> Self {
        if enabled {
            TrayState::Enabled
        } else {
            TrayState::Disabled
        }
    }
}

/// Return the appropriate tray icon [`Image`] for the given state.
///
/// On macOS, returns a template image (caller must set `icon_as_template(true)`).
/// On Windows, returns the icon colored for the current taskbar theme.
pub fn tray_image(state: TrayState) -> Image<'static> {
    #[cfg(target_os = "macos")]
    {
        macos_image(state)
    }

    #[cfg(target_os = "windows")]
    {
        windows_image(state)
    }
}

// macOS ===============================================================================================================

// Enabled and Disabled intentionally resolve to the same bytes (user
// spec 2026-05-10: the designer hasn't shipped a separate disabled
// design). The `TrayState` enum is kept so a future design can drop in
// at this dispatch site without API churn at every call site.
#[cfg(target_os = "macos")]
fn macos_image(_state: TrayState) -> Image<'static> {
    const TEMPLATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-template.rgba"));
    const SIZE: u32 = 36;
    Image::new(TEMPLATE, SIZE, SIZE)
}

// Windows =============================================================================================================

// See `macos_image` re: identical bytes for Enabled/Disabled.
#[cfg(target_os = "windows")]
fn windows_image(_state: TrayState) -> Image<'static> {
    const DARK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-dark.rgba"));
    const LIGHT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-light.rgba"));
    const SIZE: u32 = 32;

    let rgba = if is_light_taskbar() { LIGHT } else { DARK };
    Image::new(rgba, SIZE, SIZE)
}

/// Check whether the Windows taskbar uses a light theme.
///
/// Reads `SystemUsesLightTheme` from the registry. Returns `false` (dark) on any error.
#[cfg(target_os = "windows")]
fn is_light_taskbar() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize") else {
        return false;
    };
    let Ok(val): Result<u32, _> = key.get_value("SystemUsesLightTheme") else {
        return false;
    };
    val == 1
}

#[cfg(test)]
#[path = "tray_icons_tests.rs"]
mod tray_icons_tests;
