//! Tray icon image loading and platform-specific theme handling.

use tauri::image::Image;

/// Which visual state the tray icon should display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Enabled,
    Disabled,
}

impl From<bool> for TrayState {
    fn from(enabled: bool) -> Self {
        if enabled { TrayState::Enabled } else { TrayState::Disabled }
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

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = state;
        unimplemented!("tray icons not yet supported on this platform")
    }
}

// macOS =====

#[cfg(target_os = "macos")]
fn macos_image(state: TrayState) -> Image<'static> {
    const ENABLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-enabled-template.rgba"));
    const DISABLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-disabled-template.rgba"));
    const SIZE: u32 = 36;

    let rgba = match state {
        TrayState::Enabled => ENABLED,
        TrayState::Disabled => DISABLED,
    };
    Image::new(rgba, SIZE, SIZE)
}

// Windows =====

#[cfg(target_os = "windows")]
fn windows_image(state: TrayState) -> Image<'static> {
    const ENABLED_DARK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray-enabled-dark.rgba"));
    const ENABLED_LIGHT: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/tray-enabled-light.rgba"));
    const DISABLED_DARK: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/tray-disabled-dark.rgba"));
    const DISABLED_LIGHT: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/tray-disabled-light.rgba"));
    const SIZE: u32 = 32;

    let is_light = is_light_taskbar();
    let rgba = match (state, is_light) {
        (TrayState::Enabled, false) => ENABLED_DARK,
        (TrayState::Enabled, true) => ENABLED_LIGHT,
        (TrayState::Disabled, false) => DISABLED_DARK,
        (TrayState::Disabled, true) => DISABLED_LIGHT,
    };
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
    let Ok(key) =
        hkcu.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")
    else {
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
