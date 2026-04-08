use super::*;

#[cfg(target_os = "macos")]
const ICON_SIZE: u32 = 36;
#[cfg(target_os = "windows")]
const ICON_SIZE: u32 = 32;

#[skuld::test]
fn enabled_image_has_correct_dimensions() {
    let img = tray_image(TrayState::Enabled);
    let expected_len = (ICON_SIZE * ICON_SIZE * 4) as usize;
    assert_eq!(img.rgba().len(), expected_len);
    assert_eq!(img.width(), ICON_SIZE);
    assert_eq!(img.height(), ICON_SIZE);
}

#[skuld::test]
fn disabled_image_has_correct_dimensions() {
    let img = tray_image(TrayState::Disabled);
    let expected_len = (ICON_SIZE * ICON_SIZE * 4) as usize;
    assert_eq!(img.rgba().len(), expected_len);
    assert_eq!(img.width(), ICON_SIZE);
    assert_eq!(img.height(), ICON_SIZE);
}

#[skuld::test]
fn enabled_and_disabled_differ() {
    let enabled = tray_image(TrayState::Enabled);
    let disabled = tray_image(TrayState::Disabled);
    assert_ne!(enabled.rgba(), disabled.rgba());
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn is_light_taskbar_does_not_panic() {
    // Registry key may or may not exist in CI; just verify no panic.
    let _ = is_light_taskbar();
}
