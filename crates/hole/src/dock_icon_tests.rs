use super::*;

#[skuld::test]
fn app_icon_decodes_to_nonempty_nsimage() {
    // Decodes on the BUILD host and is non-empty. (End-user AppKit may differ, so
    // set_dock_icon degrades at runtime rather than assuming this holds there.)
    let image = decode_app_icon().expect("app-icon.png must decode as an NSImage");
    let size = image.size(); // NSSize; if it needs a feature/unsafe, adjust at impl time.
    assert!(size.width > 0.0 && size.height > 0.0, "decoded NSImage is empty");
}
