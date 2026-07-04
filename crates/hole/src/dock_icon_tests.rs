use super::*;

#[skuld::test]
fn app_icon_decodes_to_nonempty_nsimage() {
    // The compiled-in PNG is content-checked by app_icon_png_is_square_hi_res;
    // this proves the NSData→NSImage bridge decodes it to a non-degenerate image.
    // (set_dock_icon degrades at runtime if end-user AppKit ever differs.)
    let image = decode_app_icon().expect("app-icon.png must decode as an NSImage");
    let size = image.size();
    assert!(size.width > 0.0 && size.height > 0.0, "decoded NSImage is empty");
}
