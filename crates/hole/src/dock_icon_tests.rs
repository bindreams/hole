use super::*;

#[skuld::test]
fn app_icon_decodes_to_nonempty_nsimage() {
    // The compiled-in PNG is content-checked by app_icon_png_is_square_hi_res;
    // this proves the NSData→NSImage bridge decodes it (decode_app_icon rejects
    // a nil or zero-size image).
    assert!(
        decode_app_icon().is_some(),
        "app-icon.png must decode as a non-empty NSImage"
    );
}

#[skuld::test]
fn is_bundled_exe_detects_app_layout() {
    assert!(is_bundled_exe(Path::new("/Applications/Hole.app/Contents/MacOS/hole")));
    assert!(!is_bundled_exe(Path::new("/Users/me/src/hole/target/debug/hole")));
    assert!(!is_bundled_exe(Path::new("hole")));
}
