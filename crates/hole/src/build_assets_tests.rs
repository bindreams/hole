//! Verifies build.rs assets: the app ICNS and the runtime Dock-icon PNG.

use std::io::Cursor;

#[skuld::test]
fn app_icns_has_required_resolutions() {
    // The canonical bundled artifact (build.rs exports its path), not a copy.
    // The generated ICNS, via HOLE_ICNS_PATH — a cargo-isolated OUT_DIR copy of
    // the bundled bytes (the shared .cache path can be written mid-read).
    const ICNS: &[u8] = include_bytes!(env!("HOLE_ICNS_PATH"));
    let family = icns::IconFamily::read(Cursor::new(ICNS)).expect("icon.icns must parse");
    let have = family.available_icons();
    // Independent minimum, not build.rs's ICNS_ENTRIES: dropping any of these from
    // the producer must fail here.
    use icns::IconType::{
        RGBA32_128x128, RGBA32_16x16, RGBA32_256x256, RGBA32_32x32, RGBA32_512x512, RGBA32_512x512_2x,
    };
    for t in [
        RGBA32_16x16,
        RGBA32_32x32,
        RGBA32_128x128,
        RGBA32_256x256,
        RGBA32_512x512,
        RGBA32_512x512_2x,
    ] {
        assert!(have.contains(&t), "icon.icns missing required {t:?}; have {have:?}");
        // The stored image must decode and be non-empty (guards a corrupt entry).
        let img = family.get_icon_with_type(t).expect("required type present");
        assert!(img.width() > 0 && img.height() > 0, "{t:?} decoded empty");
    }
}

#[skuld::test]
fn app_icon_png_is_square_hi_res() {
    // Independent minimum: the Dock icon must be a square, hi-res PNG.
    const PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"));
    let reader = png::Decoder::new(Cursor::new(PNG))
        .read_info()
        .expect("app-icon.png must be a valid PNG");
    let info = reader.info();
    assert_eq!(info.width, info.height, "app-icon.png must be square");
    assert!(info.width >= 256, "app-icon.png must be >=256px, got {}", info.width);
}
