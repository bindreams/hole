//! Verifies build.rs assets: the app ICNS and the runtime Dock-icon PNG.

use std::io::Cursor;

#[skuld::test]
fn app_icns_has_required_resolutions() {
    // Read the OUT_DIR copy (HOLE_ICNS_PATH), not shared .cache, which a concurrent build can rewrite mid-read.
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
        let img = family.get_icon_with_type(t).expect("required type present");
        assert!(img.width() > 0 && img.height() > 0, "{t:?} decoded empty");
    }
    // Content, not just geometry: a blank/transparent render (broken SVG, resvg
    // regression) has the right dimensions but ships an invisible icon.
    let rgba = family
        .get_icon_with_type(RGBA32_128x128)
        .expect("128px present")
        .convert_to(icns::PixelFormat::RGBA);
    assert!(
        rgba.data().chunks_exact(4).any(|px| px[3] != 0),
        "icon.icns 128px is fully transparent"
    );
}

#[skuld::test]
fn app_icon_png_is_square_hi_res() {
    const PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"));
    let mut reader = png::Decoder::new(Cursor::new(PNG))
        .read_info()
        .expect("app-icon.png must be a valid PNG");
    let (w, h, color) = {
        let info = reader.info();
        (info.width, info.height, info.color_type)
    };
    // Independent minimum: a square, hi-res PNG.
    assert_eq!(w, h, "app-icon.png must be square");
    assert!(w >= 256, "app-icon.png must be >=256px, got {w}");
    // Content, not just geometry: build.rs writes RGBA, so require an opaque pixel.
    assert_eq!(color, png::ColorType::Rgba, "expected an RGBA app-icon.png");
    let mut buf = vec![0u8; reader.output_buffer_size().expect("app-icon.png buffer size")];
    let frame = reader.next_frame(&mut buf).expect("decode app-icon.png frame");
    assert!(
        buf[..frame.buffer_size()].chunks_exact(4).any(|px| px[3] != 0),
        "app-icon.png is fully transparent"
    );
}
