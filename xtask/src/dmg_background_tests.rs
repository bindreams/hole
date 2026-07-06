// A text-free SVG needs no font DB, so this stays cross-platform (no SF Pro /
// macOS dependency). The rect fills the whole 10x10 viewBox with #112233, so
// sampling pixels proves resvg actually painted AND that the viewBox was scaled
// to fill the requested (non-square) extent — a width/height swap or a deleted
// `render` call fails this, unlike a bare buffer-length check.
#[skuld::test]
fn render_rgba_paints_and_scales() {
    let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#112233"/></svg>"##;
    let (w, h) = (120u32, 80u32);
    let opt = resvg::usvg::Options::default();
    let rgba = crate::dmg_background::render_rgba(svg, w, h, &opt).unwrap();
    assert_eq!(rgba.len(), (w * h * 4) as usize);

    let px = |x: u32, y: u32| {
        let i = ((y * w + x) * 4) as usize;
        (rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3])
    };
    assert_eq!(
        px(w / 2, h / 2),
        (0x11, 0x22, 0x33, 0xff),
        "center must be the painted, opaque fill"
    );
    assert_eq!(
        px(w - 1, h - 1),
        (0x11, 0x22, 0x33, 0xff),
        "far corner proves the viewBox scaled to fill"
    );
}
