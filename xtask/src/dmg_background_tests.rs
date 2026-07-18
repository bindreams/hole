use crate::dmg_background::{background_inputs, pick_family, render_all, render_typst};

const FONT: &str = "/System/Library/Fonts/SFNS.ttf";
const ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#0a84ff"/></svg>"##;
// Uses sys.inputs for the font (default keeps it standalone-compilable).
const SRC: &str = r####"
#set page(width: 660pt, height: 560pt, margin: (top: 226pt, x: 46pt, bottom: 34pt), fill: none)
#set text(font: sys.inputs.at("font", default: "SF NS"), size: 22pt, weight: "bold", fill: rgb("#1d1d1f"))
Hello #box(baseline: 25%, image("./icon.svg", height: 20pt)) world.
#block(fill: rgb(255, 0, 0, 128), width: 44pt, height: 16pt)
"####;

fn px(rgba: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
    let i = ((y * w + x) * 4) as usize;
    [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
}
fn near(p: [u8; 4], r: u8, g: u8, b: u8) -> bool {
    let d = |a: u8, b: u8| (a as i16 - b as i16).abs() <= 8;
    d(p[0], r) && d(p[1], g) && d(p[2], b)
}
fn png_dims(bytes: &[u8]) -> (u32, u32) {
    // png::Decoder<R> requires R: BufRead + Seek; &[u8] impls BufRead but not
    // Seek, so wrap in a Cursor (Seek over the same bytes, no behavior change).
    let r = png::Decoder::new(std::io::Cursor::new(bytes)).read_info().unwrap();
    (r.info().width, r.info().height)
}

#[skuld::test]
fn pick_family_requires_exact_sf_ns() {
    assert_eq!(pick_family(&["SF NS".into()]).unwrap(), "SF NS");
    assert!(
        pick_family(&["SF Mono".into()]).is_err(),
        "wrong-but-SF family must error"
    );
    assert!(pick_family(&["Helvetica".into()]).is_err(), "non-SF family must error");
    assert!(
        pick_family(&["SF NS".into(), "SF Mono".into()]).is_err(),
        ">1 face must error"
    );
    assert!(pick_family(&[]).is_err(), "no face must error");
}

#[skuld::test]
fn render_typst_dims_transparency_ink_and_alpha() {
    let font = std::fs::read(FONT).expect("read SFNS.ttf");
    let images = vec![("./icon.svg".to_string(), ICON.as_bytes().to_vec())];

    let (rgba1, w1, h1) = render_typst(SRC, &font, &images, 1, &[]).unwrap();
    assert_eq!((w1, h1), (660, 560));
    assert_eq!(rgba1.len(), (w1 * h1 * 4) as usize);
    let (_r2, w2, h2) = render_typst(SRC, &font, &images, 2, &[]).unwrap();
    assert_eq!((w2, h2), (1320, 1120));

    assert_eq!(px(&rgba1, w1, 2, 2)[3], 0, "corner transparent");
    assert!(
        rgba1
            .chunks_exact(4)
            .any(|p| p[3] >= 200 && near([p[0], p[1], p[2], p[3]], 0x1d, 0x1d, 0x1f)),
        "no dark ink"
    );
    assert!(
        rgba1
            .chunks_exact(4)
            .any(|p| p[0] > 230 && p[1] < 40 && p[2] < 40 && (110..=150).contains(&p[3])),
        "red not straight-alpha"
    );
}

#[skuld::test]
fn render_typst_errors_when_content_overflows_one_page() {
    let font = std::fs::read(FONT).expect("read SFNS.ttf");
    let src = format!(
        "#set page(width: 660pt, height: 560pt, margin: 20pt, fill: none)\n#set text(font: sys.inputs.at(\"font\", default: \"SF NS\"), size: 24pt)\n{}",
        "Overflow line. \\\n".repeat(80)
    );
    let err = render_typst(&src, &font, &[], 1, &[]).unwrap_err().to_string();
    assert!(err.contains("page"), "overflow must error mentioning pages, got: {err}");
}

#[skuld::test]
fn render_all_produces_both_scales_before_writing() {
    let outputs = render_all(&crate::repo_root().unwrap()).unwrap();
    assert_eq!(outputs.len(), 2, "both scales encoded before any write");
    for (name, bytes) in &outputs {
        let want = if name.contains("@2x") { (1320, 1120) } else { (660, 560) };
        assert_eq!(png_dims(bytes), want, "{name}");
    }
}

#[skuld::test]
fn build_swaps_atomic_pair_no_staging_leftover() {
    let base = tempfile::tempdir().unwrap();
    let out = base.path().join("dmgbg");
    crate::dmg_background::build(&crate::repo_root().unwrap(), &out).unwrap();
    for (name, want) in [
        ("background.png", (660u32, 560u32)),
        ("background@2x.png", (1320, 1120)),
    ] {
        assert_eq!(png_dims(&std::fs::read(out.join(name)).unwrap()), want, "{name}");
    }
    assert!(!base.path().join(".dmgbg.staging").exists(), "staging dir left behind");
}

#[skuld::test]
fn background_inputs_carries_window_and_derived_arrow() {
    let (source, [w, h], inputs) = background_inputs(&crate::repo_root().unwrap()).unwrap();
    assert_eq!([w, h], [660, 560]);
    let get = |k: &str| inputs.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v.clone());
    assert_eq!(get("window_w").as_deref(), Some("660"));
    // Arrow x-offset = icon midpoint (330) − half the 92pt arrow width (46) = 284.
    assert_eq!(get("arrow_dx").as_deref(), Some("284"));
    assert!(!source.is_empty());
}

#[skuld::test]
fn clean_icons_are_glyphs_not_white_boxes() {
    let font = std::fs::read(FONT).expect("read SFNS.ttf");
    let dmg = crate::repo_root().unwrap().join("crates/hole/dmg/symbols");
    for (file, r, g, b) in [("gear.svg", 0x8E, 0x8E, 0x93), ("hand.svg", 0x0A, 0x84, 0xFF)] {
        let svg = std::fs::read_to_string(dmg.join(file)).unwrap();
        // Structural: exactly the two self-color paths, no <style>/wireframe scaffolding.
        assert_eq!(
            svg.matches("<path").count(),
            2,
            "{file}: expected exactly 2 <path> elements"
        );
        assert!(!svg.contains("<style"), "{file}: SF-Symbols scaffolding present");

        let images = vec![(format!("./{file}"), svg.into_bytes())];
        let src = format!("#set page(width: 660pt, height: 560pt, margin: 0pt, fill: none)\n#place(top + left, box(image(\"./{file}\", height: 200pt)))");
        let (rgba, _w, _h) = render_typst(&src, &font, &images, 1, &[]).unwrap();
        let opaque = rgba.chunks_exact(4).filter(|p| p[3] == 255).count();
        let white = rgba.chunks_exact(4).filter(|p| *p == [255, 255, 255, 255]).count();
        assert!(opaque > 0, "{file}: nothing rendered");
        // Measured: clean ≈0.21–0.24, raw white-box ≈0.94.
        assert!(
            (white as f64) / (opaque as f64) < 0.5,
            "{file}: mostly opaque white — wireframe box?"
        );
        assert!(
            rgba.chunks_exact(4)
                .any(|p| p[3] == 255 && near([p[0], p[1], p[2], p[3]], r, g, b)),
            "{file}: missing self-color"
        );
    }
}
