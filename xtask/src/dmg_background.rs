//! `cargo xtask dmg-background` — render the macOS DMG installer background.
//!
//! Renders `crates/hole/dmg/background.svg` (resvg, the same renderer
//! `crates/hole/build.rs` uses for icons) to `.cache/dmg/background.png`
//! (660x560) and `background@2x.png` (1320x1120). `dmg-installer`'s dmgbuild
//! step consumes them — its `lookForHiDPI` picks up the `@2x` companion for a
//! crisp Retina background. macOS-only: needs the system font, and the
//! `hole-dmg` target that calls it is darwin-only.

use std::path::Path;

use anyhow::{Context, Result};

const WIDTH: u32 = 660;
const HEIGHT: u32 = 560;
/// macOS system font (SF Pro), loaded by explicit path so resolution never
/// depends on flaky system-font *name* matching.
const SF_PRO_PATH: &str = "/System/Library/Fonts/SFNS.ttf";

/// Render `svg` to a `width`x`height` straight-RGBA buffer using `opt` (which
/// carries the font database).
pub fn render_rgba(svg: &[u8], width: u32, height: u32, opt: &resvg::usvg::Options) -> Result<Vec<u8>> {
    let tree = resvg::usvg::Tree::from_data(svg, opt).context("parsing background.svg")?;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height).context("allocating pixmap")?;
    let sx = width as f32 / tree.size().width();
    let sy = height as f32 / tree.size().height();
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(sx, sy),
        &mut pixmap.as_mut(),
    );
    let rgba = pixmap.data().to_vec();
    // Contract: the DMG background must be fully opaque, so tiny-skia's
    // premultiplied output equals straight RGBA (no unpremultiply needed).
    // Enforce it loudly — a transparent SVG edit would otherwise emit
    // silently-wrong colors.
    assert!(
        rgba.chunks_exact(4).all(|p| p[3] == 0xFF),
        "DMG background must be fully opaque"
    );
    Ok(rgba)
}

fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut encoder = png::Encoder::new(&mut buf, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().context("writing PNG header")?;
    writer.write_image_data(rgba).context("writing PNG data")?;
    drop(writer);
    Ok(buf)
}

/// Render the background SVG to `.cache/dmg/background.png` + `background@2x.png`.
pub fn build(repo_root: &Path) -> Result<()> {
    let svg_path = repo_root.join("crates/hole/dmg/background.svg");
    let svg = std::fs::read(&svg_path).with_context(|| format!("reading {}", svg_path.display()))?;

    let out_dir = repo_root.join(".cache/dmg");
    std::fs::create_dir_all(&out_dir).context("creating .cache/dmg/")?;

    let mut opt = resvg::usvg::Options {
        font_family: "SF Pro".to_string(),
        ..Default::default()
    };
    opt.fontdb_mut()
        .load_font_file(SF_PRO_PATH)
        .with_context(|| format!("loading font {SF_PRO_PATH}"))?;

    for (scale, name) in [(1u32, "background.png"), (2, "background@2x.png")] {
        let (w, h) = (WIDTH * scale, HEIGHT * scale);
        let png = encode_png(&render_rgba(&svg, w, h, &opt)?, w, h)?;
        let path = out_dir.join(name);
        std::fs::write(&path, png).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
