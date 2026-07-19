//! Typesets `crates/hole/dmg/background.typ` (Typst library) to a transparent
//! `background.png` + `background@2x.png` pair, so Finder composites the
//! dark-on-light art over its own white fill. macOS-only. Geometry (window,
//! icon size/positions) comes from `crates/hole/dmg/layout.json`, shared with
//! the Python builder.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use typst::foundations::{Dict, IntoValue};
use typst::text::FontInfo;
use typst_as_lib::TypstEngine;
use typst_layout::PagedDocument;
use typst_render::{render, RenderOptions};
use typst_utils::Scalar;

const SF_PRO_PATH: &str = "/System/Library/Fonts/SFNS.ttf";
// The drag-arrow polygon authored in background.typ is 92pt × 44pt; its offset is
// the icon midpoint minus these half-extents, so the arrow bbox centers on the gap.
const ARROW_HALF_W: i64 = 46;
const ARROW_HALF_H: i64 = 22;

/// The render family. Requires exactly one face named exactly "SF NS" (the
/// system-font family), so a swapped/absent font — or a different
/// SF-branded face like "SF Mono" — fails loudly rather than shipping wrong text.
pub(crate) fn pick_family(families: &[String]) -> Result<String> {
    match families {
        [only] if only == "SF NS" => Ok(only.clone()),
        [only] => Err(anyhow!("unexpected font family {only:?} — expected \"SF NS\"")),
        _ => Err(anyhow!("expected exactly 1 font face, got {}", families.len())),
    }
}

fn u32_at(v: &serde_json::Value, path: &[&str], idx: usize) -> Result<u32> {
    let mut cur = v;
    for k in path {
        cur = &cur[k];
    }
    cur[idx]
        .as_u64()
        .with_context(|| format!("layout.json {path:?}[{idx}]"))
        .map(|n| n as u32)
}

/// Read `background.typ` + `layout.json`; return the source, `[w,h]`, and the
/// `sys.inputs` key/values: window size and the arrow offset DERIVED from the icon
/// centers (not hand-tuned), so a geometry change moves the arrow automatically.
// The tuple return is the interface both `render_all` (below) and the test file
// destructure directly; a type alias would just rename the same shape, so the
// clippy::type_complexity note is suppressed rather than worked around.
#[allow(clippy::type_complexity)]
pub(crate) fn background_inputs(repo_root: &Path) -> Result<(String, [u32; 2], Vec<(&'static str, String)>)> {
    let dmg = repo_root.join("crates/hole/dmg");
    let source = std::fs::read_to_string(dmg.join("background.typ")).context("reading background.typ")?;
    let geo: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dmg.join("layout.json")).context("reading layout.json")?)?;
    let (w, h) = (u32_at(&geo, &["window"], 0)?, u32_at(&geo, &["window"], 1)?);
    let (app_x, fold_x) = (u32_at(&geo, &["app_pos"], 0)?, u32_at(&geo, &["appfolder_pos"], 0)?);
    let row_y = u32_at(&geo, &["app_pos"], 1)?;
    let arrow_dx = (app_x as i64 + fold_x as i64) / 2 - ARROW_HALF_W;
    let arrow_dy = row_y as i64 - ARROW_HALF_H;
    let inputs = vec![
        ("window_w", w.to_string()),
        ("window_h", h.to_string()),
        ("arrow_dx", arrow_dx.to_string()),
        ("arrow_dy", arrow_dy.to_string()),
    ];
    Ok((source, [w, h], inputs))
}

/// Typeset `source` with `font_bytes` and extra `inputs` (plus the derived font
/// family) as `sys.inputs`, render at integer `scale` px-per-pt, return
/// straight-alpha RGBA8 + dims.
pub fn render_typst(
    source: &str,
    font_bytes: &[u8],
    images: &[(String, Vec<u8>)],
    scale: u32,
    inputs: &[(&str, String)],
) -> Result<(Vec<u8>, u32, u32)> {
    let families: Vec<String> = FontInfo::iter(font_bytes).map(|f| f.family).collect();
    let family = pick_family(&families)?;

    let engine = TypstEngine::builder()
        .main_file(source)
        .fonts([font_bytes.to_vec()])
        .with_static_file_resolver(images.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>())
        .build();

    let mut dict = Dict::new();
    dict.insert("font".into(), family.into_value());
    for (k, v) in inputs {
        dict.insert((*k).into(), v.clone().into_value());
    }
    let compiled = engine.compile_with_input::<_, PagedDocument>(dict);

    // Propagate a real compile error first (full detail) so it isn't masked by the
    // warnings check when both occur; then treat ANY warning as a hard error (typst
    // 0.15.1 emits zero for SFNS.ttf — verified).
    let doc = compiled.output.map_err(|e| anyhow!("typst compile failed: {e:?}"))?;
    if !compiled.warnings.is_empty() {
        let msgs = compiled
            .warnings
            .iter()
            .map(|w| w.message.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow!("unexpected typst warning(s): {msgs}"));
    }

    // Fixed page size ⇒ page 1 is always full-size; a 2nd page is the only
    // (vertical) overflow signal. Horizontal clip is caught by the edge-ring test.
    if doc.pages().len() != 1 {
        return Err(anyhow!(
            "background.typ produced {} pages — content overflowed (would clip)",
            doc.pages().len()
        ));
    }
    let page = doc.pages().first().expect("one page");

    let pixmap = render(
        page,
        &RenderOptions {
            pixel_per_pt: Scalar::from(scale as f64),
            render_bleed: false,
        },
    );
    let (w, h) = (pixmap.width(), pixmap.height());
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    for px in pixmap.pixels() {
        let c = px.demultiply(); // premultiplied → straight, else text edges halo
        rgba.extend_from_slice(&[c.red(), c.green(), c.blue(), c.alpha()]);
    }
    Ok((rgba, w, h))
}

fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut encoder = png::Encoder::new(&mut buf, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().context("PNG header")?;
    writer.write_image_data(rgba).context("PNG data")?;
    drop(writer);
    Ok(buf)
}

fn read_icon(dmg_dir: &Path, rel: &str) -> Result<Vec<u8>> {
    std::fs::read(dmg_dir.join(rel)).with_context(|| format!("reading icon {rel}"))
}

/// Render+encode both scales. Both are produced before any file write, and each is
/// validated against `layout.json`'s window.
pub(crate) fn render_all(repo_root: &Path) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let (source, [jw, jh], inputs) = background_inputs(repo_root)?;
    let font_bytes = std::fs::read(SF_PRO_PATH).with_context(|| format!("reading {SF_PRO_PATH}"))?;
    let dmg = repo_root.join("crates/hole/dmg");
    let images = vec![
        ("./gear.svg".to_string(), read_icon(&dmg, "symbols/gear.svg")?),
        ("./hand.svg".to_string(), read_icon(&dmg, "symbols/hand.svg")?),
    ];
    let mut outputs = Vec::new();
    for (scale, name) in [(1u32, "background.png"), (2, "background@2x.png")] {
        let (rgba, w, h) = render_typst(&source, &font_bytes, &images, scale, &inputs)?;
        if (w, h) != (jw * scale, jh * scale) {
            return Err(anyhow!(
                "background {name}: got {w}x{h}, want {}x{}",
                jw * scale,
                jh * scale
            ));
        }
        outputs.push((name, encode_png(&rgba, w, h)?));
    }
    Ok(outputs)
}

/// Render into `out_dir` (a dedicated directory holding only the pair). Stages both
/// PNGs in a sibling `.<name>.staging` dir, then swaps it onto `out_dir` by moving
/// any existing out_dir aside with a single atomic rename, renaming staging into
/// place, and dropping the aside — so out_dir is only ever the complete old pair,
/// absent, or the new pair, never a mismatched partial. A kill mid-swap leaves
/// out_dir absent (build_dmg_at rejects that loudly).
pub fn build(repo_root: &Path, out_dir: &Path) -> Result<()> {
    let outputs = render_all(repo_root)?;
    let parent = out_dir.parent().context("out_dir has no parent")?;
    std::fs::create_dir_all(parent).context("creating output parent")?;
    let name = out_dir.file_name().and_then(|s| s.to_str()).unwrap_or("dmgbg");
    let staging = parent.join(format!(".{name}.staging"));

    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).context("creating staging dir")?;
    for (fname, bytes) in &outputs {
        std::fs::write(staging.join(fname), bytes).with_context(|| format!("writing staging {fname}"))?;
    }
    // Move any existing out_dir aside first (see the doc comment above).
    let aside = parent.join(format!(".{name}.old"));
    let _ = std::fs::remove_dir_all(&aside);
    if out_dir.exists() {
        std::fs::rename(out_dir, &aside).with_context(|| format!("moving old {} aside", out_dir.display()))?;
    }
    std::fs::rename(&staging, out_dir).with_context(|| format!("swapping staging into {}", out_dir.display()))?;
    let _ = std::fs::remove_dir_all(&aside);
    Ok(())
}
