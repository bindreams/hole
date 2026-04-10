use std::path::{Path, PathBuf};

fn main() {
    let icons_dir = Path::new("icons");
    let svg_path = icons_dir.join("icon.svg");

    println!("cargo:rerun-if-changed={}", svg_path.display());

    let repo_root = git_repo_root();
    let cache_icons_dir = repo_root.join(".cache").join("icons");
    std::fs::create_dir_all(&cache_icons_dir).expect("failed to create .cache/icons/");

    emit_version_env(&repo_root);
    generate_icons(&svg_path, &cache_icons_dir);
    generate_tray_icons(icons_dir);

    // Runtime asset acquisition (v2ray-plugin Go build, wintun.dll download)
    // moved to `cargo xtask deps` in Commit 4 of this PR. See issue #143.

    ensure_external_bin_stub(&repo_root);
    tauri_build::build();
}

/// Ensure the `externalBin` stub exists so `tauri_build::build()` passes
/// validation even when `cargo xtask deps` has not been run yet.
/// The real binary is built by `cargo xtask deps`.
fn ensure_external_bin_stub(repo_root: &Path) {
    let target = std::env::var("TARGET").unwrap();
    let suffix = if target.contains("windows") { ".exe" } else { "" };
    let path = repo_root
        .join(".cache/v2ray-plugin")
        .join(format!("v2ray-plugin-{target}{suffix}"));
    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("failed to create .cache/v2ray-plugin/");
        std::fs::File::create(&path).expect("failed to create v2ray-plugin stub");
        println!("cargo:warning=created empty v2ray-plugin stub — run `cargo xtask deps` for a real build");
    }
}

// Repo root ===========================================================================================================

fn git_repo_root() -> PathBuf {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("failed to run `git rev-parse --show-toplevel` — is git installed?");

    assert!(output.status.success(), "git rev-parse --show-toplevel failed");

    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

// Version =============================================================================================================

fn emit_version_env(repo_root: &Path) {
    let git_dir = repo_root.join(".git");

    // Rerun triggers: branch ref changes, tag changes, packed-refs. The
    // version computation itself lives in xtask-lib so it's testable and
    // shared with `cargo xtask version` (which the prek hook + release CI
    // workflow use). See xtask-lib/src/version.rs and issue #143.
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(refpath) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(refpath).display());
        }
    }
    println!("cargo:rerun-if-changed={}", git_dir.join("refs").join("tags").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());

    let version = xtask_lib::version::display_version(repo_root);
    println!("cargo:rustc-env=HOLE_VERSION={version}");
}

// Icons ===============================================================================================================

fn generate_icons(svg_path: &Path, out_dir: &Path) {
    let svg_data = std::fs::read(svg_path).expect("failed to read icon.svg");
    let tree =
        resvg::usvg::Tree::from_data(&svg_data, &resvg::usvg::Options::default()).expect("failed to parse icon.svg");

    // Generate PNGs at required sizes
    for size in [32u32, 128] {
        let png_path = out_dir.join(format!("{size}x{size}.png"));
        render_png(&tree, size, &png_path);
    }

    // Generate ICO (contains 16x16 + 32x32 + 256x256)
    let ico_path = out_dir.join("icon.ico");
    render_ico(&tree, &ico_path);

    // Generate ICNS (Tauri expects it but only uses on macOS)
    let icns_path = out_dir.join("icon.icns");
    let png_data = std::fs::read(out_dir.join("128x128.png")).unwrap();
    write_icns(&icns_path, &png_data);
}

fn render_to_rgba(tree: &resvg::usvg::Tree, size: u32) -> Vec<u8> {
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size).unwrap();
    let scale_x = size as f32 / tree.size().width();
    let scale_y = size as f32 / tree.size().height();
    let transform = resvg::tiny_skia::Transform::from_scale(scale_x, scale_y);
    resvg::render(tree, transform, &mut pixmap.as_mut());
    pixmap.data().to_vec()
}

fn render_png(tree: &resvg::usvg::Tree, size: u32, path: &Path) {
    let rgba = render_to_rgba(tree, size);
    let file = std::fs::File::create(path).unwrap();
    let mut encoder = png::Encoder::new(file, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(&rgba).unwrap();
}

fn render_ico(tree: &resvg::usvg::Tree, path: &Path) {
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 32, 256] {
        let rgba = render_to_rgba(tree, size);
        let image = ico::IconImage::from_rgba_data(size, size, rgba);
        icon_dir.add_entry(ico::IconDirEntry::encode(&image).unwrap());
    }
    let file = std::fs::File::create(path).unwrap();
    icon_dir.write(file).unwrap();
}

fn write_icns(path: &Path, png_data: &[u8]) {
    // Minimal ICNS: magic + size header, then ic07 (128x128 PNG) entry
    let entry_size = (8 + png_data.len()) as u32;
    let total_size = 8 + entry_size;
    let mut buf = Vec::with_capacity(total_size as usize);
    buf.extend_from_slice(b"icns");
    buf.extend_from_slice(&total_size.to_be_bytes());
    buf.extend_from_slice(b"ic07");
    buf.extend_from_slice(&entry_size.to_be_bytes());
    buf.extend_from_slice(png_data);
    std::fs::write(path, buf).unwrap();
}

// Tray icons ==========================================================================================================

fn generate_tray_icons(icons_dir: &Path) {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    for name in ["tray-enabled", "tray-disabled"] {
        let svg_path = icons_dir.join(format!("{name}.svg"));
        println!("cargo:rerun-if-changed={}", svg_path.display());

        let svg_data =
            std::fs::read(&svg_path).unwrap_or_else(|e| panic!("failed to read {}: {e}", svg_path.display()));
        let tree = resvg::usvg::Tree::from_data(&svg_data, &resvg::usvg::Options::default())
            .unwrap_or_else(|e| panic!("failed to parse {name}.svg: {e}"));

        match target_os.as_str() {
            "macos" => generate_tray_icons_macos(&tree, &out_dir, name),
            "windows" => generate_tray_icons_windows(&tree, &out_dir, name),
            other => println!("cargo:warning=tray icon generation not implemented for {other}"),
        }
    }
}

fn generate_tray_icons_macos(tree: &resvg::usvg::Tree, out_dir: &Path, name: &str) {
    let mut rgba = render_to_rgba_padded(tree, 36, 2);
    unpremultiply_rgba(&mut rgba);
    let template = luminance_to_alpha(&rgba);
    let path = out_dir.join(format!("{name}-template.rgba"));
    std::fs::write(&path, &template).unwrap();
}

fn generate_tray_icons_windows(tree: &resvg::usvg::Tree, out_dir: &Path, name: &str) {
    let mut rgba = render_to_rgba_padded(tree, 32, 1);
    unpremultiply_rgba(&mut rgba);

    // Dark taskbar variant: light artwork on transparent (as rendered)
    let dark_path = out_dir.join(format!("{name}-dark.rgba"));
    std::fs::write(&dark_path, &rgba).unwrap();

    // Light taskbar variant: invert RGB, keep alpha
    let light = invert_colors(&rgba);
    let light_path = out_dir.join(format!("{name}-light.rgba"));
    std::fs::write(&light_path, &light).unwrap();
}

/// Render an SVG tree into an RGBA buffer of `target_size`, with `padding` px on each side.
fn render_to_rgba_padded(tree: &resvg::usvg::Tree, target_size: u32, padding: u32) -> Vec<u8> {
    debug_assert!(
        2 * padding < target_size,
        "padding must be less than half of target_size"
    );
    let content_size = target_size - 2 * padding;
    let mut content_pixmap = resvg::tiny_skia::Pixmap::new(content_size, content_size).unwrap();
    let scale_x = content_size as f32 / tree.size().width();
    let scale_y = content_size as f32 / tree.size().height();
    let transform = resvg::tiny_skia::Transform::from_scale(scale_x, scale_y);
    resvg::render(tree, transform, &mut content_pixmap.as_mut());

    let mut canvas = resvg::tiny_skia::Pixmap::new(target_size, target_size).unwrap();
    canvas.draw_pixmap(
        padding as i32,
        padding as i32,
        content_pixmap.as_ref(),
        &resvg::tiny_skia::PixmapPaint::default(),
        resvg::tiny_skia::Transform::identity(),
        None,
    );
    canvas.data().to_vec()
}

/// Convert premultiplied RGBA to straight RGBA.
fn unpremultiply_rgba(rgba: &mut [u8]) {
    for pixel in rgba.chunks_exact_mut(4) {
        let a = pixel[3] as u32;
        if a == 0 {
            pixel[0] = 0;
            pixel[1] = 0;
            pixel[2] = 0;
            continue;
        }
        if a == 255 {
            continue;
        }
        pixel[0] = ((pixel[0] as u32 * 255 + a / 2) / a).min(255) as u8;
        pixel[1] = ((pixel[1] as u32 * 255 + a / 2) / a).min(255) as u8;
        pixel[2] = ((pixel[2] as u32 * 255 + a / 2) / a).min(255) as u8;
    }
}

/// Convert straight RGBA to a macOS template image: alpha = BT.601 luminance × original alpha.
fn luminance_to_alpha(rgba: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; rgba.len()];
    for (dst, src) in out.chunks_exact_mut(4).zip(rgba.chunks_exact(4)) {
        let r = src[0] as u32;
        let g = src[1] as u32;
        let b = src[2] as u32;
        let a = src[3] as u32;
        let lum = (r * 77 + g * 150 + b * 29) >> 8;
        dst[3] = ((lum * a + 127) / 255) as u8;
    }
    out
}

/// Invert RGB channels of straight RGBA, keeping alpha unchanged.
fn invert_colors(rgba: &[u8]) -> Vec<u8> {
    let mut out = rgba.to_vec();
    for pixel in out.chunks_exact_mut(4) {
        if pixel[3] == 0 {
            continue;
        }
        pixel[0] = 255 - pixel[0];
        pixel[1] = 255 - pixel[1];
        pixel[2] = 255 - pixel[2];
    }
    out
}
