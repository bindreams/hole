use std::path::{Path, PathBuf};

fn main() {
    let icons_dir = Path::new("icons");

    // Rerun on any SVG change in icons/, not just the ones the active
    // target reads. Designers iterating across platforms (or hosts
    // toggling target_os via incremental builds) shouldn't get stale
    // outputs. Watching the directory mtime catches additions/removals
    // that don't touch existing files.
    println!("cargo:rerun-if-changed={}", icons_dir.display());
    for entry in std::fs::read_dir(icons_dir).expect("failed to read icons dir") {
        let path = entry
            .unwrap_or_else(|e| panic!("failed to read entry in {}: {e}", icons_dir.display()))
            .path();
        if path.extension().and_then(|e| e.to_str()) == Some("svg") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let repo_root = git_repo_root();
    let cache_icons_dir = repo_root.join(".cache").join("icons");
    std::fs::create_dir_all(&cache_icons_dir).expect("failed to create .cache/icons/");

    emit_version_env(&repo_root);
    generate_icons(icons_dir, &cache_icons_dir);
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

fn generate_icons(icons_dir: &Path, out_dir: &Path) {
    // Always produce platform-correct ICO and ICNS regardless of host.
    // ICO is consumed by Windows bundles, ICNS by macOS. Reading the
    // wrong SVG into either would silently ship the wrong design on a
    // cross-bundle (e.g. `tauri build` targeting macOS from a Windows
    // host). Tauri's manifest references both files unconditionally —
    // the tauri_build validation step needs them present on every host.
    let win_tree = parse_svg(&icons_dir.join("icon-windows.svg"));
    let mac_tree = parse_svg(&icons_dir.join("icon-macos.svg"));

    render_ico(&win_tree, &out_dir.join("icon.ico"));

    // ICNS: render the macOS SVG to 128×128 PNG and wrap in a minimal
    // ic07 container.
    let mac_128_png = render_png_in_memory(&mac_tree, 128);
    write_icns(&out_dir.join("icon.icns"), &mac_128_png);

    // PNG fallbacks (referenced unconditionally by tauri.conf.json,
    // used as window icon on the host platform). Render from the
    // host's SVG so a host-resident GUI window shows the right design.
    let host_tree = match std::env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => &win_tree,
        "macos" => &mac_tree,
        other => panic!("app icon not provided for target_os={other}"),
    };
    for size in [32u32, 128] {
        render_png(host_tree, size, &out_dir.join(format!("{size}x{size}.png")));
    }
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
    std::fs::write(path, render_png_in_memory(tree, size)).unwrap();
}

fn render_png_in_memory(tree: &resvg::usvg::Tree, size: u32) -> Vec<u8> {
    let rgba = render_to_rgba(tree, size);
    let mut buf = Vec::new();
    let mut encoder = png::Encoder::new(&mut buf, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(&rgba).unwrap();
    drop(writer);
    buf
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

    // Clean any pre-rename tray rgba files left by a previous incremental
    // build. include_bytes! cites only the new names, so stale files
    // would silently bloat OUT_DIR.
    if let Ok(read) = std::fs::read_dir(&out_dir) {
        for entry in read.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("tray-") && name.ends_with(".rgba") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    // No build-time padding: the SVG is the source of truth for the
    // icon's internal margins. If breathing room is needed, adjust the
    // SVG's viewBox-relative artwork instead of compensating here.
    match target_os.as_str() {
        "windows" => {
            for variant in ["dark", "light"] {
                let svg_path = icons_dir.join(format!("tray-windows-{variant}.svg"));
                let tree = parse_svg(&svg_path);
                let mut rgba = render_to_rgba(&tree, 32);
                unpremultiply_rgba(&mut rgba);
                std::fs::write(out_dir.join(format!("tray-{variant}.rgba")), &rgba).unwrap();
            }
        }
        "macos" => {
            let svg_path = icons_dir.join("tray-macos.svg");
            let tree = parse_svg(&svg_path);
            let mut rgba = render_to_rgba(&tree, 36);
            unpremultiply_rgba(&mut rgba);
            let template = luminance_to_alpha(&rgba);
            std::fs::write(out_dir.join("tray-template.rgba"), &template).unwrap();
        }
        other => println!("cargo:warning=tray icon generation not implemented for {other}"),
    }
}

fn parse_svg(svg_path: &Path) -> resvg::usvg::Tree {
    let svg_data = std::fs::read(svg_path).unwrap_or_else(|e| panic!("failed to read {}: {e}", svg_path.display()));
    resvg::usvg::Tree::from_data(&svg_data, &resvg::usvg::Options::default())
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", svg_path.display()))
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
