#![allow(clippy::disallowed_methods)] // dev tooling, never privileged
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn main() {
    let icons_dir = Path::new("icons");

    // Rerun on any SVG change in icons/, not just the ones the active
    // target reads. Designers iterating across platforms (or hosts
    // toggling target_os via incremental builds) shouldn't get stale
    // outputs. Watching the directory mtime catches additions/removals
    // that don't touch existing files.
    println!("cargo:rerun-if-changed={}", icons_dir.display());
    let mut svgs_mtime = SystemTime::UNIX_EPOCH;
    for entry in std::fs::read_dir(icons_dir).expect("failed to read icons dir") {
        let path = entry
            .unwrap_or_else(|e| panic!("failed to read entry in {}: {e}", icons_dir.display()))
            .path();
        if path.extension().and_then(|e| e.to_str()) == Some("svg") {
            println!("cargo:rerun-if-changed={}", path.display());
            svgs_mtime = svgs_mtime.max(mtime(&path));
        }
    }

    let repo_root = git_repo_root();
    let cache_icons_dir = repo_root.join(".cache").join("icons");
    std::fs::create_dir_all(&cache_icons_dir).expect("failed to create .cache/icons/");

    emit_version_env(&repo_root);
    generate_icons(icons_dir, &cache_icons_dir, svgs_mtime);
    generate_tray_icons(icons_dir);

    // Runtime asset acquisition (ex-ray Go build, wintun.dll download)
    // lives in `cargo xtask deps`, not here — this build.rs is
    // compile-time metadata only.

    println!("cargo:rerun-if-changed=tauri.conf.json");
    ensure_external_bin_stubs(&repo_root);

    // `codegen` generates the context here, so every embedded asset is on disk
    // before any unit that reads it starts. `tauri::generate_context!()` would
    // write them during the unit's own rustc run, which cargo dates the unit's
    // fingerprint before — a fresh `OUT_DIR` would leave it stale for the next
    // command (see `xtask::tauri_context_conformance_tests`).
    let attributes = tauri_build::Attributes::new().codegen(tauri_build::CodegenContext::new());
    // In production mode `ui/dist` must exist; tauri panics when it does not.
    // Report that as a build error that names the remedy, not a backtrace.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if missing_frontend_dist(info.payload()).is_none() {
            default_hook(info);
        }
    }));
    match std::panic::catch_unwind(|| tauri_build::try_build(attributes)) {
        Ok(result) => result.unwrap_or_else(|e| panic!("tauri-build failed: {e:#}")),
        Err(payload) => match missing_frontend_dist(&*payload) {
            Some(message) => println!(
                "cargo::error={message} (relative to {}). Production mode embeds the frontend: \
                 run `cargo xtask build frontend-build`, or create an empty `ui/dist` (gitignored) for \
                 checks that do not run the GUI, or build with `--no-default-features`",
                std::env::current_dir().unwrap().display()
            ),
            None => std::panic::resume_unwind(payload),
        },
    }
}

/// The message of tauri-codegen's panic for a `frontendDist` directory that
/// does not exist, if `payload` is that panic.
fn missing_frontend_dist(payload: &(dyn std::any::Any + Send)) -> Option<&str> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;
    (message.contains("`frontendDist`") && message.contains("doesn't exist")).then_some(message)
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("failed to stat {}: {e}", path.display()))
}

/// Date `path` as old as the newest input it derives from, `inputs`.
///
/// `tauri-build` lists the icons and sidecar stubs it embeds in
/// `rerun-if-changed`, and cargo dates a build-script run from its start. A
/// file this script creates or rewrites is newer than that, so the next cargo
/// command reruns the script, rewrites the context and recompiles `hole`. The
/// files must stay at the paths `tauri.conf.json` names (the bundler reads
/// them), and nothing else can write them before the script starts without
/// breaking a bare `cargo build -p hole`. Dated by their inputs, an edit to an
/// input still reruns the script, and the script's own output never does.
fn date_as_input(path: &Path, inputs: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(inputs))
        .unwrap_or_else(|e| panic!("failed to date {}: {e}", path.display()));
}

/// Stub every `externalBin` sidecar so `tauri_build::build()` passes
/// validation even when `cargo xtask deps` has not been run yet. The stub
/// list derives from `tauri.conf.json`'s `bundle.externalBin`, so a new
/// sidecar entry can never desync from its stub. Each entry `<base>` resolves
/// to `<repo>/<base>-<target>{suffix}`, mirroring what Tauri's bundler reads.
/// The real binaries are built by `cargo xtask deps`.
fn ensure_external_bin_stubs(repo_root: &Path) {
    let target = std::env::var("TARGET").unwrap();
    let suffix = if target.contains("windows") { ".exe" } else { "" };
    let conf = std::fs::read_to_string("tauri.conf.json").expect("failed to read tauri.conf.json");
    let conf: serde_json::Value = serde_json::from_str(&conf).expect("failed to parse tauri.conf.json");
    let entries = conf["bundle"]["externalBin"]
        .as_array()
        .expect("tauri.conf.json bundle.externalBin must be an array");
    for entry in entries {
        let base = entry.as_str().expect("externalBin entry must be a string");
        let path = repo_root.join(format!("{base}-{target}{suffix}"));
        if !path.exists() {
            std::fs::create_dir_all(path.parent().unwrap()).expect("failed to create sidecar cache dir");
            std::fs::File::create(&path).expect("failed to create sidecar stub");
            date_as_input(&path, mtime(Path::new("tauri.conf.json")));
            println!("cargo:warning=created empty {base} stub — run `cargo xtask deps` for a real build");
        }
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
    // workflow use). See xtask-lib/src/version.rs.
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(refpath) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(refpath).display());
        }
    }
    println!("cargo:rerun-if-changed={}", git_dir.join("refs").join("tags").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());

    let version = xtask_lib::version::display_version(repo_root, xtask_lib::version::Group::Hole);
    println!("cargo:rustc-env=HOLE_VERSION={version}");
}

// Icons ===============================================================================================================

/// Render size (px) of the runtime Dock icon PNG (`dock_icon.rs`).
const APP_ICON_PX: u32 = 512;

const ICNS_ENTRIES: &[(u32, icns::IconType)] = &[
    (16, icns::IconType::RGBA32_16x16),
    (32, icns::IconType::RGBA32_32x32),
    (64, icns::IconType::RGBA32_32x32_2x),
    (128, icns::IconType::RGBA32_128x128),
    (256, icns::IconType::RGBA32_256x256),
    (512, icns::IconType::RGBA32_512x512),
    (1024, icns::IconType::RGBA32_512x512_2x),
];

/// Encode a multi-resolution ICNS from the macOS app SVG.
fn build_icns_bytes(tree: &resvg::usvg::Tree) -> Vec<u8> {
    use std::io::Cursor;
    let mut family = icns::IconFamily::new();
    for &(size, icon_type) in ICNS_ENTRIES {
        let png = render_png_in_memory(tree, size);
        let image = icns::Image::read_png(Cursor::new(png)).expect("re-decode rendered PNG");
        family
            .add_icon_with_type(&image, icon_type)
            .unwrap_or_else(|e| panic!("add {icon_type:?} to icns: {e}"));
    }
    let mut bytes = Vec::new();
    family.write(&mut bytes).expect("encode icns");
    bytes
}

fn generate_icons(icons_dir: &Path, cache_icons_dir: &Path, svgs_mtime: SystemTime) {
    // Always produce platform-correct ICO and ICNS regardless of host.
    // ICO is consumed by Windows bundles, ICNS by macOS. Reading the
    // wrong SVG into either would silently ship the wrong design on a
    // cross-bundle (e.g. `tauri build` targeting macOS from a Windows
    // host). Tauri's manifest references both files unconditionally —
    // the tauri_build validation step needs them present on every host.
    let win_tree = parse_svg(&icons_dir.join("icon-windows.svg"));
    let mac_tree = parse_svg(&icons_dir.join("icon-macos.svg"));

    render_ico(&win_tree, &cache_icons_dir.join("icon.ico"));

    // ICNS: same bytes to the bundled .cache copy (tauri.conf.json) and a
    // cargo-isolated OUT_DIR copy. The test reads the OUT_DIR copy — .cache is a
    // repo-root shared path a concurrent build could write mid-read.
    let icns = build_icns_bytes(&mac_tree);
    std::fs::write(cache_icons_dir.join("icon.icns"), &icns).unwrap();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let icns_out = out_dir.join("icon.icns");
    std::fs::write(&icns_out, &icns).unwrap();
    println!("cargo:rustc-env=HOLE_ICNS_PATH={}", icns_out.display());

    // Runtime Dock icon (dock_icon.rs).
    render_png(&mac_tree, APP_ICON_PX, &out_dir.join("app-icon.png"));

    // PNG fallbacks (referenced unconditionally by tauri.conf.json,
    // used as window icon on the host platform). Render from the
    // host's SVG so a host-resident GUI window shows the right design.
    let host_tree = match std::env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => &win_tree,
        "macos" => &mac_tree,
        other => panic!("app icon not provided for target_os={other}"),
    };
    for size in [32u32, 128] {
        render_png(host_tree, size, &cache_icons_dir.join(format!("{size}x{size}.png")));
    }

    // The files `tauri.conf.json`'s `bundle.icon` lists; `tauri-build` watches them.
    for name in ["icon.ico", "icon.icns", "32x32.png", "128x128.png"] {
        date_as_input(&cache_icons_dir.join(name), svgs_mtime);
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
    for pixel in rgba.as_chunks_mut::<4>().0 {
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
    for (dst, src) in out.as_chunks_mut::<4>().0.iter_mut().zip(rgba.as_chunks::<4>().0) {
        let r = src[0] as u32;
        let g = src[1] as u32;
        let b = src[2] as u32;
        let a = src[3] as u32;
        let lum = (r * 77 + g * 150 + b * 29) >> 8;
        dst[3] = ((lum * a + 127) / 255) as u8;
    }
    out
}
