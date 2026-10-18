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

    if report_missing_frontend_dist() {
        return;
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

    // Generate the context here so embedded assets are written before any unit
    // that reads them starts; `xtask::tauri_context_conformance_tests` says why
    // the macro must not.
    let attributes = tauri_build::Attributes::new().codegen(tauri_build::CodegenContext::new());
    tauri_build::try_build(attributes).unwrap_or_else(|e| panic!("tauri-build failed: {e:#}"));
}

/// Fail the build, naming the remedy, when it must embed `ui/dist` and the
/// directory is absent. Returns whether it did.
///
/// The decision is made over the config `tauri-build` reads: its own loader
/// for the target being built, then `TAURI_CONFIG` merged over it.
fn report_missing_frontend_dist() -> bool {
    let config_dir = std::env::current_dir().expect("failed to read the current directory");
    let target = tauri_utils::platform::Target::from_triple(
        &std::env::var("TARGET").expect("cargo sets TARGET for build scripts"),
    );
    let (config, _paths) = tauri_utils::config::parse::read_from(target, &config_dir)
        .unwrap_or_else(|e| panic!("failed to read the Tauri config: {e}"));
    let tauri_config = std::env::var("TAURI_CONFIG").ok();
    let missing = xtask_lib::frontend_dist::missing_frontend_dist(
        tauri_build::is_dev(),
        config,
        tauri_config.as_deref(),
        &config_dir,
        |dir| dir.exists(),
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let Some(dir) = missing else { return false };
    println!(
        "cargo::error=`frontendDist` {} does not exist. Production mode embeds the frontend: run \
         `cargo xtask build frontend-build`, or create an empty `ui/dist` (gitignored) for checks that \
         do not run the GUI, or build with `--no-default-features`",
        dir.display()
    );
    true
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("failed to stat {}: {e}", path.display()))
}

/// Publish `path` with `bytes`, dated as old as `inputs`.
///
/// `tauri-build` watches the icons and sidecar stubs it embeds, and cargo dates
/// a build-script run from its start, so a file this script writes would stale
/// `hole` on the next command unless it is dated by its inputs. The files must
/// stay at the paths `tauri.conf.json` names, so they cannot be written
/// elsewhere first. The file is written and dated under a temporary name, then
/// renamed into place: a concurrent reader (another build of this worktree, or
/// `tauri-build` in it) sees a whole file, and the watched path never carries a
/// fresh mtime.
fn write_dated(path: &Path, bytes: &[u8], inputs: SystemTime) {
    let temp = write_temp(path, bytes, inputs);
    std::fs::rename(&temp, path).unwrap_or_else(|e| panic!("failed to replace {}: {e}", path.display()));
}

/// Like [`write_dated`], but only if `path` does not exist, and without ever
/// overwriting it: whoever created it first (`cargo xtask deps`, a concurrent
/// build) keeps it and its mtime. Returns whether it created `path`.
fn create_dated(path: &Path, bytes: &[u8], inputs: SystemTime) -> bool {
    let temp = write_temp(path, bytes, inputs);
    let linked = std::fs::hard_link(&temp, path);
    std::fs::remove_file(&temp).unwrap_or_else(|e| panic!("failed to remove {}: {e}", temp.display()));
    match linked {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => panic!("failed to create {}: {e}", path.display()),
    }
}

/// A complete, dated copy of the file `path` will become, beside it. Named by
/// process, so two builds never share one.
fn write_temp(path: &Path, bytes: &[u8], inputs: SystemTime) -> PathBuf {
    use std::io::Write;
    let name = path
        .file_name()
        .expect("published path has a file name")
        .to_string_lossy();
    let temp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::File::create(&temp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.set_modified(inputs)
        })
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", temp.display()));
    temp
}

fn tauri_conf() -> serde_json::Value {
    let conf = std::fs::read_to_string("tauri.conf.json").expect("failed to read tauri.conf.json");
    serde_json::from_str(&conf).expect("failed to parse tauri.conf.json")
}

/// The files `tauri.conf.json`'s `bundle.icon` lists, as paths from the crate
/// directory (the config's directory, where `tauri-build` resolves them).
fn bundle_icons() -> Vec<PathBuf> {
    tauri_conf()["bundle"]["icon"]
        .as_array()
        .expect("tauri.conf.json bundle.icon must be an array")
        .iter()
        .map(|icon| PathBuf::from(icon.as_str().expect("icon entry must be a string")))
        .collect()
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
    let conf = tauri_conf();
    let entries = conf["bundle"]["externalBin"]
        .as_array()
        .expect("tauri.conf.json bundle.externalBin must be an array");
    for entry in entries {
        let base = entry.as_str().expect("externalBin entry must be a string");
        let path = repo_root.join(format!("{base}-{target}{suffix}"));
        std::fs::create_dir_all(path.parent().unwrap()).expect("failed to create sidecar cache dir");
        if create_dated(&path, &[], mtime(Path::new("tauri.conf.json"))) {
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
    // Rerun triggers (HEAD, its branch ref, tags, packed-refs); the version
    // computation lives in xtask-lib so it's testable and shared with `cargo xtask
    // version` (which the prek hook + release CI workflow use). See
    // xtask-lib/src/version.rs and git_rerun.rs.
    xtask_lib::git_rerun::emit_rerun_if_changed(repo_root);

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

    let mut generated: Vec<&str> = Vec::new();
    let mut publish = |name: &'static str, bytes: &[u8]| {
        write_dated(&cache_icons_dir.join(name), bytes, svgs_mtime);
        generated.push(name);
    };

    publish("icon.ico", &ico_bytes(&win_tree));

    // ICNS: same bytes to the bundled .cache copy (tauri.conf.json) and a
    // cargo-isolated OUT_DIR copy. The test reads the OUT_DIR copy.
    let icns = build_icns_bytes(&mac_tree);
    publish("icon.icns", &icns);
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
    publish("32x32.png", &render_png_in_memory(host_tree, 32));
    publish("128x128.png", &render_png_in_memory(host_tree, 128));

    // `tauri-build` watches every file `tauri.conf.json`'s `bundle.icon` lists,
    // so one this script does not write (and so does not date) would stale
    // `hole` on every command. An entry outside the cache is a committed file
    // this script does not own.
    let cache = cache_icons_dir.canonicalize().expect("failed to resolve .cache/icons/");
    for icon in bundle_icons() {
        let icon = icon
            .canonicalize()
            .unwrap_or_else(|e| panic!("bundle.icon entry {} is not on disk: {e}", icon.display()));
        if let Ok(name) = icon.strip_prefix(&cache) {
            assert!(
                generated.iter().any(|g| Path::new(g) == name),
                "bundle.icon lists {}, which build.rs does not generate: write it with `publish` so it is dated",
                icon.display()
            );
        }
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

fn ico_bytes(tree: &resvg::usvg::Tree) -> Vec<u8> {
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 32, 256] {
        let rgba = render_to_rgba(tree, size);
        let image = ico::IconImage::from_rgba_data(size, size, rgba);
        icon_dir.add_entry(ico::IconDirEntry::encode(&image).unwrap());
    }
    let mut bytes = Vec::new();
    icon_dir.write(&mut bytes).unwrap();
    bytes
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
