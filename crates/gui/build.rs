use std::path::{Path, PathBuf};

fn main() {
    let icons_dir = Path::new("icons");
    let svg_path = icons_dir.join("icon.svg");

    println!("cargo:rerun-if-changed={}", svg_path.display());

    let repo_root = git_repo_root();
    let cache_dir = repo_root.join(".cache").join("gui");
    let cache_icons_dir = cache_dir.join("icons");
    std::fs::create_dir_all(&cache_icons_dir).expect("failed to create .cache/gui/icons/");

    emit_version_env(&repo_root);
    generate_icons(&svg_path, &cache_icons_dir);
    generate_tray_icons(icons_dir);
    build_v2ray_plugin(&repo_root, &cache_dir);

    #[cfg(target_os = "windows")]
    download_wintun(&cache_dir);

    tauri_build::build();
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

    // Rerun triggers: branch ref changes, tag changes, packed-refs.
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(refpath) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(refpath).display());
        }
    }
    println!("cargo:rerun-if-changed={}", git_dir.join("refs").join("tags").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());

    let version = match compute_git_version(repo_root) {
        Ok(v) => v,
        Err(msg) => {
            println!("cargo:warning=failed to compute git version: {msg}");
            "0.0.0-unknown".to_string()
        }
    };

    println!("cargo:rustc-env=HOLE_VERSION={version}");
}

fn compute_git_version(repo_root: &Path) -> Result<String, String> {
    // git describe --tags --match "v[0-9]*.[0-9]*.[0-9]*" --long
    // Output format: <tag>-<distance>-g<short-hash>
    let output = std::process::Command::new("git")
        .args(["describe", "--tags", "--match", "v[0-9]*.[0-9]*.[0-9]*", "--long"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("git describe: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "git describe exited {}: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let desc = String::from_utf8(output.stdout).map_err(|e| format!("git describe output not utf-8: {e}"))?;
    let desc = desc.trim();

    // Parse --long format by splitting from the right on '-'.
    // Safe because we validate the tag contains no hyphens below.
    let parts: Vec<&str> = desc.rsplitn(3, '-').collect();
    if parts.len() != 3 {
        return Err(format!("unexpected git describe output: {desc}"));
    }
    let tag = parts[2];
    let distance: u64 = parts[1].parse().map_err(|e| format!("bad distance in '{desc}': {e}"))?;

    // Validate strict vMAJOR.MINOR.PATCH (no pre-release/build suffixes).
    let semver = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("tag '{tag}' missing 'v' prefix"))?;
    let parsed = semver::Version::parse(semver).map_err(|e| format!("tag '{tag}' is not valid semver: {e}"))?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(format!(
            "tag '{tag}' must be strict vMAJOR.MINOR.PATCH (no pre-release/build)"
        ));
    }

    let mut version = semver.to_string();

    if distance > 0 {
        // Get full commit hash for the snapshot suffix.
        let hash_output = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo_root)
            .output()
            .map_err(|e| format!("git rev-parse HEAD: {e}"))?;
        let full_hash =
            String::from_utf8(hash_output.stdout).map_err(|e| format!("git rev-parse output not utf-8: {e}"))?;
        version = format!("{version}-snapshot+git.{}", full_hash.trim());
    }

    // Check if worktree is dirty (tracked files only; untracked files are ignored,
    // matching `git describe --dirty` behavior).
    let dirty = std::process::Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(repo_root)
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    if dirty {
        version.push_str(".dirty");
    }

    Ok(version)
}

// v2ray-plugin build ==================================================================================================

fn v2ray_plugin_output_name() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-pc-windows-msvc.exe"
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-apple-darwin"
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-apple-darwin"
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
    )))]
    compile_error!("unsupported platform for v2ray-plugin sidecar")
}

fn build_v2ray_plugin(repo_root: &Path, cache_dir: &Path) {
    let source_dir = repo_root.join("external").join("v2ray-plugin");
    let output_dir = cache_dir.join("v2ray-plugin");
    let output_name = v2ray_plugin_output_name();
    let output_path = output_dir.join(output_name);

    // No rerun-if-changed for the source dir: cargo's directory tracking only
    // detects top-level file additions/removals, not modifications inside.
    // Go's own build cache makes repeated builds fast (~instant if unchanged).

    std::fs::create_dir_all(&output_dir).expect("failed to create cache/v2ray-plugin/");

    let status = std::process::Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&output_path)
        .arg(".")
        .current_dir(&source_dir)
        .env("CGO_ENABLED", "0")
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("go build failed with exit code {}", s.code().unwrap_or(-1)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!("Go toolchain not found. Install from https://go.dev/dl/");
        }
        Err(e) => panic!("failed to run go build: {e}"),
    }
}

// wintun download =====================================================================================================

#[cfg(target_os = "windows")]
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
#[cfg(target_os = "windows")]
const WINTUN_ZIP_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

#[cfg(target_os = "windows")]
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex_encode(&hash)
}

#[cfg(target_os = "windows")]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(target_os = "windows")]
fn download_wintun(cache_dir: &Path) {
    let wintun_dir = cache_dir.join("wintun");
    let dll_path = wintun_dir.join("wintun.dll");

    std::fs::create_dir_all(&wintun_dir).expect("failed to create cache/wintun/");

    // Check cache: verify the hash sentinel written after a successful download
    let hash_sentinel = wintun_dir.join("wintun.dll.verified");
    if dll_path.exists() && hash_sentinel.exists() {
        let stored_hash = std::fs::read_to_string(&hash_sentinel).unwrap_or_default();
        if stored_hash.trim() == WINTUN_ZIP_SHA256 {
            return;
        }
        // Hash mismatch — stale cache from a different version, re-download
    }

    // Download and verify
    eprintln!("Downloading wintun.dll from {WINTUN_URL}...");
    let response = ureq::get(WINTUN_URL).call().expect("failed to download wintun zip");

    let zip_data = response
        .into_body()
        .read_to_vec()
        .expect("failed to read wintun zip response");

    let actual_hash = sha256_hex(&zip_data);
    assert_eq!(
        actual_hash, WINTUN_ZIP_SHA256,
        "wintun.zip hash mismatch: expected {WINTUN_ZIP_SHA256}, got {actual_hash}"
    );

    // Extract wintun.dll from zip
    let cursor = std::io::Cursor::new(&zip_data);
    let mut archive = zip::ZipArchive::new(cursor).expect("failed to open wintun zip");

    let mut dll_file = archive
        .by_name("wintun/bin/amd64/wintun.dll")
        .expect("wintun.dll not found in zip archive");

    let mut dll_data = Vec::new();
    std::io::Read::read_to_end(&mut dll_file, &mut dll_data).expect("failed to read wintun.dll from zip");

    std::fs::write(&dll_path, &dll_data).expect("failed to write wintun.dll to cache");
    std::fs::write(&hash_sentinel, WINTUN_ZIP_SHA256).expect("failed to write hash sentinel");
    eprintln!("wintun.dll downloaded and verified ({} bytes)", dll_data.len());
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
            other => eprintln!("cargo:warning=tray icon generation not implemented for {other}"),
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
