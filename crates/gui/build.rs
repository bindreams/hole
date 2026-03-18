use std::path::{Path, PathBuf};

fn main() {
    let icons_dir = Path::new("icons");
    let svg_path = icons_dir.join("icon.svg");

    println!("cargo:rerun-if-changed={}", svg_path.display());

    let repo_root = git_repo_root();

    generate_icons(&svg_path, icons_dir);
    build_v2ray_plugin(&repo_root);

    #[cfg(target_os = "windows")]
    download_wintun(&repo_root);

    tauri_build::build();
}

// Repo root =====

fn git_repo_root() -> PathBuf {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("failed to run `git rev-parse --show-toplevel` — is git installed?");

    assert!(output.status.success(), "git rev-parse --show-toplevel failed");

    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

// v2ray-plugin build =====

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

fn build_v2ray_plugin(repo_root: &Path) {
    let source_dir = repo_root.join("external").join("v2ray-plugin");
    let cache_dir = repo_root.join(".cache").join("v2ray-plugin");
    let output_name = v2ray_plugin_output_name();
    let cache_path = cache_dir.join(output_name);
    let binaries_dir = Path::new("binaries");
    let final_path = binaries_dir.join(output_name);

    // No rerun-if-changed for the source dir: cargo's directory tracking only
    // detects top-level file additions/removals, not modifications inside.
    // Go's own build cache makes repeated builds fast (~instant if unchanged).

    std::fs::create_dir_all(&cache_dir).expect("failed to create .cache/v2ray-plugin/");
    std::fs::create_dir_all(binaries_dir).expect("failed to create binaries/");

    // Run go build (Go caches internally, so this is fast on repeat builds)
    let status = std::process::Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&cache_path)
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

    // Copy to Tauri's expected sidecar location
    std::fs::copy(&cache_path, &final_path).expect("failed to copy v2ray-plugin to binaries/");
}

// wintun download =====

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
fn download_wintun(repo_root: &Path) {
    let cache_dir = repo_root.join(".cache").join("wintun");
    let cache_path = cache_dir.join("wintun.dll");
    let binaries_dir = Path::new("binaries");
    let final_path = binaries_dir.join("wintun.dll");

    std::fs::create_dir_all(&cache_dir).expect("failed to create .cache/wintun/");
    std::fs::create_dir_all(binaries_dir).expect("failed to create binaries/");

    // Check cache: verify the hash sentinel written after a successful download
    let hash_sentinel = cache_dir.join("wintun.dll.verified");
    if cache_path.exists() && hash_sentinel.exists() {
        let stored_hash = std::fs::read_to_string(&hash_sentinel).unwrap_or_default();
        if stored_hash.trim() == WINTUN_ZIP_SHA256 {
            std::fs::copy(&cache_path, &final_path).expect("failed to copy wintun.dll to binaries/");
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

    std::fs::write(&cache_path, &dll_data).expect("failed to write wintun.dll to cache");
    std::fs::write(&hash_sentinel, WINTUN_ZIP_SHA256).expect("failed to write hash sentinel");
    std::fs::copy(&cache_path, &final_path).expect("failed to copy wintun.dll to binaries/");
    eprintln!("wintun.dll downloaded and verified ({} bytes)", dll_data.len());
}

// Icons =====

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

    // Generate ICNS placeholder (Tauri expects it but only uses on macOS)
    let icns_path = out_dir.join("icon.icns");
    if !icns_path.exists() {
        // Write a minimal valid ICNS with the 128x128 PNG embedded
        let png_data = std::fs::read(out_dir.join("128x128.png")).unwrap();
        write_icns(&icns_path, &png_data);
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
