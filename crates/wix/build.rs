use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use log::{debug, info, warn};
use serde::Deserialize;

// Toolchain config =====

#[derive(Deserialize)]
struct WixToolchain {
    version: String,
    url: String,
    sha256: String,
}

// Main =====

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env("CARGO_WIX_LOG")
        .init();

    println!("cargo:rerun-if-changed=wix-toolchain.toml");

    let tc: WixToolchain =
        toml::from_str(include_str!("wix-toolchain.toml")).expect("failed to parse wix-toolchain.toml");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let wix_zip_path = out_dir.join("wix-bundle.zip");

    // Check if the zip already exists and matches the expected version
    let sentinel_path = out_dir.join("wix-bundle.version");
    if wix_zip_path.exists() && sentinel_path.exists() {
        let stored_version = std::fs::read_to_string(&sentinel_path).unwrap_or_default();
        if stored_version.trim() == tc.version {
            debug!("WiX bundle already cached in OUT_DIR, skipping");
            return;
        }
    }

    // Cache downloaded MSI in .cache/wix/ (project convention)
    let repo_root = git_repo_root();
    let cache_dir = repo_root.join(".cache").join("wix");
    std::fs::create_dir_all(&cache_dir).expect("failed to create .cache/wix/");

    let msi_cache_path = cache_dir.join(format!("wix-cli-x64-v{}.msi", tc.version));
    let msi_data = load_or_download_msi(&tc, &msi_cache_path, &cache_dir);

    // Determine target architecture for filtering
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
    let arch_filter = match target_arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x86",
        other => {
            warn!("Unknown target arch '{other}', defaulting to x64");
            "x64"
        }
    };
    info!("Target arch: {target_arch} -> WiX arch filter: {arch_filter}");

    // Open MSI and extract files via embedded CAB
    info!("Extracting files from MSI...");
    let files = extract_files_from_msi(&msi_data, arch_filter);
    info!("Extracted {} files from MSI", files.len());

    // Repack extracted files into a zip
    let zip_data = create_zip(&files);
    std::fs::write(&wix_zip_path, &zip_data).expect("failed to write wix-bundle.zip");
    std::fs::write(&sentinel_path, &tc.version).expect("failed to write version sentinel");
    println!(
        "cargo:warning=WiX v{} bundle: {} files, {:.1} MB (arch: {arch_filter})",
        tc.version,
        files.len(),
        zip_data.len() as f64 / 1024.0 / 1024.0,
    );
}

// Helpers =====

fn git_repo_root() -> PathBuf {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("failed to run git");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn load_or_download_msi(tc: &WixToolchain, msi_cache_path: &Path, cache_dir: &Path) -> Vec<u8> {
    let hash_sentinel = cache_dir.join(format!(
        "{}.verified",
        msi_cache_path.file_name().unwrap().to_string_lossy()
    ));

    if msi_cache_path.exists() && hash_sentinel.exists() {
        let stored_hash = std::fs::read_to_string(&hash_sentinel).unwrap_or_default();
        if stored_hash.trim() == tc.sha256 {
            info!("Using cached WiX MSI: {}", msi_cache_path.display());
            return std::fs::read(msi_cache_path).expect("failed to read cached MSI");
        }
    }

    info!("Downloading WiX v{} from {}...", tc.version, tc.url);
    let response = ureq::get(&tc.url).call().expect("failed to download WiX MSI");
    let msi_data = response
        .into_body()
        .with_config()
        .limit(50 * 1024 * 1024)
        .read_to_vec()
        .expect("failed to read WiX MSI response");

    let actual_hash = sha256_hex(&msi_data);
    assert_eq!(
        actual_hash, tc.sha256,
        "WiX MSI SHA256 mismatch: expected {}, got {actual_hash}",
        tc.sha256
    );

    std::fs::write(msi_cache_path, &msi_data).expect("failed to write MSI to cache");
    std::fs::write(&hash_sentinel, &tc.sha256).expect("failed to write hash sentinel");
    info!("WiX MSI cached at {}", msi_cache_path.display());

    msi_data
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// MSI extraction =====

/// Build a directory path from the Directory table by walking parent references.
fn resolve_dir_path(dir_key: &str, dir_parent: &HashMap<String, String>, dir_name: &HashMap<String, String>) -> String {
    const MAX_DEPTH: usize = 64;
    let mut parts = Vec::new();
    let mut current = dir_key.to_string();

    for _ in 0..MAX_DEPTH {
        let name = dir_name.get(&current).cloned().unwrap_or_default();
        if name.is_empty()
            || current == "TARGETDIR"
            || current == "ProgramFilesFolder"
            || current == "ProgramFiles64Folder"
        {
            break;
        }
        parts.push(name);
        match dir_parent.get(&current) {
            Some(parent) if !parent.is_empty() && parent != &current => {
                current = parent.clone();
            }
            _ => break,
        }
    }

    parts.reverse();
    parts.join("/")
}

/// Extract files from an MSI, filtering to the specified architecture.
///
/// Architecture-specific directories in the MSI:
/// - `bin/x64/` — x64-specific .NET assemblies and native helpers
/// - `bin/x86/` — x86-specific
/// - `bin/arm64/` — arm64-specific
/// - `bin/` — shared files (wix.exe, .NET Framework assemblies)
///
/// We include `bin/<target_arch>/` and `bin/` (shared), and exclude other archs.
fn extract_files_from_msi(msi_data: &[u8], arch_filter: &str) -> Vec<(String, Vec<u8>)> {
    let cursor = Cursor::new(msi_data);
    let mut package = msi::Package::open(cursor).expect("failed to open MSI package");

    // Arch directories to EXCLUDE
    let all_arches = ["x64", "x86", "arm64"];
    let excluded_arches: Vec<&str> = all_arches.iter().filter(|a| **a != arch_filter).copied().collect();

    // Read Directory table
    let mut dir_parent: HashMap<String, String> = HashMap::new();
    let mut dir_name: HashMap<String, String> = HashMap::new();
    {
        let query = msi::Select::table("Directory");
        let rows = package.select_rows(query).expect("failed to query Directory table");
        for row in rows {
            let key = value_to_string(&row["Directory"]);
            let parent = value_to_string(&row["Directory_Parent"]);
            let default_dir = value_to_string(&row["DefaultDir"]);
            let long_name = default_dir.split('|').next_back().unwrap_or(&default_dir).to_string();
            let long_name = if long_name == "." { String::new() } else { long_name };
            dir_parent.insert(key.clone(), parent);
            dir_name.insert(key, long_name);
        }
    }

    // Read Component table
    let mut component_dir: HashMap<String, String> = HashMap::new();
    {
        let query = msi::Select::table("Component");
        let rows = package.select_rows(query).expect("failed to query Component table");
        for row in rows {
            let comp = value_to_string(&row["Component"]);
            let dir = value_to_string(&row["Directory_"]);
            component_dir.insert(comp, dir);
        }
    }

    // Read File table
    struct FileInfo {
        name: String,
        component: String,
    }
    let mut file_key_to_info: HashMap<String, FileInfo> = HashMap::new();
    {
        let query = msi::Select::table("File");
        let rows = package.select_rows(query).expect("failed to query File table");
        for row in rows {
            let key = value_to_string(&row["File"]);
            let component = value_to_string(&row["Component_"]);
            let filename = value_to_string(&row["FileName"]);
            let long_name = filename.split('|').next_back().unwrap_or(&filename).to_string();
            file_key_to_info.insert(
                key,
                FileInfo {
                    name: long_name,
                    component,
                },
            );
        }
    }

    debug!(
        "File table: {} entries, Directory: {}, Component: {}",
        file_key_to_info.len(),
        dir_name.len(),
        component_dir.len()
    );

    // Build file key -> relative path mapping, filtering by architecture
    let mut file_key_to_path: HashMap<String, String> = HashMap::new();
    let mut skipped = 0usize;
    for (key, info) in &file_key_to_info {
        let dir_key = component_dir.get(&info.component).cloned().unwrap_or_default();
        let dir_path = resolve_dir_path(&dir_key, &dir_parent, &dir_name);
        let full_path = if dir_path.is_empty() {
            info.name.clone()
        } else {
            format!("{}/{}", dir_path, info.name)
        };

        // Filter out other architectures
        let dominated_by_other_arch = excluded_arches
            .iter()
            .any(|arch| full_path.contains(&format!("/{arch}/")) || full_path.contains(&format!("\\{arch}\\")));
        if dominated_by_other_arch {
            debug!("Skipping (wrong arch): {full_path}");
            skipped += 1;
            continue;
        }

        file_key_to_path.insert(key.clone(), full_path);
    }

    info!(
        "Included {} files, skipped {} (other archs)",
        file_key_to_path.len(),
        skipped
    );

    // Extract from embedded CAB streams
    let mut extracted = Vec::new();
    let stream_names: Vec<String> = package.streams().map(|s| s.to_string()).collect();

    for stream_name in &stream_names {
        let mut stream_data = Vec::new();
        if let Ok(mut reader) = package.read_stream(stream_name) {
            reader.read_to_end(&mut stream_data).expect("failed to read stream");
        } else {
            continue;
        }

        let Ok(mut cabinet) = cab::Cabinet::new(Cursor::new(&stream_data)) else {
            continue;
        };

        let file_names: Vec<String> = cabinet
            .folder_entries()
            .flat_map(|folder| folder.file_entries().map(|f| f.name().to_string()))
            .collect();

        debug!("CAB '{}': {} files", stream_name, file_names.len());

        for cab_file_name in &file_names {
            // Skip files not in our arch-filtered set
            let Some(relative_path) = file_key_to_path.get(cab_file_name.as_str()) else {
                continue;
            };

            let mut file_data = Vec::new();
            if let Ok(mut reader) = cabinet.read_file(cab_file_name) {
                reader
                    .read_to_end(&mut file_data)
                    .expect("failed to read file from CAB");
                extracted.push((relative_path.clone(), file_data));
            }
        }
    }

    if extracted.is_empty() {
        panic!("No files extracted from MSI. Streams: {stream_names:?}");
    }

    extracted
}

fn value_to_string(value: &msi::Value) -> String {
    match value {
        msi::Value::Str(s) => s.clone(),
        msi::Value::Int(i) => i.to_string(),
        msi::Value::Null => String::new(),
        _ => format!("{value:?}"),
    }
}

// Zip creation =====

fn create_zip(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, data) in files {
            zip.start_file(name, options)
                .unwrap_or_else(|e| panic!("failed to start zip entry '{name}': {e}"));
            zip.write_all(data)
                .unwrap_or_else(|e| panic!("failed to write zip entry '{name}': {e}"));
        }

        zip.finish().expect("failed to finalize zip");
    }
    buf
}
