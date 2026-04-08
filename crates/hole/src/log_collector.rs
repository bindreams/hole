// Collect GUI and bridge logs into a zip archive.

use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Locate all log directories to include in the archive.
///
/// The user-local log dir holds both GUI and foreground-bridge logs.
/// Service-mode bridge logs live in system paths and are included when present.
fn log_dirs() -> Vec<(&'static str, PathBuf)> {
    #[cfg(target_os = "windows")]
    let service_dir = PathBuf::from(r"C:\ProgramData\hole\logs");
    #[cfg(not(target_os = "windows"))]
    let service_dir = PathBuf::from("/var/log/hole");

    vec![
        ("user", hole_common::logging::default_log_dir()),
        ("service", service_dir),
    ]
}

/// Create a zip archive containing all log files. Returns the path to the temp zip.
pub fn collect_logs_to_zip() -> Result<PathBuf, String> {
    let zip_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp directory: {e}"))?;
    let zip_path = zip_dir.keep().join("hole-logs.zip");

    let file = std::fs::File::create(&zip_path).map_err(|e| format!("Failed to create zip file: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut file_count = 0;

    for (prefix, dir) in log_dirs() {
        if !dir.exists() {
            info!(dir = %dir.display(), "log directory does not exist, skipping");
            continue;
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "failed to read log directory");
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let archive_name = format!("{prefix}/{file_name}");
            if let Err(e) = add_file_to_zip(&mut zip, &path, &archive_name, options) {
                warn!(file = %path.display(), error = %e, "failed to add log file to zip");
                continue;
            }
            file_count += 1;
        }
    }

    zip.finish().map_err(|e| format!("Failed to finalize zip: {e}"))?;

    if file_count == 0 {
        return Err("No log files found".to_string());
    }

    info!(count = file_count, path = %zip_path.display(), "collected log files");
    Ok(zip_path)
}

fn add_file_to_zip(
    zip: &mut zip::ZipWriter<std::fs::File>,
    path: &Path,
    archive_name: &str,
    options: zip::write::SimpleFileOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    zip.start_file(archive_name, options)?;
    zip.write_all(&data)?;
    Ok(())
}
