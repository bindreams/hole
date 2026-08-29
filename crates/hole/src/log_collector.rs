// Collect GUI and bridge logs into a zip archive.

use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Locate all log directories to include in the archive.
///
/// The user-local log dir holds both GUI and foreground-bridge logs.
/// Service-mode bridge logs live in system paths and are included when present.
fn log_dirs() -> Vec<(&'static str, PathBuf)> {
    vec![
        ("user", hole_common::logging::default_log_dir()),
        ("service", hole_common::update_marker::service_log_dir()),
    ]
}

/// Create a zip archive containing all log files. Returns the path to the temp zip.
pub fn collect_logs_to_zip() -> Result<PathBuf, String> {
    let zip_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp directory: {e}"))?;
    let zip_path = zip_dir.keep().join("hole-logs.zip");
    collect_logs_into(&log_dirs(), &zip_path)?;
    Ok(zip_path)
}

/// Entry name of the residual manifest.
const REDACTION_MANIFEST_NAME: &str = "REDACTION.txt";

/// What collection redacted, and what it could not. Asserted by
/// `redaction_manifest_names_every_residual`, not assumed.
const REDACTION_MANIFEST: &str = "Server-address redaction applied when this bundle was collected.

Configured server addresses were replaced with <server:XXXXXXXX> tokens. The
same endpoint keeps the same token across every file, so lines can still be
correlated. Three residuals:

1. Lines written before this feature shipped may still contain a server's
   resolved IP. The GUI holds hostnames; it never holds the addresses the
   bridge resolved over DoH, so it cannot recognise them.
2. A server since deleted from the configuration is not in the registry and
   was not redacted.
3. Files taken from the service log directory were scrubbed with that same
   hostname-only registry. That is where most of the pre-fix exposure is: the
   ETW `remote:`, route-command and plugin-dial lines carry the IP and never
   the hostname.
";

/// [`collect_logs_to_zip`] with the source directories and destination given,
/// so collection is testable without writing to the real log directories.
fn collect_logs_into(dirs: &[(&'static str, PathBuf)], zip_path: &Path) -> Result<(), String> {
    let file = std::fs::File::create(zip_path).map_err(|e| format!("Failed to create zip file: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut file_count = 0;

    for (prefix, dir) in dirs {
        if !dir.exists() {
            info!(dir = %dir.display(), "log directory does not exist, skipping");
            continue;
        }

        let entries = match std::fs::read_dir(dir) {
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

    if file_count == 0 {
        return Err("No log files found".to_string());
    }

    zip.start_file(REDACTION_MANIFEST_NAME, options)
        .and_then(|()| zip.write_all(REDACTION_MANIFEST.as_bytes()).map_err(Into::into))
        .map_err(|e| format!("Failed to write the redaction manifest: {e}"))?;

    zip.finish().map_err(|e| format!("Failed to finalize zip: {e}"))?;

    info!(count = file_count, path = %zip_path.display(), "collected log files");
    Ok(())
}

/// Copy one log file into the archive, redacting as it goes.
///
/// Streams line by line as **bytes**, not `String`: a relayed plugin line can
/// carry any byte, and lossy decoding would mangle it. This runs as the
/// unprivileged GUI reading its own user's files, so it crosses no privilege
/// boundary.
fn add_file_to_zip(
    zip: &mut zip::ZipWriter<std::fs::File>,
    path: &Path,
    archive_name: &str,
    options: zip::write::SimpleFileOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufRead as _;

    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    zip.start_file(archive_name, options)?;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        zip.write_all(&util::redact::redact_bytes(&line))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "log_collector_tests.rs"]
mod log_collector_tests;
