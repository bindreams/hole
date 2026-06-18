//! Root-trusted validation of the macOS `.app` swap target. The cutover's
//! `RENAME_SWAP` exchanges the destination bundle's directory entry and then
//! deletes the swapped-out original, so a caller-supplied `app_dest` is a
//! root-level destroy/replace primitive. The unprivileged GUI is the attacker in
//! the bridge's trust model: its `current_exe`-derived path is a HINT, never a
//! trust anchor. The bridge validates that the bundle already present at
//! `app_dest` is genuinely Hole (`CFBundleIdentifier == com.hole.app`) before
//! swapping onto it.

use std::path::{Path, PathBuf};

/// The bundle identity the swap target must already carry to be trusted.
const HOLE_BUNDLE_ID: &str = "com.hole.app";

/// Randomized App Translocation root: a quarantined/relocated copy runs from
/// here, never the canonical install. A swap target under it is a tell of an
/// attacker-staged copy, not the real `/Applications` bundle.
const TRANSLOCATION_PREFIX: &str = "/private/var/folders/";

/// Derive the `.app` bundle root from the GUI's `current_exe`
/// (`<bundle>/Contents/MacOS/<exe>`). Pure string walk; returns `None` if `exe`
/// is not inside a `.app/Contents/MacOS/` layout.
pub fn resolve_app_dest_from_exe(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?; // <bundle>/Contents/MacOS
    let contents = macos.parent()?; // <bundle>/Contents
    let bundle = contents.parent()?; // <bundle>
    if macos.file_name()? != "MacOS" || contents.file_name()? != "Contents" {
        return None;
    }
    if bundle.extension()? != "app" {
        return None;
    }
    Some(bundle.to_path_buf())
}

/// Validate that `dest` is a genuine, canonically-installed Hole bundle safe to
/// swap onto: it exists, is a `.app`, is not an App-Translocation copy, and its
/// `Contents/Info.plist` declares `CFBundleIdentifier == com.hole.app`.
///
/// Bounded TOCTOU: the canonical install lives under `/Applications`, which is
/// admin-writable only, so a non-admin caller cannot swap the bundle for a
/// foreign one between this check and the privileged swap.
pub fn validate_app_dest(dest: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    if dest.starts_with(TRANSLOCATION_PREFIX) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("refusing an App-Translocation swap target: {dest:?}"),
        ));
    }
    if dest.extension().and_then(|e| e.to_str()) != Some("app") {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("swap target is not a `.app` bundle: {dest:?}"),
        ));
    }
    if !dest.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("swap target does not exist: {dest:?}"),
        ));
    }
    // Parse the bundle's `Info.plist` with the `plist` crate (handles both the XML
    // and binary plist forms a real `.app` can ship) — a security gate must not
    // hand-roll structured-data parsing.
    let plist_path = dest.join("Contents").join("Info.plist");
    let value = plist::Value::from_file(&plist_path).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("cannot read the swap target's Info.plist ({plist_path:?}): {e}"),
        )
    })?;
    let id = value
        .as_dictionary()
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("swap target's Info.plist has no string CFBundleIdentifier: {plist_path:?}"),
            )
        })?;
    if id != HOLE_BUNDLE_ID {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("swap target is not a Hole bundle (CFBundleIdentifier = {id:?}, expected {HOLE_BUNDLE_ID:?})"),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_dest_tests.rs"]
mod app_dest_tests;
