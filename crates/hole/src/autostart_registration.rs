//! Argument-only edits to an existing OS autostart registration.
//!
//! `tauri-plugin-autostart` can only rewrite a registration wholesale — from
//! `current_exe()` and with the enabled state forced on — which is unsafe for a
//! background migration. So the dashboard flag is edited in place: the registered
//! program path and the enabled state are never touched.

/// What the migration did, for logging.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Autostart was never registered; nothing to migrate.
    NoRegistration,
    /// Already carries the wanted flag.
    AlreadyCurrent,
    /// Flag rewritten.
    Rewritten,
}

/// The flags this module owns. Anything else in a registration belongs to
/// somebody else and is preserved untouched.
const DASHBOARD_FLAGS: [&str; 2] = [hole::launch::SHOW_DASHBOARD, hole::launch::NO_SHOW_DASHBOARD];

/// Byte range of `flag` in `value` as a whitespace-delimited token, including the
/// single separator before it so removal leaves no double space.
fn token_range(value: &str, flag: &str) -> Option<std::ops::Range<usize>> {
    let mut from = 0;
    while let Some(offset) = value[from..].find(flag) {
        let start = from + offset;
        let end = start + flag.len();
        let delimited = (start == 0 || value[..start].ends_with(char::is_whitespace))
            && (end == value.len() || value[end..].starts_with(char::is_whitespace));
        if delimited {
            let with_separator = value[..start]
                .char_indices()
                .next_back()
                .filter(|(_, c)| c.is_whitespace())
                .map_or(start, |(i, _)| i);
            return Some(with_separator..end);
        }
        from = end;
    }
    None
}

/// Set (or with `None`, remove) the dashboard flag in a Windows `Run` value.
///
/// Non-flag text is preserved byte-for-byte, so an unquoted path containing
/// spaces is never re-parsed — which matters because the Win32 and Rust
/// command-line parsers disagree about where such a path ends.
pub fn set_dashboard_flag_in_value(value: &str, flag: Option<&str>) -> String {
    let mut base = value.to_string();
    while let Some(range) = DASHBOARD_FLAGS.iter().find_map(|owned| token_range(&base, owned)) {
        base.replace_range(range, "");
    }
    let base = base.trim_end();
    match flag {
        Some(flag) => format!("{base} {flag}"),
        None => base.to_string(),
    }
}

/// Set (or with `None`, remove) the dashboard flag in a macOS LaunchAgent
/// `ProgramArguments` array. Element 0 is the program; every other argument this
/// module does not own is preserved, in order.
pub fn set_dashboard_flag_in_arguments(existing: &[String], flag: Option<&str>) -> Vec<String> {
    let Some(program) = existing.first() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(existing.len() + 1);
    out.push(program.clone());
    out.extend(
        existing[1..]
            .iter()
            .filter(|arg| !DASHBOARD_FLAGS.contains(&arg.as_str()))
            .cloned(),
    );
    out.extend(flag.map(str::to_string));
    out
}

/// `NoRegistration` when there was nothing to edit, `AlreadyCurrent` when the
/// edit was a no-op, else `Rewritten`. Shared so both arms report identically.
pub fn classify<T: PartialEq>(before: Option<&T>, after: &T) -> Outcome {
    match before {
        None => Outcome::NoRegistration,
        Some(before) if before == after => Outcome::AlreadyCurrent,
        Some(_) => Outcome::Rewritten,
    }
}

/// Set the dashboard `flag` on an existing autostart registration, preserving
/// the registered program and the enabled state.
#[cfg(target_os = "windows")]
pub fn migrate(app_name: &str, flag: &str) -> std::io::Result<Outcome> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = match hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE) {
        Ok(run) => run,
        // No Run key at all is the same state as no value under it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::NoRegistration),
        Err(e) => return Err(e),
    };
    let current = match run.get_value::<String, _>(app_name) {
        Ok(current) => Some(current),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            // Present but not a string: a foreign or corrupted write. Nothing of
            // ours to edit, but loud enough to tell apart from plain absence.
            tracing::warn!(error = %e, "autostart Run value is not readable as a string");
            None
        }
    };
    let Some(current) = current else {
        return Ok(Outcome::NoRegistration);
    };

    let updated = set_dashboard_flag_in_value(&current, Some(flag));
    let outcome = classify(Some(&current), &updated);
    if outcome == Outcome::Rewritten {
        // Only the Run value is touched — the StartupApproved override that Task
        // Manager writes is left exactly as the user set it.
        run.set_value(app_name, &updated)?;
    }
    Ok(outcome)
}

#[cfg(target_os = "macos")]
pub fn migrate(app_name: &str, flag: &str) -> std::io::Result<Outcome> {
    let Some(home) = dirs::home_dir() else {
        tracing::warn!("no home directory; cannot migrate the autostart registration");
        return Ok(Outcome::NoRegistration);
    };
    let dir = home.join("Library/LaunchAgents");
    let plist_path = dir.join(format!("{app_name}.plist"));

    // Ask forgiveness rather than `exists()`: the read already reports absence,
    // and a check-then-act would add a window in which we could recreate a
    // registration the user just turned off.
    let root = match plist::Value::from_file(&plist_path) {
        Ok(value) => value,
        Err(e) if e.as_io().map(std::io::Error::kind) == Some(std::io::ErrorKind::NotFound) => {
            return Ok(Outcome::NoRegistration);
        }
        Err(e) => return Err(std::io::Error::other(e)),
    };
    let mut root = root
        .into_dictionary()
        .ok_or_else(|| std::io::Error::other("LaunchAgent plist root is not a dictionary"))?;

    let source = root
        .get("ProgramArguments")
        .and_then(plist::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let existing: Vec<String> = source
        .iter()
        .filter_map(|v| v.as_string().map(str::to_string))
        .collect();
    if existing.is_empty() {
        // No program to preserve: a malformed or foreign plist. Report it rather
        // than letting the no-op comparison below call it already-migrated.
        tracing::warn!("LaunchAgent plist has no ProgramArguments; leaving it untouched");
        return Ok(Outcome::NoRegistration);
    }
    if existing.len() != source.len() {
        // Rewriting would drop the non-string elements, and this module's whole
        // premise is that it does not destroy state it does not own.
        tracing::warn!("LaunchAgent plist has non-string ProgramArguments; leaving it untouched");
        return Ok(Outcome::NoRegistration);
    }

    let updated = set_dashboard_flag_in_arguments(&existing, Some(flag));
    let outcome = classify(Some(&existing), &updated);
    if outcome != Outcome::Rewritten {
        return Ok(outcome);
    }

    root.insert(
        "ProgramArguments".into(),
        plist::Value::Array(updated.into_iter().map(plist::Value::String).collect()),
    );

    // Write-then-rename: this plist's existence *is* the user's Start-at-Login
    // setting (`auto-launch` disables by deleting it), so a truncated file would
    // silently stop Hole starting at login while the UI still read "enabled".
    let temp_path = dir.join(format!("{app_name}.plist.hole-new"));
    let write = plist::Value::Dictionary(root)
        .to_file_xml(&temp_path)
        .map_err(std::io::Error::other)
        .and_then(|()| std::fs::rename(&temp_path, &plist_path));
    if let Err(e) = write {
        // Leave no stray intermediate behind for the next start to trip over.
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    Ok(Outcome::Rewritten)
}

/// Hole ships macOS and Windows only; there is no Linux autostart to migrate.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn migrate(_app_name: &str, _flag: &str) -> std::io::Result<Outcome> {
    Ok(Outcome::NoRegistration)
}

#[cfg(test)]
#[path = "autostart_registration_tests.rs"]
mod autostart_registration_tests;
