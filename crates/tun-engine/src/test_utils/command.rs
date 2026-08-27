//! Shelling out, with the diagnostics a first CI run needs.

use std::process::{Command, Output};

/// Render a completed process's exit status AND both streams. `netsh` writes
/// its diagnostics to STDOUT, not stderr — a stderr-only capture silently
/// drops the one line that explains a failure, turning "failed:" into an
/// empty, undiagnosable message.
pub fn describe_output(out: &Output) -> String {
    format!(
        "exit={:?} stdout={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
}

/// Run a PowerShell one-liner and return its trimmed stdout, or a rendered
/// diagnostic on a spawn failure or nonzero exit.
///
/// Never panics: a caller inside a covered window can fold the result into a
/// local and judge it after the cover is released, where a panic would skip
/// the release guards (Rule #0).
pub fn ps_capture(script: &str) -> Result<String, String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| format!("failed to spawn powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "powershell -Command {script:?} failed: {}",
            describe_output(&out)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// [`ps_capture`], panicking on failure. For use only where no cover is
/// engaged — see [`ps_capture`].
pub fn ps_output(script: &str) -> String {
    ps_capture(script).unwrap_or_else(|e| panic!("HARNESS: {e}"))
}
