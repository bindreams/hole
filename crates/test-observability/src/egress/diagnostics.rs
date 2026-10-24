//! What the OS says about its own network at the moment a probe first fails.

// Dev tooling that reads state and is never privileged: OS diagnostics by name, not a Hole spawn.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

/// Log the OS's interface, route and resolver state. Best-effort: a tool that cannot run is reported
/// in the dump, and nothing here can fail the caller.
pub(super) fn dump(what: &str) {
    for (program, args) in commands() {
        let shown = format!("{program} {}", args.join(" "));
        match Command::new(program).args(args).output() {
            Ok(out) => tracing::warn!(
                "{what}: `{shown}` (exit {}):\n{}{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ),
            Err(e) => tracing::warn!("{what}: `{shown}` could not run: {e}"),
        }
    }
}

#[cfg(target_os = "macos")]
fn commands() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("/sbin/ifconfig", &[]),
        ("/sbin/route", &["-n", "get", "default"]),
        ("/usr/sbin/scutil", &["--dns"]),
    ]
}

#[cfg(target_os = "windows")]
fn commands() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("ipconfig", &["/all"]), ("route", &["print"])]
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn commands() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("ip", &["addr"]), ("ip", &["route"])]
}
