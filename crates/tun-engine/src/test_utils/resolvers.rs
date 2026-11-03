//! The resolver set the OS reports, read for the privileged DNS tests (macOS `scutil --dns`).

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

use std::process::Command;

use hole_test_observability::egress::{self, HoleState};

/// A host that neither a cover nor a tunnel the DNS tests engage ever blocks: the control that tells a
/// runner network loss from a Hole defect when a resolver set is read.
pub const NETWORK_CONTROL: &str = "8.8.8.8:443";

/// `scutil --dns`, or why it could not be read: a failed read is taken again, not compared.
pub fn scutil_dns_checked() -> Result<String, String> {
    let output = Command::new("scutil")
        .arg("--dns")
        .output()
        .map_err(|e| format!("failed to spawn scutil --dns: {e}"))?;
    if !output.status.success() {
        return Err(format!("scutil --dns exited with {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every `nameserver[N] : ADDR` line, sorted and deduped — the structural shape of "which resolvers does
/// this machine use", stable enough to compare before against after.
pub fn nameservers(scutil_dns_output: &str) -> Vec<String> {
    let mut out: Vec<String> = scutil_dns_output
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("nameserver["))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The raw `scutil --dns` output and its resolver set, read with [`NETWORK_CONTROL`] answering around
/// the read: the runner's own resolver leaves with its network, so a set read while it was away is no
/// evidence about Hole.
#[track_caller]
pub fn resolver_set(what: &str, hole_state: HoleState<'_>) -> (String, Vec<String>) {
    egress::read_with_network_up(what, NETWORK_CONTROL, hole_state, || {
        let dns = scutil_dns_checked()?;
        let servers = nameservers(&dns);
        Ok::<_, String>((dns, servers))
    })
}

/// [`resolver_set`] for a test that engages no cover, so a cover Hole holds is an earlier test's leak.
/// The cover oracle reads the OS, so the directory it is handed names nothing.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[track_caller]
pub fn resolver_set_uncovered(what: &str) -> (String, Vec<String>) {
    let no_cover_dir = tempfile::tempdir().expect("HARNESS: tempdir for the cover oracle");
    resolver_set(what, &|| super::held_covers(no_cover_dir.path()))
}

#[cfg(test)]
#[path = "resolvers_tests.rs"]
mod resolvers_tests;
