//! A probe route owned for exactly as long as the test that installed it.

use std::net::IpAddr;
use std::process::Command;

use super::command::{describe_output, ps_capture, ps_output};

/// The destination form `netstat -rn` prints for `prefix`: it drops trailing
/// zero octets, so `198.51.100.0/24` appears as `198.51.100`. Derived from
/// the prefix rather than written out, so the pre-existence guard cannot go
/// stale when the prefix changes and start matching nothing.
pub fn netstat_dest(prefix: &str) -> String {
    let addr = prefix.split('/').next().unwrap_or(prefix);
    let mut octets: Vec<&str> = addr.split('.').collect();
    while octets.len() > 1 && octets.last() == Some(&"0") {
        octets.pop();
    }
    octets.join(".")
}

/// A route this harness added, removed on `Drop` — and only ever a route it
/// confirmed adding (own only what we install).
///
/// Ownership is taken the instant the add succeeds and BEFORE any
/// verification, so a panic in the read-back still unwinds through `Drop`. A
/// route that escapes outlives the process (`store=active` on Windows keeps
/// it until reboot) and every later run then trips the pre-existence guard,
/// wedging the test on that machine until someone deletes it by hand.
///
/// `Drop` never panics: a failed removal is announced, so a developer whose
/// box is left modified finds out, without risking a double panic during an
/// unwind that would skip the release guards downstream.
pub struct OwnedRoute {
    prefix: String,
    interface: String,
}

impl OwnedRoute {
    /// Add `prefix` on `interface` (Windows: via `nexthop`, when the route is
    /// not on-link), after refusing to double up on a pre-existing route to
    /// the same prefix. `nexthop` is Windows-only.
    pub fn add(prefix: &str, interface: &str, nexthop: Option<IpAddr>) -> Self {
        assert_no_pre_existing(prefix);
        let out = if cfg!(target_os = "windows") {
            // NOTE: no manual quotes around the interface value. `Command::args`
            // already escapes each element as ONE argv token for the standard
            // Windows argv parser netsh's own C runtime startup uses; wrapping
            // the value in literal `"` characters makes THEM part of the
            // delivered value (`"Ethernet 3"`, quotes included) instead of
            // delimiting it, and netsh then fails to resolve a nonexistent
            // adapter literally named with quote marks — confirmed empirically
            // against a runner interface name containing a space.
            let mut args = vec![
                "interface".to_string(),
                "ipv4".to_string(),
                "add".to_string(),
                "route".to_string(),
                format!("prefix={prefix}"),
                format!("interface={interface}"),
            ];
            if let Some(nh) = nexthop {
                args.push(format!("nexthop={nh}"));
            }
            args.push("store=active".to_string());
            Command::new("netsh").args(&args).output()
        } else {
            assert!(nexthop.is_none(), "HARNESS: nexthop is Windows-only");
            Command::new("route")
                .args(["-n", "add", "-net", prefix, "-interface", interface])
                .output()
        };
        let out = out.unwrap_or_else(|e| panic!("HARNESS: failed to spawn the route-add command: {e}"));
        if !out.status.success() {
            panic!(
                "HARNESS: adding route {prefix} on '{interface}' failed: {}",
                describe_output(&out)
            );
        }

        Self {
            prefix: prefix.to_string(),
            interface: interface.to_string(),
        }
    }

    /// Assert the kernel's OWN lookup for `dest` now leaves via this route's
    /// interface. The add can succeed while a pre-existing same-length prefix
    /// elsewhere still wins the lookup, which no exit status reports; asking
    /// the kernel is the only answer that matches what a probe will do.
    pub fn assert_wins_for(&self, dest: IpAddr) {
        let winner = self.winner_for(dest).unwrap_or_else(|e| panic!("HARNESS: {e}"));
        assert_eq!(
            winner, self.interface,
            "HARNESS: after adding {}, traffic to {dest} would actually leave via '{winner}', not '{}' — \
             a pre-existing route may be winning a metric tiebreak",
            self.prefix, self.interface
        );
    }

    /// The interface the kernel would send `dest` out of, right now, or a
    /// rendered diagnostic. Never panics, so it can also be read inside a
    /// covered window as a same-instant check that the path is still there.
    pub fn winner_for(&self, dest: IpAddr) -> Result<String, String> {
        if cfg!(target_os = "windows") {
            return ps_capture(&format!(
                "(Find-NetRoute -RemoteIPAddress '{dest}' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty InterfaceAlias)"
            ));
        }
        let out = Command::new("route")
            .args(["-n", "get", &dest.to_string()])
            .output()
            .map_err(|e| format!("failed to spawn route get: {e}"))?;
        if !out.status.success() {
            return Err(format!("route -n get {dest} failed: {}", describe_output(&out)));
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.lines()
            .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()))
            .ok_or_else(|| format!("could not parse `route -n get {dest}` output:\n{text}"))
    }

    /// The interface this route names.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Drop for OwnedRoute {
    fn drop(&mut self) {
        let prefix = &self.prefix;
        let interface = &self.interface;
        let out = if cfg!(target_os = "windows") {
            // See `add`'s note: no manual quoting around the interface value.
            Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("prefix={prefix}"),
                    &format!("interface={interface}"),
                    "store=active",
                ])
                .output()
        } else {
            Command::new("route")
                .args(["-n", "delete", "-net", prefix, "-interface", interface])
                .output()
        };
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => super::escape::announce(&format!(
                "HARNESS: removing route {prefix} on '{interface}' failed: {} — the host is left modified",
                describe_output(&o)
            )),
            Err(e) => super::escape::announce(&format!(
                "HARNESS: failed to spawn the route-delete command for {prefix} on '{interface}': {e} — the host is \
                 left modified"
            )),
        }
    }
}

/// Refuse to add a second route to `prefix`: a route this harness did not
/// create must never be doubled up on, nor deleted out from under whatever
/// did create it.
fn assert_no_pre_existing(prefix: &str) {
    if cfg!(target_os = "windows") {
        let existing = ps_output(&format!(
            "(Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String).Trim()"
        ));
        assert!(
            existing.is_empty(),
            "HARNESS: a pre-existing route to {prefix} already exists — refusing to add a second:\n{existing}"
        );
        return;
    }
    let Ok(out) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() else {
        return;
    };
    let needle = netstat_dest(prefix);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let existing = text.lines().find(|l| {
        l.split_whitespace()
            .next()
            .map(|dest| dest.starts_with(&needle))
            .unwrap_or(false)
    });
    assert!(
        existing.is_none(),
        "HARNESS: a pre-existing route touching {prefix} already exists — refusing to add a second:\n{}",
        existing.unwrap_or_default()
    );
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod route_tests;
