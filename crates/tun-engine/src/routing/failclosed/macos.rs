//! macOS fail-closed cover via pf (`pfctl`).
//!
//! Engage enables pf (refcounted, `pfctl -E`), flushes all state, and loads a
//! self-contained ruleset that blocks every outbound packet except loopback
//! and the SS server IP. Disengage restores the canonical `/etc/pf.conf` and
//! drops our enable refcount (`pfctl -X <token>`).
//!
//! Documented caveats (pf has no programmatic API — `pfctl` text I/O IS the
//! interface, as `netsh`/`route` are for routing):
//! - Restore reloads the on-disk `/etc/pf.conf`, not a snapshot of whatever
//!   ruleset was live before us (matches wg-quick's macOS behavior).
//! - The `pfctl -E` token is parsed from stderr — its only exposure.

use std::net::IpAddr;
use std::path::Path;

use super::super::{run_capturing, PHASE_COVER, PHASE_RECOVER_COVER};
use crate::error::RoutingError;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::failclosed_state as state;

/// Build the self-contained pf ruleset (loaded via `pfctl -f -`).
///
/// `set block-policy drop` silently drops blocked packets (no RST/ICMP).
/// `block out all` is the fail-closed default; the `quick` pass rules for
/// loopback and the server IP win without depending on pf's last-match rule.
pub fn build_pf_ruleset(server_ip: IpAddr) -> String {
    format!(
        "set block-policy drop\n\
         block out all\n\
         pass out quick on lo0 all\n\
         pass in quick on lo0 all\n\
         pass out quick from any to {server_ip}\n"
    )
}

/// pf anchor name for the standing lockdown ruleset. Scoped so the
/// session-long guard does not flush user/MDM pf policy (unlike the transient
/// cover's `-Fa`). A named anchor only evaluates when the MAIN ruleset
/// references it — see [`build_main_ruleset_with_anchor`].
pub const LOCKDOWN_ANCHOR: &str = "com.hole.lockdown";

/// Build the BODY loaded into the [`LOCKDOWN_ANCHOR`] (`pfctl -a <anchor> -f -`).
/// Blocks all outbound except loopback, the TUN interface (so app traffic flows
/// while connected), and the server IP. pf has no per-process matching, so the
/// server permit is IP-based (Decision A: macOS pins the server IP for the
/// session). All passes are `quick` so they win over the anchor's own
/// `block out all` without relying on last-match. This body is INERT until the
/// main ruleset references the anchor.
pub fn build_lockdown_ruleset(tun_name: &str, server_ip: IpAddr) -> String {
    format!(
        "set block-policy drop\n\
         block out all\n\
         pass out quick on lo0 all\n\
         pass in quick on lo0 all\n\
         pass out quick on {tun_name} all\n\
         pass out quick from any to {server_ip}\n"
    )
}

/// Compose the MAIN ruleset to load (NO `-Fa`): the host's pre-lockdown main
/// ruleset `snapshot` (captured via `pfctl -sr`) followed by the
/// `anchor "com.hole.lockdown"` call-out that makes the anchor body evaluate.
/// Without this call-out the lockdown anchor is inert and the kill switch does
/// nothing — this is the load-bearing composition.
pub fn build_main_ruleset_with_anchor(snapshot: &str) -> String {
    let mut main = String::with_capacity(snapshot.len() + 64);
    main.push_str(snapshot);
    if !snapshot.ends_with('\n') && !snapshot.is_empty() {
        main.push('\n');
    }
    main.push_str(&format!("anchor \"{LOCKDOWN_ANCHOR}\"\n"));
    main
}

/// Parse the enable token from `pfctl -E` output (it prints `Token : <n>`).
pub fn parse_enable_token(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.split_once("Token :").map(|(_, t)| t.trim().to_owned()))
        .filter(|t| !t.is_empty())
}

/// Parse `pfctl -s info` for the `Status: Enabled` line.
pub fn parse_pf_enabled(output: &str) -> bool {
    output
        .lines()
        .any(|l| l.trim_start().starts_with("Status:") && l.contains("Enabled"))
}

// --- engage layer ---

const PFCONF: &str = "/etc/pf.conf";

fn pfctl(args: &[&str], stdin: Option<&[u8]>, phase: &str) -> Result<std::process::Output, RoutingError> {
    let cmd: Vec<String> = std::iter::once("pfctl")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect();
    run_capturing(&cmd, stdin, phase).map_err(|e| RoutingError::RouteSetup(format!("pfctl spawn failed: {e}")))
}

/// pf-backed cover guard. Drop restores `/etc/pf.conf` and drops our enable
/// refcount.
pub struct Cover {
    token: String,
    state_dir: std::path::PathBuf,
}

pub fn engage(server_ip: IpAddr, state_dir: &Path) -> Result<Cover, RoutingError> {
    // 1. Read current enabled-state (read-only).
    let info = pfctl(&["-s", "info"], None, PHASE_COVER)?;
    let was_enabled = parse_pf_enabled(&String::from_utf8_lossy(&info.stdout));

    // 2. Enable pf (refcounted) and capture the token.
    let en = pfctl(&["-E"], None, PHASE_COVER)?;
    let token = parse_enable_token(&String::from_utf8_lossy(&en.stderr))
        .or_else(|| parse_enable_token(&String::from_utf8_lossy(&en.stdout)))
        .ok_or_else(|| RoutingError::RouteSetup("pfctl -E returned no token".into()))?;

    // 3. Persist BEFORE loading the blocking ruleset (persist-before-mutate),
    //    so a crash after this point is recoverable (`pfctl -X <token>`).
    state::save(
        state_dir,
        &state::FailClosedState {
            version: state::SCHEMA_VERSION,
            pf_token: token.clone(),
            pf_was_enabled: was_enabled,
        },
    )
    .map_err(|e| RoutingError::RouteSetup(format!("failed to persist failclosed-state: {e}")))?;

    // 4. Flush all + load our self-contained blocking ruleset from stdin.
    let ruleset = build_pf_ruleset(server_ip);
    let out = pfctl(&["-Fa", "-f", "-"], Some(ruleset.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        // A *failed engage* is the sole place this module fails OPEN on its own
        // error: we must not leave a half-loaded ruleset blocking traffic. Note
        // `-Fa` already flushed the host's prior rules, so a full `disengage`
        // (restore `/etc/pf.conf` + drop our refcount + clear the state file) is
        // required to undo the flush — dropping only the refcount would strand
        // the host with an empty pass-all ruleset. The PR3 cutover treats an
        // engage error as fatal and aborts before stopping the old bridge, so
        // the tunnel is never torn down uncovered.
        disengage(&token, state_dir);
        return Err(RoutingError::RouteSetup(format!(
            "pfctl load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
    })
}

impl Drop for Cover {
    fn drop(&mut self) {
        disengage(&self.token, &self.state_dir);
    }
}

/// Restore the canonical ruleset, drop our enable refcount, clear the file.
/// Best-effort; logs on failure. Shared by `Drop` and `recover_cover`.
fn disengage(token: &str, state_dir: &Path) {
    if let Err(e) = pfctl(&["-f", PFCONF], None, PHASE_RECOVER_COVER) {
        tracing::warn!(error = %e, "pf ruleset restore failed during cover disengage");
    }
    if let Err(e) = pfctl(&["-X", token], None, PHASE_RECOVER_COVER) {
        tracing::warn!(error = %e, "pfctl -X failed during cover disengage");
    }
    if let Err(e) = state::clear(state_dir) {
        tracing::warn!(error = %e, "failclosed-state clear failed during cover disengage");
    }
}

pub fn recover_cover(state_dir: &Path) {
    let Some(st) = state::load(state_dir) else {
        tracing::debug!("no failclosed-state file, nothing to recover");
        return;
    };
    tracing::info!(
        was_enabled = st.pf_was_enabled,
        "recovering fail-closed cover from crashed run"
    );
    disengage(&st.pf_token, state_dir);
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
