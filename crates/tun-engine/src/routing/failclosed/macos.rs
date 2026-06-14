//! macOS fail-closed cover via pf (`pfctl`). Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted,
//!   `pfctl -E`), flushes all state (`-Fa`), and loads a self-contained ruleset
//!   blocking every outbound packet except loopback and the SS server IP.
//!   Disengage restores the canonical `/etc/pf.conf` and drops the refcount.
//! - **Standing lockdown** (`engage_lockdown`/`lockdown_disengage`): loads a
//!   self-contained MAIN ruleset (NO `-Fa`) that carries the host's translation
//!   rules forward and blocks all egress except the TUN and server IP. Disengage
//!   restores the host's pre-lockdown filter+nat from the persisted snapshot —
//!   not a blind `/etc/pf.conf` reload — and drops the refcount.
//!
//! Documented caveats (pf has no programmatic API — `pfctl` text I/O IS the
//! interface, as `netsh`/`route` are for routing):
//! - The transient restore reloads `/etc/pf.conf`; the lockdown restore reloads
//!   the captured snapshot. Neither can recover prior `set` options (pf exposes
//!   no dump of them), so both restore under pf defaults.
//! - The `pfctl -E` token is parsed from stderr — its only exposure.

use std::net::IpAddr;
use std::path::Path;

use super::super::{run_capturing, PHASE_COVER, PHASE_RECOVER_COVER};
use crate::error::RoutingError;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::failclosed_state as state;
use super::lockdown_pf_state as lockdown_state;

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

/// Normalize a snapshot fragment to end in exactly one `\n`. Empty stays empty
/// (so an absent NAT section contributes no stray blank line); non-empty text
/// gets a single trailing newline if it lacks one.
pub fn ensure_trailing_nl(s: &str) -> String {
    if s.is_empty() || s.ends_with('\n') {
        s.to_owned()
    } else {
        format!("{s}\n")
    }
}

/// Build the self-contained MAIN ruleset for the standing lockdown, loaded via
/// `pfctl -f -` (NO `-Fa`). It IS the host's egress policy while engaged:
/// `block drop out quick all` is the fail-closed base, with earlier `quick`
/// permits for the TUN and the server IP.
///
/// `set` lives here (main-ruleset-only — it is a parse error inside an anchor),
/// and the host's translation rules (`nat_snapshot`, from `pfctl -sn`) are
/// carried forward so the session does not flush NAT. Ordering is
/// `require-order`-enforced: Options -> Translation (nat) -> Filter. The server
/// permit precedes `block drop out quick inet6 all` so a v6 server is not
/// killed. pf has no per-process matching, so the server permit is IP-based.
pub fn build_lockdown_main_ruleset(tun_name: &str, server_ip: IpAddr, nat_snapshot: &str) -> String {
    let proto = "tcp"; // +udp once a UDP-transport plugin lands; egress is TCP-only today.
    format!(
        "set block-policy drop\n\
         set skip on lo0\n\
         {nat}\
         pass out quick proto {proto} from any to {ip}\n\
         pass out quick on {tun} all\n\
         block drop out quick inet6 all\n\
         block drop out quick all\n",
        nat = ensure_trailing_nl(nat_snapshot),
        proto = proto,
        ip = server_ip,
        tun = tun_name,
    )
}

/// Build the ruleset that restores the host's pre-lockdown policy on Sweep,
/// reloaded via `pfctl -f -`. Composes the captured translation (`nat_snapshot`,
/// from `pfctl -sn`) and filter (`main_snapshot`, from `pfctl -sr`) snapshots.
///
/// `set require-order no` leads: `pfctl -sr` on macOS emits a NORMALIZATION line
/// (`scrub-anchor "com.apple/*"`) interleaved with filter rules, so naively
/// concatenating `{nat}{filter}` puts translation before normalization — a
/// `require-order` parse error that would silently fail the restore. Disabling
/// the order check lets pfctl accept the snapshots verbatim, exactly as the
/// host had them loaded.
pub fn build_lockdown_restore_ruleset(nat_snapshot: &str, main_snapshot: &str) -> String {
    format!(
        "set require-order no\n\
         set block-policy drop\n\
         {nat}{filter}",
        nat = ensure_trailing_nl(nat_snapshot),
        filter = main_snapshot,
    )
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

/// Which cover a [`Cover`] guard owns — selects its Drop disengage path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverKind {
    Transient,
    Lockdown,
}

/// pf-backed cover guard. Drop disengages per [`CoverKind`]: the transient
/// cover restores `/etc/pf.conf`; the lockdown cover restores the snapshot.
pub struct Cover {
    token: String,
    state_dir: std::path::PathBuf,
    kind: CoverKind,
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
        kind: CoverKind::Transient,
    })
}

impl Drop for Cover {
    fn drop(&mut self) {
        match self.kind {
            CoverKind::Transient => disengage(&self.token, &self.state_dir),
            CoverKind::Lockdown => lockdown_disengage(&self.state_dir),
        }
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

// --- lockdown layer ---

/// Snapshot the host's filter (`-sr`) and translation (`-sn`) rules and persist
/// them with `token` (persist-before-mutate). Returns the nat snapshot for the
/// engage ruleset. Separated so its `?`-error path can be unwound (drop the pf
/// refcount) by the caller without leaking the `-E` enable.
fn capture_and_persist(token: &str, state_dir: &Path) -> Result<String, RoutingError> {
    let sr = pfctl(&["-sr"], None, PHASE_COVER)?;
    let main_snapshot = String::from_utf8_lossy(&sr.stdout).into_owned();
    let sn = pfctl(&["-sn"], None, PHASE_COVER)?;
    let nat_snapshot = String::from_utf8_lossy(&sn.stdout).into_owned();

    lockdown_state::save(
        state_dir,
        &lockdown_state::LockdownPfState {
            version: lockdown_state::SCHEMA_VERSION,
            pf_token: token.to_owned(),
            main_snapshot,
            nat_snapshot: nat_snapshot.clone(),
        },
    )
    .map_err(|e| RoutingError::RouteSetup(format!("failed to persist lockdown-pf-state: {e}")))?;
    Ok(nat_snapshot)
}

/// Engage the standing lockdown cover. Persist-before-mutate, no `-Fa`:
///
/// 1. If a valid `bridge-lockdown-pf.json` already exists (Adopt re-engage),
///    REUSE its token + snapshots — re-running `-sr`/`-sn` here would snapshot
///    our own lockdown ruleset as the "host" and lose the real host policy.
/// 2. Else: `pfctl -E` (refcount) + capture token; `pfctl -sr` (filter) and
///    `pfctl -sn` (nat) snapshots; persist {token, snapshots} before mutating.
/// 3. Load the self-contained main ruleset via `pfctl -f -` (NO `-Fa`), so the
///    block takes effect while host translation is carried forward.
///
/// On load failure the host is restored (`lockdown_disengage`) and Err returned;
/// the bridge's fail-FATAL caller aborts the start.
pub fn engage_lockdown(server_ip: IpAddr, tun_name: &str, state_dir: &Path) -> Result<Cover, RoutingError> {
    let (token, nat_snapshot) = match lockdown_state::load(state_dir) {
        // Adopt re-engage: reuse the persisted host snapshot+token so the real
        // host policy is preserved for the eventual restore.
        Some(st) => (st.pf_token, st.nat_snapshot),
        None => {
            let en = pfctl(&["-E"], None, PHASE_COVER)?;
            let token = parse_enable_token(&String::from_utf8_lossy(&en.stderr))
                .or_else(|| parse_enable_token(&String::from_utf8_lossy(&en.stdout)))
                .ok_or_else(|| RoutingError::RouteSetup("pfctl -E returned no token".into()))?;

            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match capture_and_persist(&token, state_dir) {
                Ok(nat_snapshot) => (token, nat_snapshot),
                Err(e) => {
                    if let Err(xe) = pfctl(&["-X", &token], None, PHASE_COVER) {
                        tracing::warn!(error = %xe, "pfctl -X failed unwinding a failed lockdown engage");
                    }
                    return Err(e);
                }
            }
        }
    };

    let main = build_lockdown_main_ruleset(tun_name, server_ip, &nat_snapshot);
    let out = pfctl(&["-f", "-"], Some(main.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        // Restore the host (snapshot reload + drop refcount) before failing, so
        // a partially-loaded ruleset never strands the host.
        lockdown_disengage(state_dir);
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Lockdown,
    })
}

/// Sweep: restore the host's pre-lockdown ruleset from the snapshot, drop our pf
/// refcount, clear the state. The snapshot reload IS the restore — there is no
/// anchor to flush. Shared by Drop (user-stop) and `recover_lockdown` when the
/// persisted intent is OFF. Best-effort; logs on failure.
///
/// Caveat: pf exposes no dump of prior `set` options, so the restore reloads the
/// host's filter+nat rules under pf defaults (same class of limitation the
/// transient cover documents for its `/etc/pf.conf` reload).
fn lockdown_disengage(state_dir: &Path) {
    if let Some(st) = lockdown_state::load(state_dir) {
        let restore = build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot);
        if let Err(e) = pfctl(&["-f", "-"], Some(restore.as_bytes()), PHASE_RECOVER_COVER) {
            tracing::warn!(error = %e, "lockdown snapshot restore failed");
        }
        if let Err(e) = pfctl(&["-X", &st.pf_token], None, PHASE_RECOVER_COVER) {
            tracing::warn!(error = %e, "pfctl -X failed during lockdown disengage");
        }
    }
    if let Err(e) = lockdown_state::clear(state_dir) {
        tracing::warn!(error = %e, "lockdown-pf-state clear failed during disengage");
    }
}

/// Act on a recovery decision for the lockdown cover (called from
/// `failclosed::recover_lockdown`). `Adopt` (intent ON): KEEP the host
/// fail-closed — leave the lockdown ruleset + state file in force. The dead
/// utun name in the `pass out quick on <tun>` line is harmless (matches no live
/// interface); the next connect's `engage_lockdown` reuses the persisted
/// snapshot and reloads with the fresh utun name. `Sweep` (intent OFF): full
/// restore via `lockdown_disengage`. `Noop`: nothing.
pub fn recover_lockdown(decision: crate::routing::CoverRecovery, state_dir: &Path) {
    use crate::routing::CoverRecovery::*;
    match decision {
        Noop => {}
        Adopt => {
            tracing::info!("lockdown recovery: adopting persistent cover (host stays fail-closed)");
            // Intentionally NOTHING removed: the block must survive the
            // restart (this IS the crash-leak fix). NOTE: macOS pf rules do
            // NOT survive a reboot, so a reboot opens a boot->first-connect
            // window — tracked under the deferred Decision C-b (block when
            // disconnected, needs an early-boot block).
        }
        Sweep => {
            tracing::info!("lockdown recovery: sweeping leftover cover (intent off)");
            lockdown_disengage(state_dir);
        }
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
