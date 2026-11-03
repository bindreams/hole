//! What Hole's covers hold on this host, read back from the OS, for the privileged tests.
//!
//! The egress waits in `hole_test_observability::egress` take this as their `HoleState`: an unreachable
//! target while a cover is installed is Hole's, never the runner's network. The reads are the ones the
//! production code already makes for the same question, so a test cannot disagree with the sweep about
//! what is installed.

use std::path::Path;

#[cfg(test)]
pub(crate) use super::permit_scenario::permit_scenario;

/// A description of every cover Hole holds, or `None` when it holds none. `state_dir` is the directory
/// the test engaged its covers with.
///
/// Anything but a confirmed absence counts as held (`CoverPresence::is_present`): a firewall that could
/// not be asked has not shown the cover gone.
pub(crate) fn held_covers(state_dir: &Path) -> Option<String> {
    let mut held = Vec::new();
    if let Some(lockdown) = lockdown_held(state_dir) {
        held.push(lockdown);
    }
    if let Some(transient) = transient_held(state_dir) {
        held.push(transient);
    }
    (!held.is_empty()).then(|| held.join(" and "))
}

/// The standing lockdown cover: the read the production sweep makes (WFP filters; pf label and state file).
fn lockdown_held(state_dir: &Path) -> Option<String> {
    let presence = super::lockdown_cover_presence(state_dir);
    presence
        .is_present()
        .then(|| format!("a standing lockdown cover (OS says {presence:?})"))
}

/// Windows: the transient cover's fixed filter keys.
#[cfg(target_os = "windows")]
fn transient_held(_state_dir: &Path) -> Option<String> {
    let presence = super::platform::transient_cover_presence();
    presence
        .is_present()
        .then(|| format!("a transient cover (OS says {presence:?})"))
}

/// macOS: the transient ruleset carries no pf label, so it is read two ways. Hole's state file, which an
/// engage writes before it touches pf and a confirmed release is the only thing to clear, lives under the
/// engaging test's directory only. The live main ruleset is global: a clean host's has no `block` rule,
/// so one is a cover, whichever test engaged it and whether or not its record survived.
#[cfg(target_os = "macos")]
fn transient_held(state_dir: &Path) -> Option<String> {
    let mut sources = Vec::new();
    if !matches!(
        super::failclosed_state::load_presence(state_dir),
        super::StateFile::Absent
    ) {
        sources.push("its state record exists");
    }
    match live_main_ruleset_blocks() {
        Some(false) => {}
        Some(true) => sources.push("the live pf ruleset has a block rule"),
        None => sources.push("pf could not be asked"),
    }
    (!sources.is_empty()).then(|| format!("a transient cover ({})", sources.join(" and ")))
}

/// Whether `pfctl -sr` lists a block rule; `None` when pf could not be asked.
#[cfg(target_os = "macos")]
fn live_main_ruleset_blocks() -> Option<bool> {
    use crate::routing::{run_capturing, BestEffortPhase};
    use util::system_tool::SystemTool;

    let out = match run_capturing(SystemTool::Pfctl, &["-sr"], None, BestEffortPhase::RecoverCover) {
        Ok(out) => out,
        Err(e) => {
            tracing::warn!("pfctl -sr could not run, so pf could not be asked: {e}");
            return None;
        }
    };
    if !out.status.success() {
        tracing::warn!(
            "pfctl -sr exited {}, so pf could not be asked: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(ruleset_has_block_rule(&String::from_utf8_lossy(&out.stdout)))
}

/// Whether a `pfctl -sr` listing has a block rule: a rule line whose first word is `block`. A clean
/// runner lists only `scrub-anchor` and `anchor` lines for Apple's own anchors.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn ruleset_has_block_rule(listing: &str) -> bool {
    listing
        .lines()
        .any(|line| line.split_whitespace().next() == Some("block"))
}
