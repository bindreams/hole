//! What Hole's covers hold on this host, read back from the OS, for the privileged tests.
//!
//! The egress waits in `hole_test_observability::egress` take this as their `HoleState`: an unreachable
//! target while a cover is installed is Hole's, never the runner's network. The reads are the ones the
//! production code already makes for the same question, so a test cannot disagree with the sweep about
//! what is installed.

use std::path::Path;

/// A description of every cover Hole holds, or `None` when it holds none. `state_dir` is the directory
/// the test engaged its covers with.
///
/// Anything but a confirmed absence counts as held (`CoverPresence::is_present`): a firewall that could
/// not be asked has not shown the cover gone.
pub(crate) fn held_covers(state_dir: &Path) -> Option<String> {
    let mut held = Vec::new();
    if let Some(lockdown) = crate::test_utils::held_lockdown(state_dir) {
        held.push(lockdown);
    }
    if let Some(transient) = transient_held(state_dir) {
        held.push(transient);
    }
    (!held.is_empty()).then(|| held.join(" and "))
}

/// Windows: the transient cover's twelve fixed filter keys, folded by the same `classify_presence` the
/// lockdown probe uses.
#[cfg(target_os = "windows")]
fn transient_held(_state_dir: &Path) -> Option<String> {
    use super::platform::{boottime_probe, classify_presence, FILTER_GUIDS};

    let mut engine_opened = true;
    let mut codes = Vec::new();
    for guid in FILTER_GUIDS {
        match boottime_probe::get_by_key(guid) {
            Ok((code, _)) => codes.push(code),
            Err(_) => engine_opened = false,
        }
    }
    let presence = classify_presence(engine_opened, &codes);
    presence
        .is_present()
        .then(|| format!("a transient cover (OS says {presence:?})"))
}

/// macOS: pf keeps no label for the transient ruleset, so the only record of it is Hole's own state
/// file, which an engage writes before it touches pf and a confirmed release is the only thing to clear.
#[cfg(target_os = "macos")]
fn transient_held(state_dir: &Path) -> Option<String> {
    let record = super::failclosed_state::load_presence(state_dir);
    (!matches!(record, super::StateFile::Absent)).then(|| "a transient cover (its state record exists)".to_string())
}

/// Run `scenario` (engage a cover, probe while it is engaged, drop the cover) until it holds. It returns
/// `Err(why)` AFTER dropping its cover when a permit probe failed; whether that is the network or the
/// cover is decided by [`hole_test_observability::egress::rerun_until_network_holds`], with `control`
/// probed outside the cover. Panics with `why` when the permit really failed.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[track_caller]
pub(crate) fn permit_scenario<T>(
    what: &str,
    state_dir: &Path,
    control: &str,
    scenario: impl FnMut() -> Result<T, String>,
) -> T {
    hole_test_observability::egress::rerun_until_network_holds(what, control, &|| held_covers(state_dir), scenario)
        .unwrap_or_else(|why| panic!("{why}"))
}
