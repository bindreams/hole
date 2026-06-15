//! Unit tests for the tray's pure decision logic (outcome mapping, the
//! intended-enabled persist rule). The remaining handler glue (menu
//! events, rebuilds, dialogs) requires a full Tauri app context and has
//! no automated coverage; the Start-at-Login toggle logic is unit-tested
//! in autostart_tests.rs.

use super::*;
use crate::bridge_client::ClientError;
use hole_common::config_store::ConfigStore;
use hole_common::protocol::{BridgeResponse, CANCELLED_MESSAGE};
use skuld::temp_dir;
use std::path::Path;
use std::sync::Mutex;

#[skuld::test]
fn transition_slot_rejects_concurrent_and_clears() {
    let t = TransitionSlot::new();
    assert_eq!(t.target(), None);
    assert!(t.try_begin(true));
    assert_eq!(t.target(), Some(true));
    assert!(
        !t.try_begin(false),
        "second toggle while one is in flight must be rejected"
    );
    t.end();
    assert_eq!(t.target(), None);
    assert!(t.try_begin(false));
}

fn err_resp(msg: &str) -> BridgeResponse {
    BridgeResponse::Error { message: msg.into() }
}

fn transport_err() -> ClientError {
    ClientError::Connection(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"))
}

#[skuld::test]
fn start_response_outcomes() {
    use StartDecision::*;
    assert!(matches!(
        outcome_for_start_response(&Ok(BridgeResponse::Ack)),
        Outcome(ToggleOutcome::Running)
    ));
    assert!(matches!(
        outcome_for_start_response(&Ok(err_resp(CANCELLED_MESSAGE))),
        Outcome(ToggleOutcome::Cancelled)
    ));
    assert!(matches!(
        outcome_for_start_response(&Ok(err_resp("proxy already running"))),
        Outcome(ToggleOutcome::Running)
    ));
    assert!(matches!(outcome_for_start_response(&Ok(err_resp("boom"))), Fail(_)));
    assert!(matches!(
        outcome_for_start_response(&Ok(BridgeResponse::Ack)),
        Outcome(ToggleOutcome::Running)
    ));
    assert!(matches!(
        outcome_for_start_response(&Err(ClientError::PermissionDenied)),
        NeedsElevation
    ));
    assert!(matches!(outcome_for_start_response(&Err(transport_err())), Fail(_)));
}

#[skuld::test]
fn stop_response_outcomes() {
    use StartDecision::*;
    assert!(matches!(
        outcome_for_stop_response(&Ok(BridgeResponse::Ack)),
        Outcome(ToggleOutcome::Stopped)
    ));
    assert!(matches!(
        outcome_for_stop_response(&Ok(err_resp("teardown failed"))),
        Fail(_)
    ));
    assert!(matches!(
        outcome_for_stop_response(&Err(ClientError::PermissionDenied)),
        NeedsElevation
    ));
    assert!(matches!(outcome_for_stop_response(&Err(transport_err())), Fail(_)));
}

#[skuld::test]
fn persist_intended_enabled_writes_only_on_change(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let (store, config, _) = ConfigStore::load(path.clone(), time::OffsetDateTime::UNIX_EPOCH);
    let config = Mutex::new(config);

    persist_intended_enabled(&config, &store, true);
    assert!(config.lock().unwrap().enabled);
    let (_, reloaded, _) = ConfigStore::load(path.clone(), time::OffsetDateTime::UNIX_EPOCH);
    assert!(reloaded.enabled, "the change must reach the disk");

    // Unchanged value → no write: delete the file, call with the same
    // value, assert it was NOT recreated.
    std::fs::remove_file(&path).unwrap();
    persist_intended_enabled(&config, &store, true);
    assert!(!path.exists(), "no-op persist must not touch the disk");

    // …and a CHANGED value after the delete does write again.
    persist_intended_enabled(&config, &store, false);
    assert!(path.exists());
    let (_, reloaded, _) = ConfigStore::load(path, time::OffsetDateTime::UNIX_EPOCH);
    assert!(!reloaded.enabled);
}

// lockdown_menu_label =================================================================================================

#[skuld::test]
fn lockdown_enabled_but_inactive_renders_warning_label() {
    // enabled && !active must never render silent green — it is a warning.
    let label = lockdown_menu_label(true, false);
    assert!(
        label.to_lowercase().contains("warning") || label.contains('!'),
        "enabled+inactive must signal a warning, got {label:?}"
    );
}

#[skuld::test]
fn lockdown_active_renders_on_label() {
    let label = lockdown_menu_label(true, true);
    assert!(label.to_lowercase().contains("on") || label.to_lowercase().contains("lockdown"));
}

#[skuld::test]
fn lockdown_off_renders_plain_label() {
    let label = lockdown_menu_label(false, false);
    assert!(!label.to_lowercase().contains("warning"));
}
