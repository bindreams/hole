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

/// #580: a `NetworkBlocked` start error renders a CLEAN toast — the host-free
/// censorship sentence standalone, NOT wrapped in `Bridge error:` / attempts
/// noise — mirroring how `CANCELLED_MESSAGE` is handled by sentinel.
#[skuld::test]
fn network_blocked_renders_clean_toast() {
    use StartDecision::*;
    let resp = Ok(err_resp(hole_bridge::reachability::NETWORK_BLOCKED_MESSAGE));
    let Fail(toast) = outcome_for_start_response(&resp) else {
        panic!("expected StartDecision::Fail with the clean message");
    };
    assert_eq!(
        toast,
        hole_bridge::reachability::NETWORK_BLOCKED_MESSAGE,
        "the censorship toast must be standalone"
    );
    assert!(!toast.contains("Bridge error:"), "no Bridge error: prefix: {toast}");
    assert!(toast.contains("firewall or censorship"), "{toast}");

    // The shared message→toast producer (also used by the elevated path) renders
    // NetworkBlocked clean and everything else wrapped.
    assert_eq!(
        start_error_toast(hole_bridge::reachability::NETWORK_BLOCKED_MESSAGE),
        hole_bridge::reachability::NETWORK_BLOCKED_MESSAGE
    );
    assert_eq!(start_error_toast("plugin failed"), "Bridge error: plugin failed");
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

// startup_should_connect ==============================================================================================

#[skuld::test]
fn startup_should_connect_truth_table() {
    use hole_common::config::StartupBehavior::*;
    // DoNotConnect: never, regardless of last_enabled.
    assert!(!startup_should_connect(DoNotConnect, false));
    assert!(!startup_should_connect(DoNotConnect, true));
    // RestoreLastState: mirror the last honored intent.
    assert!(!startup_should_connect(RestoreLastState, false));
    assert!(startup_should_connect(RestoreLastState, true));
    // AlwaysConnect: always.
    assert!(startup_should_connect(AlwaysConnect, false));
    assert!(startup_should_connect(AlwaysConnect, true));
}

// should_apply_pending ================================================================================================

fn status_resp(running: bool) -> BridgeResponse {
    BridgeResponse::Status {
        running,
        uptime_secs: 0,
        error: None,
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        lockdown_active: false,
    }
}

#[skuld::test]
fn should_apply_pending_rules() {
    use PendingAction::*;
    // Owned Results, only borrowed (BridgeResponse/ClientError are not Clone).
    let table: Vec<(Result<BridgeResponse, ClientError>, PendingAction)> = vec![
        // Bridge reachable and idle -> apply the boot-connect intent now.
        (Ok(status_resp(false)), Apply),
        // Bridge reachable and already running -> intent satisfied, drop it.
        (Ok(status_resp(true)), Drop),
        // Bridge not reachable yet (still booting) -> keep the intent for a later tick.
        (Err(transport_err()), Retain),
        // A DACL/version/transport hiccup proves nothing about readiness -> keep the intent.
        (Err(ClientError::PermissionDenied), Retain),
        (Err(ClientError::VersionMismatch { bridge: None }), Retain),
        (Err(ClientError::Io(std::io::Error::other("io"))), Retain),
        (Err(ClientError::Protocol("bad frame".into())), Retain),
        // Reachable but the bridge errored on Status -> keep the intent.
        (Ok(err_resp("busy")), Retain),
        (Ok(BridgeResponse::Ack), Retain),
    ];
    for (result, expected) in &table {
        assert_eq!(should_apply_pending(result), *expected, "{result:?}");
    }
}

// Toast producers =====================================================================================================

#[skuld::test]
fn bridge_error_toast_formats_message() {
    assert_eq!(
        bridge_error_toast("invalid cipher method: aes-999"),
        "Bridge error: invalid cipher method: aes-999"
    );
}

#[skuld::test]
fn transport_after_elevation_toast_points_to_log() {
    let toast = transport_after_elevation_toast("connection refused");
    assert!(toast.to_lowercase().contains("after elevation"), "{toast}");
    assert!(toast.contains("gui.log"), "{toast}");
    assert!(toast.contains("connection refused"), "{toast}");
}

// should_prompt_install ===============================================================================================

#[skuld::test]
fn install_gate_skips_externally_supervised_bridge() {
    use crate::setup::BridgeInstallStatus::*;
    // Externally supervised (HOLE_BRIDGE_SOCKET / dev): never prompt, and the
    // production status probe is never even consulted (it may spawn launchctl).
    let mut probed = false;
    assert!(!should_prompt_install(true, || {
        probed = true;
        NotInstalled
    }));
    assert!(!probed, "external bridge must short-circuit before the status probe");
}

#[skuld::test]
fn install_gate_prompts_only_when_production_service_absent() {
    use crate::setup::BridgeInstallStatus::*;
    // GUI owns the bridge: prompt iff the production service is absent.
    assert!(should_prompt_install(false, || NotInstalled));
    assert!(!should_prompt_install(false, || Installed));
    assert!(!should_prompt_install(false, || Running));
}

// decide_elevation ====================================================================================================

#[skuld::test]
fn elevation_declined_for_externally_supervised_bridge() {
    use ElevationDecision::*;
    // Externally supervised: never elevate — neither connect nor disconnect,
    // regardless of prompts (the elevated helper would mis-target the default socket).
    for is_disconnect in [false, true] {
        for prompts in [Prompts::Allowed, Prompts::Forbidden] {
            assert!(
                matches!(decide_elevation(true, prompts, is_disconnect), Decline(_)),
                "external must decline elevation (disconnect={is_disconnect})"
            );
        }
    }
}

#[skuld::test]
fn elevation_matrix_when_gui_owns_bridge() {
    use ElevationDecision::*;
    // Connect, prompts allowed -> elevate.
    assert!(matches!(decide_elevation(false, Prompts::Allowed, false), Elevate));
    // Connect, unattended startup -> decline (no UAC at login).
    assert!(matches!(decide_elevation(false, Prompts::Forbidden, false), Decline(_)));
    // Disconnect is always interactive -> elevate regardless of prompts.
    assert!(matches!(decide_elevation(false, Prompts::Allowed, true), Elevate));
    assert!(matches!(decide_elevation(false, Prompts::Forbidden, true), Elevate));
}

#[skuld::test]
fn external_bridge_denied_toast_is_actionable() {
    let toast = external_bridge_denied_toast();
    assert!(toast.to_lowercase().contains("permission denied"), "{toast}");
    assert!(toast.contains("gui.log"), "{toast}");
}
