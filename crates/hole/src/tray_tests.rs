//! Unit tests for the tray's pure decision logic (outcome mapping, the
//! intended-enabled persist rule). The remaining handler glue (menu event
//! dispatch, tray rebuilds, dialogs) requires a full Tauri app context and
//! has no automated coverage; the Start-at-Login toggle logic is unit-tested
//! in autostart_tests.rs, and the app-wide menu's structure in
//! window_menu_tests.rs.

use super::*;
use crate::bridge_client::ClientError;
use hole_common::config_store::ConfigStore;
use hole_common::protocol::{BridgeResponse, StartError, NETWORK_BLOCKED_MESSAGE};
use skuld::temp_dir;
use std::path::Path;
use std::sync::Mutex;

#[skuld::test]
fn tray_actions_blocked_offers_retry_and_go_offline() {
    // A covered start failed → host fail-closed while not running: a distinct
    // blocked state (never silent Disconnected), Retry (covered) + Go Offline.
    let a = tray_actions(false, None, &flags(false, false, false, false, true));
    assert_eq!(a.status, "Blocked — connect failed");
    assert_eq!(a.action_id, ID_BLOCKED_RETRY);
    assert_eq!(a.action_text, "Retry");
    assert!(a.show_go_offline, "blocked state must offer the cover-release escape");
}

#[skuld::test]
fn tray_actions_running_and_transition_take_precedence_over_blocked() {
    // A live transition or a running proxy is never overridden by a stale blocked
    // flag (blocked applies only when not running and not mid-transition).
    let running = tray_actions(true, None, &flags(false, false, false, false, true));
    assert_eq!(running.action_id, ID_DISCONNECT);
    assert!(!running.show_go_offline);
    let connecting = tray_actions(false, Some(true), &flags(false, false, false, false, true));
    assert_eq!(connecting.status, "Connecting...");
    assert!(!connecting.show_go_offline);
}

#[skuld::test]
fn tray_actions_normal_states_unchanged() {
    assert_eq!(
        tray_actions(false, None, &flags(false, false, false, false, false)).action_id,
        ID_CONNECT
    );
    assert_eq!(
        tray_actions(false, None, &flags(false, false, false, false, false)).status,
        "Disconnected"
    );
    assert_eq!(
        tray_actions(true, None, &flags(false, false, false, false, false)).action_id,
        ID_DISCONNECT
    );
    assert_eq!(
        tray_actions(true, None, &flags(false, false, false, false, false)).status,
        "Connected"
    );
}

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
    let sf = |e: StartError| outcome_for_start_response(&Ok(BridgeResponse::StartFailed(e)));
    assert!(matches!(
        outcome_for_start_response(&Ok(BridgeResponse::Ack)),
        Outcome(ToggleOutcome::Running)
    ));
    assert!(matches!(sf(StartError::Cancelled), Outcome(ToggleOutcome::Cancelled)));
    assert!(matches!(
        sf(StartError::AlreadyRunning),
        Outcome(ToggleOutcome::Running)
    ));
    assert!(matches!(sf(StartError::NetworkBlocked), Fail(_)));
    assert!(matches!(sf(StartError::Failed { message: "boom".into() }), Fail(_)));
    assert!(matches!(
        outcome_for_start_response(&Err(ClientError::PermissionDenied)),
        NeedsElevation
    ));
    assert!(matches!(
        outcome_for_start_response(&Err(ClientError::ConcurrentStart)),
        Fail(_)
    ));
    assert!(matches!(outcome_for_start_response(&Err(transport_err())), Fail(_)));
    // An unexpected variant on the Start path fails gracefully (no panic).
    assert!(matches!(outcome_for_start_response(&Ok(status_resp(true))), Fail(_)));
}

/// A `NetworkBlocked` start error renders a CLEAN toast — the host-free censorship
/// sentence standalone, NOT wrapped in `Bridge error:`.
#[skuld::test]
fn network_blocked_renders_clean_toast() {
    use StartDecision::*;
    let Fail(toast) = outcome_for_start_response(&Ok(BridgeResponse::StartFailed(StartError::NetworkBlocked))) else {
        panic!("expected StartDecision::Fail with the clean message");
    };
    assert_eq!(
        toast, NETWORK_BLOCKED_MESSAGE,
        "the censorship toast must be standalone"
    );
    assert!(!toast.contains("Bridge error:"), "no Bridge error: prefix: {toast}");
    assert!(toast.contains("firewall or censorship"), "{toast}");

    // The shared kind→toast producer (also used by the elevated path) renders
    // NetworkBlocked clean and Failed wrapped; a non-failure kind degrades safely.
    assert_eq!(start_error_toast(&StartError::NetworkBlocked), NETWORK_BLOCKED_MESSAGE);
    assert_eq!(
        start_error_toast(&StartError::Failed {
            message: "plugin failed".into()
        }),
        "Bridge error: plugin failed"
    );
    assert_eq!(
        start_error_toast(&StartError::Cancelled),
        "Bridge error: unexpected start outcome"
    );
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
    let label = lockdown_menu_label(&flags(true, false, false, false, false));
    assert!(
        label.to_lowercase().contains("warning") || label.contains('!'),
        "enabled+inactive must signal a warning, got {label:?}"
    );
}

#[skuld::test]
fn lockdown_active_renders_on_label() {
    let label = lockdown_menu_label(&flags(true, true, false, false, false));
    assert!(label.to_lowercase().contains("on") || label.to_lowercase().contains("lockdown"));
}

#[skuld::test]
fn lockdown_off_renders_plain_label() {
    let label = lockdown_menu_label(&flags(false, false, false, false, false));
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
        held_closed: false,
        cover_state_unknown: false,
        blocked_until_connected: false,
    }
}

fn status_resp_blocked() -> BridgeResponse {
    match status_resp(false) {
        BridgeResponse::Status {
            uptime_secs,
            error,
            invalid_filters,
            udp_proxy_available,
            ipv6_bypass_available,
            lockdown_enabled,
            lockdown_active,
            ..
        } => BridgeResponse::Status {
            running: false,
            uptime_secs,
            error,
            invalid_filters,
            udp_proxy_available,
            ipv6_bypass_available,
            lockdown_enabled,
            lockdown_active,
            held_closed: false,
            cover_state_unknown: false,
            blocked_until_connected: true,
        },
        other => other,
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
        // Not running but fail-closed -> retain (don't re-apply against a
        // deliberately-blocked host).
        (Ok(status_resp_blocked()), Retain),
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

/// Terse `LockdownFlags` for the pure tray tests, in menu-render order.
fn flags(enabled: bool, active: bool, held_closed: bool, unknown: bool, blocked: bool) -> LockdownFlags {
    LockdownFlags {
        enabled,
        active,
        held_closed,
        unknown,
        blocked,
    }
}

// Kill-switch lockout UX ==============================================================================================

#[skuld::test]
fn tray_actions_held_closed_offers_a_release() {
    let a = tray_actions(false, None, &flags(false, false, true, false, false));
    assert_eq!(a.status, "Hole is holding your network closed");
    assert!(a.show_release_lockdown, "the way out must be on the menu");
    assert_eq!(a.action_id, ID_CONNECT, "connecting also restores service");
}

#[skuld::test]
fn tray_actions_held_closed_outranks_blocked() {
    // Go Offline drops only the TRANSIENT cover, so it cannot be the whole story
    // when a standing cover is also up — but it is still the escape for the one
    // this process holds, so both must be offered.
    let a = tray_actions(false, None, &flags(false, false, true, false, true));
    assert_eq!(a.status, "Hole is holding your network closed");
    assert_ne!(
        a.action_id, ID_BLOCKED_RETRY,
        "the held-closed arm owns the status line"
    );
    assert!(a.show_release_lockdown);
    assert!(a.show_go_offline, "the transient cover keeps its own escape");
}

#[skuld::test]
fn tray_actions_held_closed_shown_even_while_running() {
    // A session that owns no cover can be "running" over a host the stale
    // block-all is killing; rendering that as Connected offers no way out.
    let a = tray_actions(true, None, &flags(false, false, true, false, false));
    assert_eq!(a.status, "Hole is holding your network closed");
    assert!(a.show_release_lockdown);
    assert_eq!(a.action_id, ID_DISCONNECT);
}

#[skuld::test]
fn tray_actions_held_closed_defers_to_a_transition() {
    for target in [true, false] {
        let a = tray_actions(false, Some(target), &flags(false, false, true, false, false));
        assert!(
            !a.show_release_lockdown,
            "a live transition owns the menu, same as the blocked state"
        );
    }
}

#[skuld::test]
fn tray_actions_without_held_closed_are_unchanged() {
    assert_eq!(
        tray_actions(false, None, &flags(false, false, false, false, false)).status,
        "Disconnected"
    );
    assert_eq!(
        tray_actions(true, None, &flags(false, false, false, false, false)).status,
        "Connected"
    );
    assert_eq!(
        tray_actions(false, None, &flags(false, false, false, false, true)).status,
        "Blocked — connect failed"
    );
    assert!(!tray_actions(false, None, &flags(false, false, false, false, true)).show_release_lockdown);
}

#[skuld::test]
fn lockdown_label_off_but_held_closed_points_at_the_release() {
    let label = lockdown_menu_label(&flags(false, true, true, false, false));
    assert!(
        label.contains("Unblock Network"),
        "a blocked-state label must name the action that ends it: {label}"
    );
}

#[skuld::test]
fn lockdown_label_off_but_session_owns_the_cover_says_on_reconnect() {
    // Traffic is flowing here — claiming the network is blocked would be a
    // false alarm. Settings apply on reconnect, so say that.
    let label = lockdown_menu_label(&flags(false, true, false, false, false));
    assert!(label.contains("reconnect"), "{label}");
    assert!(!label.contains("blocking"), "{label}");
}

#[skuld::test]
fn lockdown_label_arms_unaffected_by_held_closed_are_unchanged() {
    assert_eq!(
        lockdown_menu_label(&flags(true, true, false, false, false)),
        "Lockdown: On"
    );
    assert_eq!(
        lockdown_menu_label(&flags(true, false, false, false, false)),
        "Lockdown: On (warning: not engaged)"
    );
    assert_eq!(
        lockdown_menu_label(&flags(false, false, false, false, false)),
        "Lockdown"
    );
}

#[skuld::test]
fn lockdown_click_intent_off_but_held_closed_releases() {
    // The arm whose label warns the network is blocked must not ARM the switch.
    assert!(
        !lockdown_click_intent(&flags(false, false, true, false, false)),
        "clicking the still-blocking item must re-release, not arm"
    );
}

#[skuld::test]
fn lockdown_click_intent_off_while_a_session_owns_the_cover_re_arms() {
    // Turning the switch off mid-session leaves the cover engaged until the next
    // reconnect. Reading that as "still blocking" would make the switch
    // impossible to turn back on without disconnecting first.
    assert!(
        lockdown_click_intent(&flags(false, false, false, false, false)),
        "a session-owned cover is not a lockout; the click must re-arm"
    );
}

#[skuld::test]
fn lockdown_click_intent_toggles_every_other_arm() {
    assert!(
        lockdown_click_intent(&flags(false, false, false, false, false)),
        "off + nothing held closed arms it"
    );
    assert!(
        !lockdown_click_intent(&flags(true, false, true, false, false)),
        "on + held closed disarms it"
    );
    assert!(
        !lockdown_click_intent(&flags(true, false, false, false, false)),
        "on + not held closed disarms it"
    );
}

#[skuld::test]
fn release_failed_message_names_the_unlock_command() {
    let m = release_failed_message();
    assert!(m.contains("hole bridge unlock"), "{m}");
    assert!(m.contains("Hole"), "the message must name what is blocking: {m}");
    if cfg!(target_os = "windows") {
        assert!(m.contains("Administrator"), "{m}");
    } else {
        assert!(m.contains("sudo"), "{m}");
    }
}

#[skuld::test]
fn tray_actions_unknown_cover_does_not_claim_we_are_blocking() {
    // A wedged firewall engine makes this state permanent on Windows. Asserting
    // "Hole is holding your network closed" would be a claim never observed, over
    // a host that is probably open — the original complaint, from a new cause.
    let a = tray_actions(false, None, &flags(false, false, true, true, false));
    assert_eq!(a.status, "Hole cannot tell whether it is blocking your network");
    assert!(a.show_release_lockdown, "the way out must still be offered");
}

#[skuld::test]
fn tray_actions_both_covers_offer_both_escapes() {
    // Unblock Network clears only what no in-process guard owns; the live blocked
    // start owns the other. One action alone would leave the user just as blocked.
    let a = tray_actions(false, None, &flags(false, true, true, false, true));
    assert!(a.show_release_lockdown);
    assert!(a.show_go_offline, "the transient cover needs its own escape too");
}

#[skuld::test]
fn lockdown_click_intent_unknown_probe_can_still_arm() {
    // Otherwise a machine whose firewall engine is wedged could never arm the
    // kill switch again — a permanent loss of the feature from an unobserved state.
    assert!(
        lockdown_click_intent(&flags(false, false, true, true, false)),
        "an unconfirmed cover must not pin the switch off"
    );
}

#[skuld::test]
fn lockdown_label_unknown_cover_says_it_cannot_confirm() {
    let label = lockdown_menu_label(&flags(false, true, true, true, false));
    assert!(label.contains("cannot confirm"), "{label}");
    assert!(label.contains("Unblock Network"), "{label}");
}

#[skuld::test]
fn release_failed_message_has_no_stray_whitespace_runs() {
    // User-visible dialog copy: a line-continuation in the source once left a
    // ten-space gap mid-sentence.
    let m = release_failed_message();
    for line in m.lines() {
        assert!(
            !line.trim_start().contains("  "),
            "whitespace run mid-line in user-facing copy: {line:?}"
        );
    }
}
