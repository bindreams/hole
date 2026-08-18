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
    let a = tray_actions(false, None, true);
    assert_eq!(a.status, "Blocked — connect failed");
    assert_eq!(a.action_id, ID_BLOCKED_RETRY);
    assert_eq!(a.action_text, "Retry");
    assert!(a.show_go_offline, "blocked state must offer the cover-release escape");
}

#[skuld::test]
fn tray_actions_running_and_transition_take_precedence_over_blocked() {
    // A live transition or a running proxy is never overridden by a stale blocked
    // flag (blocked applies only when not running and not mid-transition).
    let running = tray_actions(true, None, true);
    assert_eq!(running.action_id, ID_DISCONNECT);
    assert!(!running.show_go_offline);
    let connecting = tray_actions(false, Some(true), true);
    assert_eq!(connecting.status, "Connecting...");
    assert!(!connecting.show_go_offline);
}

#[skuld::test]
fn tray_actions_normal_states_unchanged() {
    assert_eq!(tray_actions(false, None, false).action_id, ID_CONNECT);
    assert_eq!(tray_actions(false, None, false).status, "Disconnected");
    assert_eq!(tray_actions(true, None, false).action_id, ID_DISCONNECT);
    assert_eq!(tray_actions(true, None, false).status, "Connected");
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

// escape_items ========================================================================================================

#[skuld::test]
fn escape_items_offers_unblock_and_go_offline_independently() {
    // Exhaustive over all eight (lockdown_enabled, running, blocked_offers_go_offline)
    // rows. The two escapes are independent: `unblock` is exactly
    // `lockdown_enabled && !running`; `go_offline` is exactly
    // `blocked_offers_go_offline`. Both can be true at once — rendering both is the
    // point (rule #0 favours more escapes over fewer). There is no probe input to
    // fail — this table is the whole decision.
    let table = [
        // (lockdown_enabled, running, blocked_offers_go_offline, expect_go_offline, expect_unblock)
        (true, false, true, true, true),
        (true, false, false, false, true),
        (true, true, true, true, false),
        (true, true, false, false, false),
        (false, false, true, true, false),
        (false, false, false, false, false),
        (false, true, true, true, false),
        (false, true, false, false, false),
    ];
    for (lockdown_enabled, running, blocked_offers_go_offline, expect_go_offline, expect_unblock) in table {
        let escapes = escape_items(lockdown_enabled, running, blocked_offers_go_offline);
        assert_eq!(
            escapes,
            EscapeItems {
                go_offline: expect_go_offline,
                unblock: expect_unblock,
            },
            "lockdown_enabled={lockdown_enabled} running={running} blocked_offers_go_offline={blocked_offers_go_offline}"
        );
    }
}

#[skuld::test]
fn unblock_unreachable_message_names_the_command_and_the_disconnect_caveat() {
    assert!(UNBLOCK_UNREACHABLE_MESSAGE.contains("hole bridge unlock"));
    assert!(
        UNBLOCK_UNREACHABLE_MESSAGE.to_lowercase().contains("disconnect"),
        "must caution the user to disconnect first: {UNBLOCK_UNREACHABLE_MESSAGE:?}"
    );
    assert!(
        !UNBLOCK_UNREACHABLE_MESSAGE.contains('\\') && !UNBLOCK_UNREACHABLE_MESSAGE.contains('/'),
        "must carry no filesystem path: {UNBLOCK_UNREACHABLE_MESSAGE:?}"
    );
}

#[skuld::test]
fn unblock_session_running_message_does_not_name_the_cli() {
    assert!(
        UNBLOCK_SESSION_RUNNING_MESSAGE.to_lowercase().contains("disconnect"),
        "must point the user at Disconnect: {UNBLOCK_SESSION_RUNNING_MESSAGE:?}"
    );
    assert!(
        !UNBLOCK_SESSION_RUNNING_MESSAGE.contains("bridge unlock"),
        "must NOT talk a user into an out-of-process clear over a live tunnel: {UNBLOCK_SESSION_RUNNING_MESSAGE:?}"
    );
}

#[skuld::test]
fn unblock_dialog_message_maps_each_response_distinctly() {
    use crate::bridge_client::ClientError;

    // Ack: silent success, no dialog.
    assert_eq!(unblock_dialog_message(&Ok(BridgeResponse::Ack)), None);

    // SessionRunning: the disconnect-safe message — a swapped arm here would
    // show UNBLOCK_UNREACHABLE_MESSAGE instead, which names the CLI command
    // and would strip a cover out from under a live tunnel.
    assert_eq!(
        unblock_dialog_message(&Err(ClientError::SessionRunning)).as_deref(),
        Some(UNBLOCK_SESSION_RUNNING_MESSAGE)
    );

    // A bridge-authored failure: shown verbatim, not replaced by a fixed string.
    assert_eq!(unblock_dialog_message(&Ok(err_resp("boom"))).as_deref(), Some("boom"));

    // Any transport/protocol error: the CLI-naming unreachable message.
    assert_eq!(
        unblock_dialog_message(&Err(transport_err())).as_deref(),
        Some(UNBLOCK_UNREACHABLE_MESSAGE)
    );

    // An unexpected Ok shape (a same-build contract breach): never silent —
    // falls back to the same unreachable message.
    let unexpected = Ok(BridgeResponse::Metrics {
        bytes_in: 0,
        bytes_out: 0,
        speed_in_bps: 0,
        speed_out_bps: 0,
        uptime_secs: 0,
        filter: None,
    });
    assert_eq!(
        unblock_dialog_message(&unexpected).as_deref(),
        Some(UNBLOCK_UNREACHABLE_MESSAGE)
    );
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
