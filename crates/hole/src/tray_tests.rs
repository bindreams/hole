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
fn lockdown_enabled_but_absent_renders_warning_label() {
    // enabled && == Absent must never render silent green — it is a warning.
    let label = lockdown_menu_label(true, CoverPresence::Absent);
    assert!(
        label.to_lowercase().contains("warning") || label.contains('!'),
        "enabled+absent must signal a warning, got {label:?}"
    );
}

#[skuld::test]
fn lockdown_live_renders_on_label() {
    let label = lockdown_menu_label(true, CoverPresence::Live);
    assert!(label.to_lowercase().contains("on") || label.to_lowercase().contains("lockdown"));
}

#[skuld::test]
fn lockdown_off_renders_plain_label() {
    let label = lockdown_menu_label(false, CoverPresence::Absent);
    assert!(!label.to_lowercase().contains("warning"));
}

// escape_items ========================================================================================================

#[skuld::test]
fn escape_items_offers_unblock_and_go_offline_independently() {
    // Exhaustive over all eight (cover_presence, running, blocked_offers_go_offline)
    // rows, `cover_presence` replacing `lockdown_enabled` (Task 5) but keeping the
    // same `&& !running` gate — the property is preserved by construction, not
    // reproven: `unblock` is exactly `cover_presence != Absent && !running`;
    // `go_offline` is exactly `blocked_offers_go_offline`. Both can be true at
    // once — rendering both is the point (rule #0 favours more escapes over
    // fewer). Re-gating `unblock` on presence alone is Task 8b's job.
    let table = [
        // (cover_presence, running, blocked_offers_go_offline, expect_go_offline, expect_unblock)
        (CoverPresence::Live, false, true, true, true),
        (CoverPresence::Live, false, false, false, true),
        (CoverPresence::Live, true, true, true, false),
        (CoverPresence::Live, true, false, false, false),
        (CoverPresence::Absent, false, true, true, false),
        (CoverPresence::Absent, false, false, false, false),
        (CoverPresence::Absent, true, true, true, false),
        (CoverPresence::Absent, true, false, false, false),
    ];
    for (cover_presence, running, blocked_offers_go_offline, expect_go_offline, expect_unblock) in table {
        let escapes = escape_items(cover_presence, running, blocked_offers_go_offline);
        assert_eq!(
            escapes,
            EscapeItems {
                go_offline: expect_go_offline,
                unblock: expect_unblock,
            },
            "cover_presence={cover_presence:?} running={running} blocked_offers_go_offline={blocked_offers_go_offline}"
        );
    }
}

#[skuld::test]
fn an_unreachable_probe_keeps_the_escape_offered() {
    // A probe that could not determine the truth must never resolve toward
    // "nothing is blocking" — Indeterminate and Unreachable both keep the
    // unblock escape offered (with no session running), same as a confirmed
    // Live/Recorded cover.
    for presence in [CoverPresence::Indeterminate, CoverPresence::Unreachable] {
        let escapes = escape_items(presence, false, false);
        assert!(
            escapes.unblock,
            "an uncertain probe ({presence:?}) must still offer the unblock escape"
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

fn status_resp(running: bool) -> BridgeResponse {
    BridgeResponse::Status {
        running,
        uptime_secs: 0,
        error: None,
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        cover_presence: CoverPresence::Absent,
        blocked_until_connected: false,
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

// Structural guard ====================================================================================================

/// #979: the startup-connect decision moved to the bridge
/// (`hole_bridge::target::startup_should_connect`) and the GUI's own copy was
/// deleted, not left dormant. Same idiom as
/// `the_standing_cover_field_has_exactly_one_reader`: a name reappearing in
/// non-test GUI source would mean a second decider crept back in.
#[skuld::test]
fn the_gui_no_longer_decides() {
    let needle = "startup_should_connect";
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut matches: Vec<(String, usize, String)> = Vec::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/hole/src");
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (line_no, line) in text.lines().enumerate() {
            if line.contains(needle) {
                matches.push((path.display().to_string(), line_no + 1, line.trim().to_string()));
            }
        }
    }

    assert!(
        matches.is_empty(),
        "the_gui_no_longer_decides: `{needle}` must not appear in non-test GUI sources \
         (skipping *_tests.rs) — it belongs to the bridge alone now (#979).\n\
         Matches found ({}):\n{}",
        matches.len(),
        matches
            .iter()
            .map(|(file, line_no, line)| format!("  {file}:{line_no}: {line}\n"))
            .collect::<String>()
    );
}
