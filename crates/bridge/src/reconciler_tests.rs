use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::TunnelMode;
use std::sync::atomic::Ordering;

use crate::proxy_manager::proxy_manager_tests::{MockProxy, MockRouting};
use crate::proxy_manager::ProxyState;
use crate::test_support::rt;
use tun_engine::routing::failclosed::lockdown_state;
use tun_engine::routing::{CoverRecovery, Recovery};

fn test_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "test-id".into(),
            name: "test-server".into(),
            server: "example.invalid".into(),
            server_port: 8388,
            password: "super-secret-password".into(),
            method: "aes-256-gcm".into(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        },
        local_port: 1080,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
        dns: hole_common::config::DnsConfig {
            enabled: false,
            ..hole_common::config::DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    }
}

fn connected() -> Target {
    Target::Connected {
        config: Box::new(test_config()),
    }
}

// step_order ordering =================================================================================================

#[skuld::test]
fn engaging_puts_lockdown_before_the_tunnel() {
    assert_eq!(
        step_order(CoverStep::Engage, TunnelStep::Start),
        [Phase::Cover(CoverStep::Engage), Phase::Tunnel(TunnelStep::Start)]
    );
}

#[skuld::test]
fn releasing_puts_the_tunnel_before_lockdown() {
    assert_eq!(
        step_order(CoverStep::Release, TunnelStep::Stop),
        [Phase::Tunnel(TunnelStep::Stop), Phase::Cover(CoverStep::Release)]
    );
}

// cover_step ==========================================================================================================

#[skuld::test]
fn a_connected_target_with_intent_off_never_engages() {
    let target = connected();
    assert_eq!(cover_step(Intent::Off, CoverPresence::Absent, &target), CoverStep::Hold);
}

#[skuld::test]
fn an_off_target_releases_a_live_cover() {
    assert_eq!(
        cover_step(Intent::On, CoverPresence::Live, &Target::Off),
        CoverStep::Release,
        "the engaged block follows the target, not the surviving preference"
    );
}

#[skuld::test]
fn unticking_the_switch_releases_the_block_mid_session() {
    let target = connected();
    assert_eq!(
        cover_step(Intent::Off, CoverPresence::Live, &target),
        CoverStep::Release,
        "Q4: unticking the switch releases immediately rather than waiting for stop"
    );
}

#[skuld::test]
fn an_unreachable_firewall_never_yields_release() {
    let targets = [Target::Off, connected(), Target::Unreadable];
    let intents = [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable];
    for intent in intents {
        for target in &targets {
            assert_ne!(
                cover_step(intent, CoverPresence::Unreachable, target),
                CoverStep::Release,
                "a probe that cannot reach the firewall knows nothing, so it must never yield Release \
                 (intent={intent:?}, target={target:?})"
            );
        }
    }
}

#[skuld::test]
fn cover_step_is_exhaustive_over_presence() {
    // Documents the full decision table this function encodes. One row per
    // (target-kind, intent, presence) triple; the exhaustive match inside
    // `cover_step` is what makes a missing row here a compile error instead
    // of a silently-inherited answer.
    use CoverPresence::{Absent, Indeterminate, Live, Recorded, Unreachable};
    use CoverStep::{Engage, Hold, Release};

    let intents = [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable];
    let presences = [Live, Recorded, Absent, Indeterminate, Unreachable];

    for intent in intents {
        for presence in presences {
            // Target::Off: intent never matters — the engaged block follows
            // the target, so every intent gets the same answer.
            let expected_off = match presence {
                Live | Recorded | Indeterminate => Release,
                Absent | Unreachable => Hold,
            };
            assert_eq!(
                cover_step(intent, presence, &Target::Off),
                expected_off,
                "target=Off intent={intent:?} presence={presence:?}"
            );

            // Target::Unreadable: always Hold, regardless of intent or
            // presence.
            assert_eq!(
                cover_step(intent, presence, &Target::Unreadable),
                Hold,
                "target=Unreadable intent={intent:?} presence={presence:?}"
            );

            // Target::Connected: `On`/`Unreadable` authorise engaging;
            // `Off`/`Unset` do not.
            let armed = matches!(intent, Intent::On | Intent::Unreadable);
            let expected_connected = if armed {
                match presence {
                    Live => Hold,
                    Recorded | Indeterminate | Absent => Engage,
                    Unreachable => Hold,
                }
            } else {
                match presence {
                    Live | Recorded | Indeterminate => Release,
                    Absent | Unreachable => Hold,
                }
            };
            assert_eq!(
                cover_step(intent, presence, &connected()),
                expected_connected,
                "target=Connected intent={intent:?} presence={presence:?}"
            );
        }
    }
}

// tunnel_step =========================================================================================================

#[skuld::test]
fn tunnel_step_starts_a_connected_target_with_no_live_session() {
    assert_eq!(tunnel_step(false, &connected()), TunnelStep::Start);
}

#[skuld::test]
fn tunnel_step_holds_a_live_session_toward_a_connected_target() {
    assert_eq!(tunnel_step(true, &connected()), TunnelStep::Hold);
}

#[skuld::test]
fn tunnel_step_stops_a_live_session_toward_an_off_target() {
    assert_eq!(tunnel_step(true, &Target::Off), TunnelStep::Stop);
}

#[skuld::test]
fn tunnel_step_holds_with_no_session_and_an_off_target() {
    assert_eq!(tunnel_step(false, &Target::Off), TunnelStep::Hold);
}

#[skuld::test]
fn tunnel_step_never_stops_a_session_on_an_unreadable_target() {
    // R4: Unreadable authorises neither connect nor disconnect. A corrupt
    // read while a session is live must not tear it down.
    assert_eq!(tunnel_step(true, &Target::Unreadable), TunnelStep::Hold);
    assert_eq!(tunnel_step(false, &Target::Unreadable), TunnelStep::Hold);
}

// reconcile_once ======================================================================================================

/// Unlike `test_config()`, a literal-IP server so `start_cancellable` can
/// actually run to completion against the mocks without a DoH bootstrap
/// resolver — mirrors `proxy_manager_tests::test_config`'s own reasoning.
fn connectable_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            server: "127.0.0.1".into(),
            ..test_config().server
        },
        ..test_config()
    }
}

fn connectable() -> Target {
    Target::Connected {
        config: Box::new(connectable_config()),
    }
}

#[skuld::test]
fn a_persisted_connected_target_reconciles_at_startup_with_no_gui() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let state = routing.state();
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), None, &proxy).await;

        // The tunnel started with no client ever having connected...
        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "a persisted Connected target must start the tunnel with no GUI or client involved"
        );
        // ...and the standing cover engaged, because the persisted intent is On.
        assert_eq!(
            state.lockdown_engage_calls.load(Ordering::SeqCst),
            1,
            "an On intent toward a Connected target must engage the standing cover"
        );
        // Cover-before-tunnel is `start_inner`'s own existing phase order
        // (already proven by `proxy_manager_tests`), inherited here rather
        // than re-implemented: `reconcile_once` only decides *that* both
        // happen, `start_cancellable` decides the order they happen in.
    });
}

#[skuld::test]
fn a_persisted_off_target_starts_nothing() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        target::save(dir.path(), &Target::Off, None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let state = routing.state();
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), None, &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Stopped,
            "an Off target must not start a session"
        );
        assert_eq!(
            state.lockdown_engage_calls.load(Ordering::SeqCst),
            0,
            "an Off target must not engage the standing cover"
        );
        assert_eq!(
            state.release_all_calls.load(Ordering::SeqCst),
            0,
            "no cover was present (Absent), so there is nothing to release either"
        );
    });
}

#[skuld::test]
fn startup_recovery_runs_before_reconciliation() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        // Deliberately no `bridge-lockdown.json` at all (`Intent::Unset`) —
        // only crash recovery's own adopted-claim can authorise the standing
        // cover to engage here. If `reconcile_once` read the target before
        // recovery recorded that claim (or recovery never ran first, as
        // startup must guarantee), this would stay `Hold`, not `Engage`.
        target::save(dir.path(), &connectable(), None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let state = routing.state();
        *state.cover_presence.lock().unwrap() = CoverPresence::Recorded;
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        // The exact call `route_recovery::recover_and_record` makes on its
        // `Ok` arm — driven directly, the same way `route_recovery_tests.rs`
        // does, since the real `recover_routes` free function needs
        // elevation and cannot be mocked through `Routing`.
        crate::route_recovery::record_recovery_outcome(
            Ok(Recovery {
                action: CoverRecovery::Adopt,
                record_intent_on: false,
                presence: CoverPresence::Live,
            }),
            &proxy,
        )
        .await;

        reconcile_once(dir.path(), None, &proxy).await;

        assert_eq!(
            state.lockdown_engage_calls.load(Ordering::SeqCst),
            1,
            "reconcile_once must see recovery's adopted claim — recorded before reconciliation ran — \
             and engage the standing cover even though bridge-lockdown.json itself records no intent"
        );
    });
}

#[skuld::test]
fn reconcile_once_honours_a_do_not_connect_startup_preference() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        // The user was connected when the machine went down...
        target::save(dir.path(), &connectable(), None).unwrap();
        // ...but had pushed "do not connect on startup" before that.
        target::save_startup_preference(
            dir.path(),
            &target::StartupPreference {
                on_startup: hole_common::config::StartupBehavior::DoNotConnect,
                candidate: None,
            },
            None,
        )
        .unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), None, &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Stopped,
            "DoNotConnect must suppress boot auto-connect even over a persisted Connected target"
        );
        assert_eq!(
            target::load(dir.path()),
            Target::Off,
            "DoNotConnect must durably persist Off, not merely hold it in memory for this pass"
        );
    });
}

#[skuld::test]
fn reconcile_once_honours_an_always_connect_startup_preference_with_a_candidate() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        // Nothing persisted (a fresh install, or a prior explicit stop)...
        target::save(dir.path(), &Target::Off, None).unwrap();
        // ...but the GUI pushed AlwaysConnect with the last-connected config
        // as the candidate to substitute (R8/Task 4's `candidate`).
        target::save_startup_preference(
            dir.path(),
            &target::StartupPreference {
                on_startup: hole_common::config::StartupBehavior::AlwaysConnect,
                candidate: Some(Box::new(connectable_config())),
            },
            None,
        )
        .unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), None, &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "AlwaysConnect with a pushed candidate must start the tunnel even over a persisted Off target"
        );
        assert_eq!(
            target::load(dir.path()),
            connectable(),
            "the resolved target must be durably persisted, so a later read sees what actually reconciled"
        );
    });
}

// Sanctioned release call sites =======================================================================================
//
// `release_all_covers()` is unconditional and knows nothing about cover
// state (see the module doc). The plan's own aspiration is a single caller
// in `reconciler.rs`, but that is not achievable without an on-demand/
// event-driven reconcile invocation (tracked separately, not scoped to any
// task's file list): `handle_unblock`'s own doc is explicit that its direct
// call is deliberate — it must work while a wedged teardown holds
// `state.proxy.lock()`, so it cannot route through the reconciler/manager at
// all. So this guards the WEAKER, achievable property instead: every real
// caller is one of the four independently-reasoned-about sites below, each
// with its own doc explaining why it releases directly rather than through
// the others. A fifth, undocumented caller is exactly the kind of divergent,
// re-introduced `ReleaseWarrant`-style release path this stage exists to
// prevent. Same walk pattern as `proxy_manager_tests.rs`'s
// `no_bridge_source_derives_cover_state_from_a_session`.

/// An undocumented fifth caller of `release_all_covers()` would mean a new
/// release path was added outside the four reasoned-about sites — the exact
/// kind of divergent teardown route this stage collapses cover-release onto.
#[skuld::test]
fn cover_release_has_the_known_sanctioned_caller_set() {
    let pattern = regex::Regex::new(r"release_all_covers\s*\(").unwrap();
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // (file suffix, line) for every caller reasoned about above. A real
    // caller not on this list, or one of these lines moving/disappearing
    // without the list being updated, both fail loud below.
    let sanctioned: &[(&str, usize)] = &[
        ("ipc.rs", 702),            // handle_unblock: deliberately bypasses `state.proxy.lock()`.
        ("proxy_manager.rs", 764),  // turn_lockdown_off: the explicit off-toggle.
        ("proxy_manager.rs", 2050), // apply_cover_step: session-teardown's own release, ordered after routes.
        ("reconciler.rs", 265),     // Phase::Cover(CoverStep::Release): boot-time reconciliation.
    ];

    let mut matches: Vec<(String, usize, String)> = Vec::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/bridge/src");
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
        if path.components().any(|c| c.as_os_str() == "test_support") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (line_no, line) in text.lines().enumerate() {
            if pattern.is_match(line) {
                matches.push((path.display().to_string(), line_no + 1, line.trim().to_string()));
            }
        }
    }

    let diagnostic = || {
        let mut msg = format!(
            "cover_release_has_the_known_sanctioned_caller_set: pattern `{}` must match \
             only at the {} known sanctioned call sites in non-test bridge sources (skipping \
             *_tests.rs and src/test_support/).\nMatches found ({}):\n",
            pattern.as_str(),
            sanctioned.len(),
            matches.len()
        );
        for (file, line_no, line) in &matches {
            msg.push_str(&format!("  {file}:{line_no}: {line}\n"));
        }
        msg.push_str(
            "A failure here means one of three things: a new, undocumented release path was added \
             (the real defect — add it to `sanctioned` above only after writing down, next to the \
             call, why it cannot route through one of the existing four), a sanctioned call moved \
             lines (update `sanctioned` to match), or a comment/doc string in a walked file now \
             quotes the pattern, which is a false positive and should be reworded.",
        );
        msg
    };

    assert_eq!(matches.len(), sanctioned.len(), "{}", diagnostic());
    for (file, line_no, _) in &matches {
        let is_sanctioned = sanctioned
            .iter()
            .any(|(suffix, line)| file.ends_with(suffix) && line == line_no);
        assert!(
            is_sanctioned,
            "unsanctioned call site: {file}:{line_no}\n{}",
            diagnostic()
        );
    }
}
