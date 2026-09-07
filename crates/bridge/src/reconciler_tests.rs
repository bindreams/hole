use super::*;
use hole_common::config::{ServerEntry, StartupBehavior};
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
        "unticking the switch releases immediately rather than waiting for stop"
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

/// Compile-time proof that [`ALL_INTENTS`] and [`ALL_PRESENCES`] below really
/// are every variant.
///
/// A hand-written array named "all" is a claim, not a fact: adding a variant
/// leaves it silently short, and the one test whose name promises full
/// coverage quietly stops providing it. These matches are exhaustive with no
/// wildcard arm, so a new variant fails to compile here — the same idiom
/// `cover_step` itself relies on.
fn assert_variant_lists_are_complete(intent: Intent, presence: CoverPresence) {
    match intent {
        Intent::On | Intent::Off | Intent::Unset | Intent::Unreadable => {}
    }
    match presence {
        CoverPresence::Live
        | CoverPresence::Recorded
        | CoverPresence::Absent
        | CoverPresence::Indeterminate
        | CoverPresence::Unreachable => {}
    }
}

const ALL_INTENTS: [Intent; 4] = [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable];
const ALL_PRESENCES: [CoverPresence; 5] = [
    CoverPresence::Live,
    CoverPresence::Recorded,
    CoverPresence::Absent,
    CoverPresence::Indeterminate,
    CoverPresence::Unreachable,
];

#[skuld::test]
fn cover_step_is_exhaustive_over_presence() {
    use CoverPresence::{Absent, Indeterminate, Live, Recorded, Unreachable};
    use CoverStep::{Engage, Hold, Release};

    // The expected answers are stated as DATA, not recomputed from the same
    // match arms `cover_step` uses. A mirror-match version of this test
    // verified the test file against itself: an edit to a `cover_step` arm,
    // mechanically copied here to make the test pass again, shipped the bug
    // green. A reader disagreeing with a row below has to argue about the
    // policy, which is the point.

    // Target::Off — the engaged block follows the target, so intent never
    // enters. One row per presence.
    let off_table: [(CoverPresence, CoverStep); 5] = [
        (Live, Release),
        (Recorded, Release),
        (Indeterminate, Release),
        (Absent, Hold),
        (Unreachable, Hold),
    ];

    // Target::Connected — `On`/`Unreadable` authorise engaging; `Off`/`Unset`
    // do not. One row per (armed, presence).
    let connected_table: [(bool, CoverPresence, CoverStep); 10] = [
        (true, Live, Hold),
        (true, Recorded, Engage),
        (true, Indeterminate, Engage),
        (true, Absent, Engage),
        (true, Unreachable, Hold),
        (false, Live, Release),
        (false, Recorded, Release),
        (false, Indeterminate, Release),
        (false, Absent, Hold),
        (false, Unreachable, Hold),
    ];

    for intent in ALL_INTENTS {
        for presence in ALL_PRESENCES {
            assert_variant_lists_are_complete(intent, presence);

            let (_, expected_off) = off_table
                .iter()
                .find(|(p, _)| *p == presence)
                .copied()
                .expect("off_table must have a row for every presence");
            assert_eq!(
                cover_step(intent, presence, &Target::Off),
                expected_off,
                "target=Off intent={intent:?} presence={presence:?}"
            );

            // Target::Unreadable authorises nothing, whatever else is true.
            assert_eq!(
                cover_step(intent, presence, &Target::Unreadable),
                Hold,
                "target=Unreadable intent={intent:?} presence={presence:?}"
            );

            let armed = matches!(intent, Intent::On | Intent::Unreadable);
            let (_, _, expected_connected) = connected_table
                .iter()
                .find(|(a, p, _)| *a == armed && *p == presence)
                .copied()
                .expect("connected_table must have a row for every (armed, presence)");
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
    // Unreadable authorises neither connect nor disconnect. A corrupt
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

        reconcile_once(dir.path(), &proxy).await;

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

        reconcile_once(dir.path(), &proxy).await;

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

/// The persisted target records what the user last connected to; the startup
/// preference records whether a boot is allowed to act on it. `DoNotConnect`
/// is the direction that must not fail open: `SessionEvent::ProcessExiting`
/// deliberately preserves a `Connected` target across a clean shutdown, so
/// without this every reboot would reconnect — and, with the switch on, arm a
/// fail-closed cover the user never asked for.
#[skuld::test]
fn a_do_not_connect_preference_overrides_a_persisted_connected_target() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();
        target::save_startup_preference(
            dir.path(),
            &target::StartupPreference {
                on_startup: StartupBehavior::DoNotConnect,
                candidate: Some(Box::new(connectable_config())),
            },
            None,
        )
        .unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let state = routing.state();
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Stopped,
            "DoNotConnect must not start a session, whatever the persisted target says"
        );
        assert_eq!(
            state.lockdown_engage_calls.load(Ordering::SeqCst),
            0,
            "DoNotConnect must not arm the standing cover either"
        );
        // The resolution is persisted, not merely applied in memory: the rest
        // of this pass and every later transition read one value, and a
        // restart cannot re-derive a different answer from a stale file.
        assert_eq!(
            target::load(dir.path()),
            Target::Off,
            "the resolved target must be written back, so the target file agrees with what was done"
        );
    });
}

/// The `AlwaysConnect` direction of the same wiring: the persisted target
/// carries no config to connect to, and the candidate pushed alongside the
/// preference is what supplies one.
#[skuld::test]
fn an_always_connect_preference_starts_the_candidate_over_an_off_target() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        target::save(dir.path(), &Target::Off, None).unwrap();
        target::save_startup_preference(
            dir.path(),
            &target::StartupPreference {
                on_startup: StartupBehavior::AlwaysConnect,
                candidate: Some(Box::new(connectable_config())),
            },
            None,
        )
        .unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "AlwaysConnect must connect the pushed candidate when the persisted target is Off"
        );
        assert_eq!(
            target::load(dir.path()),
            connectable(),
            "the substituted candidate must be written back as the target"
        );
    });
}

/// `RestoreLastState` is the default, and the two tests above would both pass
/// against a `reconcile_once` that ignored the preference entirely if the
/// default did anything other than pass the persisted target through.
#[skuld::test]
fn the_default_preference_leaves_the_persisted_target_untouched() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();
        // No preference file written at all — `load_startup_preference`
        // reads `RestoreLastState` with no candidate.

        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), &proxy).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "an absent preference must restore the persisted target"
        );
        assert_eq!(
            target::load(dir.path()),
            connectable(),
            "RestoreLastState must not rewrite the target"
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

        reconcile_once(dir.path(), &proxy).await;

        assert_eq!(
            state.lockdown_engage_calls.load(Ordering::SeqCst),
            1,
            "reconcile_once must see recovery's adopted claim — recorded before reconciliation ran — \
             and engage the standing cover even though bridge-lockdown.json itself records no intent"
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

    // (file suffix, enclosing fn) for every caller reasoned about above.
    //
    // Keyed on the FUNCTION each call sits in, not the line it sits on. The
    // invariant is which functions release covers; a line number is not it.
    // Pinning lines meant any unrelated edit above a call site — a doc
    // comment, a blank line, a `#[cfg]` — reddened this test with a
    // diagnostic indistinguishable from a real new caller, which trains
    // readers to treat its failures as routine busywork. The enclosing fn
    // changes only when the caller set actually does.
    let sanctioned: &[(&str, &str)] = &[
        ("ipc.rs", "handle_unblock"),              // deliberately bypasses `state.proxy.lock()`.
        ("proxy_manager.rs", "turn_lockdown_off"), // the explicit off-toggle.
        ("proxy_manager.rs", "apply_cover_step"),  // session-teardown's own release, ordered after routes.
        ("reconciler.rs", "reconcile_once"),       // Phase::Cover(CoverStep::Release): boot-time reconciliation.
    ];

    // The nearest `fn` declaration at or above a 1-indexed line — the
    // function a call on that line belongs to.
    fn enclosing_fn(text: &str, line_no: usize) -> String {
        let decl = regex::Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
        text.lines()
            .take(line_no)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .find_map(|l| decl.captures(l).map(|c| c[1].to_string()))
            .unwrap_or_else(|| "<none>".to_string())
    }

    let mut matches: Vec<(String, usize, String, String)> = Vec::new();
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
                matches.push((
                    path.display().to_string(),
                    line_no + 1,
                    line.trim().to_string(),
                    enclosing_fn(&text, line_no + 1),
                ));
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
        for (file, line_no, line, enclosing) in &matches {
            msg.push_str(&format!("  {file}:{line_no} (in fn {enclosing}): {line}\n"));
        }
        msg.push_str(
            "A failure here means one of three things: a new, undocumented release path was added \
             (the real defect — add it to `sanctioned` above only after writing down, next to the \
             call, why it cannot route through one of the existing four), a sanctioned call moved \
             out of the function that owned it (update `sanctioned` to match), or a comment/doc \
             string in a walked file now quotes the pattern, which is a false positive and \
             should be reworded.",
        );
        msg
    };

    assert_eq!(matches.len(), sanctioned.len(), "{}", diagnostic());
    for (file, line_no, _, enclosing) in &matches {
        let is_sanctioned = sanctioned
            .iter()
            .any(|(suffix, func)| file.ends_with(suffix) && func == enclosing);
        assert!(
            is_sanctioned,
            "unsanctioned call site: {file}:{line_no} in fn {enclosing}\n{}",
            diagnostic()
        );
    }
}
