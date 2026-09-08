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
/// Regex for a Rust function declaration, used to attribute a call site to the
/// function that lexically encloses it. A backwards line walk is a heuristic —
/// a call inside a nested `fn` attributes to the nested one (correct), a call
/// inside a closure attributes to the enclosing `fn` (correct), and a call
/// generated inside a macro body may mis-attribute (accepted: this guard fails
/// loud, so a mis-attribution surfaces as a failure to investigate, never as a
/// silent pass).
fn fn_decl_re() -> regex::Regex {
    regex::Regex::new(
        r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("fn-declaration regex must compile")
}

/// Every `pattern` match in `text`, as `(enclosing function name, trimmed
/// line)`. Identity is the function name, not the line number, so an edit
/// above a call site cannot change what the guard sees — the property
/// `the_sanctioned_caller_guard_survives_line_shifts` pins.
fn call_sites_by_function(text: &str, pattern: &regex::Regex) -> Vec<(String, String)> {
    let decl = fn_decl_re();
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if !pattern.is_match(line) {
            continue;
        }
        let name = (0..=idx)
            .rev()
            .find_map(|i| decl.captures(lines[i]).map(|c| c[1].to_string()))
            .unwrap_or_else(|| "<no enclosing fn>".to_string());
        out.push((name, line.trim().to_string()));
    }
    out
}

/// An undocumented fifth caller of `release_all_covers()` would mean a new
/// release path was added outside the four reasoned-about sites — the exact
/// kind of divergent teardown route this stage collapses cover-release onto.
#[skuld::test]
fn cover_release_has_the_known_sanctioned_caller_set() {
    let pattern = regex::Regex::new(r"release_all_covers\s*\(").unwrap();
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // (file suffix, enclosing fn) for every caller reasoned about above.
    // Anchored on the function, NOT the line: an unrelated edit above a call
    // must not fail this guard, because the only tempting repair for that is
    // to bump the number, which re-blesses whatever moved into the old slot.
    let sanctioned: &[(&str, &str)] = &[
        ("ipc.rs", "handle_unblock"),              // deliberately bypasses `state.proxy.lock()`.
        ("proxy_manager.rs", "turn_lockdown_off"), // the explicit off-toggle.
        ("proxy_manager.rs", "apply_cover_step"),  // session teardown, ordered after routes.
        ("reconciler.rs", "reconcile_once"),       // boot-time reconciliation.
    ];

    let mut matches: Vec<(String, String, String)> = Vec::new();
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
        for (func, line) in call_sites_by_function(&text, &pattern) {
            matches.push((path.display().to_string(), func, line));
        }
    }

    let diagnostic = || {
        let mut msg = format!(
            "cover_release_has_the_known_sanctioned_caller_set: pattern `{}` must match \
             only inside the {} known sanctioned functions in non-test bridge sources (skipping \
             *_tests.rs and src/test_support/).\nMatches found ({}):\n",
            pattern.as_str(),
            sanctioned.len(),
            matches.len()
        );
        for (file, func, line) in &matches {
            msg.push_str(&format!("  {file} fn {func}: {line}\n"));
        }
        msg.push_str(
            "A failure here means one of three things: a new, undocumented release path was added \
             (the real defect — add it to `sanctioned` above only after writing down, next to the \
             call, why it cannot route through one of the existing four), a sanctioned call was \
             renamed or removed (update `sanctioned` to match), or a comment/doc string in a walked \
             file now quotes the pattern, which is a false positive and should be reworded.",
        );
        msg
    };

    assert_eq!(matches.len(), sanctioned.len(), "{}", diagnostic());
    for (file, func, _) in &matches {
        let is_sanctioned = sanctioned
            .iter()
            .any(|(suffix, name)| file.ends_with(suffix) && name == func);
        assert!(
            is_sanctioned,
            "unsanctioned call site: {file} fn {func}\n{}",
            diagnostic()
        );
    }
}

// Line-shift resilience ===============================================================================================

/// `cover_release_has_the_known_sanctioned_caller_set` pins its whitelist by
/// enclosing function name rather than by line number. Line numbers made the
/// guard fail on every unrelated edit above a sanctioned call, and the
/// tempting repair — bumping the numbers — silently re-blesses whatever moved
/// into the old position. This asserts the property that repair-by-renumber
/// destroyed: shifting a call site's line must not change its identity.
#[skuld::test]
fn the_sanctioned_caller_guard_survives_line_shifts() {
    let src = "fn alpha() {\n    something();\n}\n\nfn beta() {\n    routing.release_all_covers()?;\n}\n";
    let shifted = "fn alpha() {\n    something();\n}\n\n// an unrelated comment\n\nfn beta() {\n    routing.release_all_covers()?;\n}\n";

    let pattern = regex::Regex::new(r"release_all_covers\s*\(").unwrap();
    let before = call_sites_by_function(src, &pattern);
    let after = call_sites_by_function(shifted, &pattern);

    assert_eq!(before.len(), 1, "expected exactly one call site, got {before:?}");
    assert_eq!(
        before, after,
        "a line shift changed the guard's view of the call site: {before:?} vs {after:?}"
    );
    assert_eq!(before[0].0, "beta", "call site attributed to the wrong function");
}

/// A call inside a closure belongs to the function that lexically encloses the
/// closure — there is no `fn` declaration to find in between, so the backwards
/// walk must not stop early or attribute it to the previous function.
#[skuld::test]
fn a_call_inside_a_closure_belongs_to_its_enclosing_function() {
    let src = "fn alpha() {\n    noop();\n}\n\nasync fn gamma() {\n    let f = || {\n        routing.release_all_covers()?;\n    };\n}\n";
    let pattern = regex::Regex::new(r"release_all_covers\s*\(").unwrap();
    let sites = call_sites_by_function(src, &pattern);
    assert_eq!(sites.len(), 1, "expected exactly one call site, got {sites:?}");
    assert_eq!(sites[0].0, "gamma", "closure body attributed to the wrong function");
}
