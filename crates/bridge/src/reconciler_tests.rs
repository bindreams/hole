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

/// A root token for tests that are not exercising cancellation. Named so the
/// call sites read as "no shutdown arrived", rather than repeating the
/// `#[allow]` at each one.
fn never_cancelled() -> CancellationToken {
    #[allow(clippy::disallowed_methods)]
    // Test-side root token; production roots live at the three entry points.
    CancellationToken::new()
}

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
    use CoverPresence::{Absent, Indeterminate, Live, Recorded, Unreachable};
    use CoverStep::{Engage, Hold, Release};

    // The expected answers are DATA, not recomputed from the same match arms
    // `cover_step` uses. A mirror-match version of this test verified the test
    // file against itself: an edit to a `cover_step` arm, mechanically copied
    // here to make the test pass again, shipped green. Disagreeing with a row
    // below means arguing about the policy, which is the point.

    // Target::Off — the engaged block follows the target, so intent never
    // enters. One row per presence.
    let off_table: [(CoverPresence, CoverStep); 5] = [
        (Live, Release),
        (Recorded, Release),
        (Indeterminate, Release),
        (Absent, Hold),
        (Unreachable, Hold),
    ];

    // Target::Connected — `On`/`Unreadable` authorise engaging, `Off`/`Unset`
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

/// The variant lists the table above iterates.
///
/// An array named "all" is a claim, not a fact: adding a variant leaves it
/// silently short, and the one test whose name promises full coverage quietly
/// stops providing it. [`assert_variant_lists_are_complete`] is what makes
/// them true.
const ALL_INTENTS: [Intent; 4] = [Intent::On, Intent::Off, Intent::Unset, Intent::Unreadable];
const ALL_PRESENCES: [CoverPresence; 5] = [
    CoverPresence::Live,
    CoverPresence::Recorded,
    CoverPresence::Absent,
    CoverPresence::Indeterminate,
    CoverPresence::Unreachable,
];

/// Compile-time proof that the two lists above really are every variant:
/// wildcard-free matches, so a new variant fails to compile here — the same
/// idiom `cover_step` itself relies on. Never called; its body is the check.
#[allow(dead_code)]
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

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

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

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

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

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

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

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

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

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

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

/// Regex for a Rust function declaration, used to attribute a call site to the
/// function that lexically encloses it. A backwards line walk is a heuristic —
/// a call inside a nested `fn` attributes to the nested one (correct), a call
/// inside a closure attributes to the enclosing `fn` (correct), and a call
/// generated inside a macro body may mis-attribute (accepted: this guard fails
/// loud, so a mis-attribution surfaces as a failure to investigate, never as a
/// silent pass).
pub(crate) fn fn_decl_re() -> regex::Regex {
    regex::Regex::new(
        r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("fn-declaration regex must compile")
}

/// Every `pattern` match in `text`, as `(enclosing function name, trimmed
/// line)`. Identity is the function name, not the line number, so an edit
/// above a call site cannot change what the guard sees — the property
/// `the_sanctioned_caller_guard_survives_line_shifts` pins.
pub(crate) fn call_sites_by_function(text: &str, pattern: &regex::Regex) -> Vec<(String, String)> {
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
    // Exact paths relative to `src/`, never `ends_with` suffixes: a suffix
    // match would also bless a future `platform/ipc.rs` or `dns/reconciler.rs`.
    let sanctioned: &[(&str, &str)] = &[
        ("ipc.rs", "handle_unblock"),              // deliberately bypasses `state.proxy.lock()`.
        ("proxy_manager.rs", "turn_lockdown_off"), // the explicit off-toggle.
        ("proxy_manager.rs", "apply_cover_disposition"), // session teardown, ordered after routes.
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

    // SET equality, not count-plus-membership: two calls inside one sanctioned
    // function and none in another satisfies the latter while a whole
    // reasoned-about release path has silently disappeared. Paths are compared
    // exactly, relative to `src/`, so a suffix match cannot bless a future
    // `platform/ipc.rs`.
    let found: std::collections::BTreeSet<(String, String)> = matches
        .iter()
        .map(|(file, func, _)| {
            let rel = std::path::Path::new(file)
                .strip_prefix(&src_root)
                .unwrap_or(std::path::Path::new(file))
                .to_string_lossy()
                .replace('\\', "/");
            (rel, func.clone())
        })
        .collect();
    let expected: std::collections::BTreeSet<(String, String)> = sanctioned
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    assert_eq!(found, expected, "{}", diagnostic());
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

// Boot cancellation ===================================================================================================

/// All three of `reconcile_once`'s call sites sit in
/// startup paths that own a shutdown signal — SIGINT/SIGTERM in the
/// foreground, SCM Stop and launchd's SIGTERM in the two service paths — and
/// that signal is exactly what has nothing to reach while a boot auto-connect
/// is in flight. A token nothing else holds cannot be cancelled by anyone.
#[skuld::test]
fn a_cancelled_boot_reconcile_abandons_the_start() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        // Shutdown arrived before reconciliation reached the start — the
        // machine is going down mid-boot.
        #[allow(clippy::disallowed_methods)]
        // Test-side root token; the production roots live at the three entry points.
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        reconcile_once(dir.path(), None, &proxy, &shutdown).await;

        assert_ne!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "a cancelled shutdown token must abandon the boot auto-connect, not start a tunnel \
             the process is about to abandon"
        );
    });
}

// teardown_cover_disposition ==========================================================================================

/// Teardown's cover fate keyed on the CAUSE of the teardown, exhaustively.
///
/// `UserStopped` is the explicit user disarm and always releases. The two
/// pre-exit events hand off to whatever adopts the filters next.
/// `GaveUp` and `Blipped` defer to `cover_step` — deliberately NOT grouped
/// with `UserStopped` despite sharing its move to `Off`: giving up is the
/// SYSTEM concluding the target is unreachable, not the user asking to open
/// the host, and collapsing the two on that shared consequence is the exact
/// defect `SessionEvent`'s own doc forbids.
#[skuld::test]
fn teardown_disposition_is_exhaustive_over_events() {
    use CoverDisposition as D;
    let connected = connected();
    let table = [
        // Explicit user act: releases regardless of what the probe says.
        (
            SessionEvent::UserStopped,
            CoverPresence::Live,
            &connected,
            D::ReleaseNow,
        ),
        (
            SessionEvent::UserStopped,
            CoverPresence::Absent,
            &connected,
            D::ReleaseNow,
        ),
        (
            SessionEvent::UserStopped,
            CoverPresence::Unreachable,
            &connected,
            D::ReleaseNow,
        ),
        // A successor adopts the filters; the process is about to exit.
        (
            SessionEvent::CutoverRestart,
            CoverPresence::Live,
            &connected,
            D::KeepEngaged,
        ),
        (
            SessionEvent::ProcessExiting,
            CoverPresence::Live,
            &connected,
            D::KeepEngaged,
        ),
        // Deferred to `cover_step`: a live cover toward a still-Connected
        // target with the intent on is held, not released.
        (SessionEvent::GaveUp, CoverPresence::Live, &connected, D::KeepEngaged),
        (SessionEvent::Blipped, CoverPresence::Live, &connected, D::KeepEngaged),
        // ...and the same events release once the target no longer authorises it.
        (SessionEvent::GaveUp, CoverPresence::Live, &Target::Off, D::ReleaseNow),
        (SessionEvent::Blipped, CoverPresence::Live, &Target::Off, D::ReleaseNow),
    ];
    for (event, presence, target, expected) in table {
        assert_eq!(
            teardown_cover_disposition(event, Intent::On, presence, target),
            expected,
            "event={event:?} presence={presence:?} target={target:?}"
        );
    }

    // The intent axis, which the table above holds fixed at `On`. With the
    // kill switch OFF a live cover is stranded, and every non-`UserStopped`
    // event must sweep it — including the two pre-exit ones. Returning
    // `KeepEngaged` for those unconditionally left the host blocked with
    // nothing owning the filters, which is what this row set exists to catch.
    for event in [
        SessionEvent::CutoverRestart,
        SessionEvent::ProcessExiting,
        SessionEvent::GaveUp,
        SessionEvent::Blipped,
    ] {
        assert_eq!(
            teardown_cover_disposition(event, Intent::Off, CoverPresence::Live, &connected),
            CoverDisposition::ReleaseNow,
            "{event:?} with the kill switch off must sweep a stranded cover, not keep it engaged"
        );
    }
}

// Contract guards =====================================================================================================

/// Whether `line` DECIDES from a value rather than merely naming or
/// constructing one.
///
/// `=>` and `==`/`!=` are the obvious forms. The rest are the ones that
/// silently slipped past an earlier version of these guards: `matches!`,
/// a match arm split so a bare `Variant` sits alone on its own line (leading
/// or trailing `|`), and the three binding forms — `if let`, `while let`, and
/// let-else — which pattern-match without any of the above tokens.
pub(crate) fn line_decides(line: &str) -> bool {
    let t = line.trim();
    t.contains("=>")
        || t.contains("==")
        || t.contains("!=")
        || t.contains("matches!")
        || t.contains("if let")
        || t.contains("while let")
        || (t.starts_with("let ") && t.contains(" else"))
        || t.ends_with('|')
        || t.starts_with('|')
}

/// Strip comment lines so a doc comment naming a variant is not mistaken for
/// a decision site. Crude on purpose: it must never hide a real match arm.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().filter(|(_, l)| {
        let t = l.trim_start();
        // NOT `starts_with('*')`: that also drops real code beginning with a
        // dereference (`*cover_presence != ..`), exactly a line this guard
        // exists to catch. Block-comment interiors become a false-positive
        // source instead — a spurious failure is safe; a silently skipped
        // decision site is not.
        !t.starts_with("//") && !t.starts_with("/*")
    })
}

/// Four separate bugs in this one change had the same shape: a contract
/// stated in prose at a definition site, violated at a call site far away.
/// `SessionEvent`'s own doc says "do not collapse any two variants onto their
/// shared consequence"; the transient-cover match did exactly that, and
/// `stop_with`'s death-reason branch re-derived a per-variant policy of its
/// own. The fix is that per-variant policy lives ON the type — one exhaustive
/// match per question — and nowhere else.
///
/// Constructing a variant (`stop_with(SessionEvent::Blipped)`) is fine and
/// deliberately not matched here: a caller naming its own cause is the API
/// working. What this forbids is DECIDING from one (`=>`, `==`, `!=`).
#[skuld::test]
fn session_event_policy_lives_on_the_type_not_at_call_sites() {
    let scan_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let src_root = scan_root.clone();
    // The two exhaustive deciders, by path relative to `src/`.
    let sanctioned = ["target.rs", "reconciler.rs"];
    let mut offenders: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/bridge/src");
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Relative PATH, never a bare file name: `macos.rs` alone would
        // exempt every file of that name in the tree.
        let rel = path
            .strip_prefix(&scan_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if name.ends_with("_tests.rs") || sanctioned.contains(&rel.as_str()) {
            continue;
        }
        if path.components().any(|c| c.as_os_str() == "test_support") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (idx, line) in code_lines(&text) {
            if line.contains("SessionEvent::") && line_decides(line) {
                offenders.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "per-variant SessionEvent policy decided outside `target.rs`/`reconciler.rs`:\n  {}\n\
         Add a classifier method to `SessionEvent` (one exhaustive match, in one place) and ask \
         it here instead. A sixth variant must be a compile error once, not silently inherit a \
         group at every site that forgot it.",
        offenders.join("\n  ")
    );
}

/// The same defect shape as [`session_event_policy_lives_on_the_type_not_at_call_sites`],
/// on the other axis. `CoverPresence` carries a rule stated in prose in
/// `openapi.yaml` and in two doc comments — *"`indeterminate` and
/// `unreachable` mean the probe could not give a real answer; every
/// escape-offering site must treat them like `live`, never like `absent`"* —
/// and every site re-derived it with its own comparison.
///
/// A site that writes `== Live` silently excludes the two uncertain variants
/// and resolves an unreachable probe toward "nothing is blocking", which is
/// the one direction that must never happen. So comparisons against a variant
/// are forbidden outside the two type definitions; ask `is_present()` (or the
/// deliberately narrow `is_confirmed_live()`) instead.
///
/// Scans the whole workspace, not just this crate: there are TWO
/// `CoverPresence` types — `tun_engine::routing`'s and the generated wire type
/// — and `crates/hole` cannot depend on tun-engine, so no single decider can
/// own both. The invariant is per-type, and so is the check.
#[skuld::test]
fn cover_presence_is_never_compared_against_a_variant() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let scan_root = workspace.clone();
    // The type definitions, plus the platform modules that PRODUCE the probe
    // (they classify their own raw OS result; the invariant binds consumers).
    // Path-qualified: bare `macos.rs`/`windows.rs` exempted fourteen unrelated
    // files, including `crates/bridge/src/platform/macos.rs`.
    let sanctioned = [
        "crates/tun-engine/src/routing.rs",
        "crates/common/src/protocol.rs",
        "crates/tun-engine/src/routing/failclosed/macos.rs",
        "crates/tun-engine/src/routing/failclosed/windows.rs",
    ];
    let mut offenders: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(workspace.join("crates")) {
        let entry = entry.expect("failed to walk crates/");
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Relative PATH, never a bare file name: `macos.rs` alone would
        // exempt every file of that name in the tree.
        let rel = path
            .strip_prefix(&scan_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if name.ends_with("_tests.rs") || sanctioned.contains(&rel.as_str()) {
            continue;
        }
        if path
            .components()
            .any(|c| c.as_os_str() == "test_support" || c.as_os_str() == "target")
        {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (idx, line) in code_lines(&text) {
            if line.contains("CoverPresence::") && line_decides(line) {
                offenders.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "CoverPresence compared against a variant outside its own type definition:\n  {}\n\
         Call `is_present()` instead. Writing `== Live` by hand drops Indeterminate and \
         Unreachable, which resolves an uncertain probe toward \"nothing is blocking\" — the one \
         direction an escape-offering site must never take.",
        offenders.join("\n  ")
    );
}

/// The guards are only worth having if they FAIL on the shapes that slipped
/// past earlier versions. Asserted directly against the predicate rather than
/// by mutating real sources, so a regression in `line_decides` cannot hide
/// behind a whitelist entry.
#[skuld::test]
fn the_decision_predicate_catches_every_pattern_matching_form() {
    for line in [
        "        SessionEvent::GaveUp => CoverDisposition::ReleaseNow,",
        "    if event == SessionEvent::GaveUp {",
        "    if event != SessionEvent::GaveUp {",
        "    matches!(e, SessionEvent::GaveUp)",
        "    if let SessionEvent::GaveUp = event {",
        "    while let SessionEvent::GaveUp = next() {",
        "    let SessionEvent::GaveUp = event else { return };",
        "        SessionEvent::CutoverRestart |",
        "        | SessionEvent::ProcessExiting => x,",
    ] {
        assert!(line_decides(line), "predicate missed a decision form: {line:?}");
    }
    // Construction and naming must NOT trip it, or every call site becomes an
    // offender and the guard gets whitelisted into uselessness.
    for line in [
        "    self.stop_with(SessionEvent::UserStopped).await",
        "    Some(SessionEvent::GaveUp)",
        "        crate::target::SessionEvent::CutoverRestart",
    ] {
        assert!(!line_decides(line), "predicate flagged a construction site: {line:?}");
    }
}

// Boot auto-connect fails OPEN ========================================================================================

/// A boot auto-connect that fails must leave the host REACHABLE, not blocked.
///
/// The transient block-until-connected cover is engaged without the user ever
/// asking for a kill switch, so a bug anywhere in the connect path would strand
/// them with no network and no obvious cause. That trade is only acceptable
/// where the user opted in: with the lockdown intent ON the standing cover
/// still engages and still holds, which this test deliberately does not touch.
#[skuld::test]
fn a_failed_boot_connect_leaves_the_host_reachable() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        // Kill switch OFF — the only case where the transient cover decides
        // the outcome. With it on, the standing cover governs instead.
        lockdown_state::set_enabled(dir.path(), false, None).unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let state = routing.state();
        let pm = ProxyManager::new(MockProxy::failing_start(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));

        reconcile_once(dir.path(), None, &proxy, &never_cancelled()).await;

        assert_eq!(
            state.cover_engage_calls.load(Ordering::SeqCst),
            0,
            "a boot auto-connect must not engage the transient fail-closed cover: a failure \
             anywhere in the connect path would leave the user with no network"
        );
        assert!(
            !proxy.lock().await.blocked_until_connected(),
            "a failed boot connect must not leave the host in the blocked state"
        );
    });
}
