use tun_engine::routing::{CoverPresence, CoverRecovery, Recovery};

use crate::proxy::ShadowsocksProxy;
use crate::proxy_manager::ProxyManager;
use tun_engine::routing::SystemRouting;

/// Fresh, side-effect-free manager: `ShadowsocksProxy::new()` and
/// `SystemRouting::new` are plain struct literals (no OS I/O happens until a
/// method is actually called), and `record_recovery_outcome` never calls one
/// — it only reads/writes `ProxyManager`'s own `adopted_standing_cover` field.
/// Production types are used directly rather than a mock: nothing here needs
/// mocking.
fn fresh_manager(dir: &std::path::Path) -> ProxyManager<ShadowsocksProxy, SystemRouting> {
    ProxyManager::new(ShadowsocksProxy::new(), SystemRouting::new(dir.to_path_buf(), None))
}

fn recovery(action: CoverRecovery, presence: CoverPresence) -> Recovery {
    Recovery {
        action,
        record_intent_on: false,
        presence,
    }
}

/// Table-driven over `record_recovery_outcome` — the exact logic
/// `recover_and_record` runs on its `Ok` arm. Covers every combination this
/// PR's finding 3 cares about: `action == Adopt` alone must NOT be read as
/// evidence of a live cover.
#[skuld::test]
async fn record_recovery_outcome_sets_the_claim_from_action_and_presence() {
    let cases = [
        (CoverRecovery::Adopt, CoverPresence::Live, true),
        (CoverRecovery::Adopt, CoverPresence::Recorded, false),
        (CoverRecovery::Adopt, CoverPresence::Indeterminate, false),
        (CoverRecovery::Sweep, CoverPresence::Live, false),
        (CoverRecovery::Sweep, CoverPresence::Recorded, false),
        (CoverRecovery::Sweep, CoverPresence::Indeterminate, false),
        (CoverRecovery::Noop, CoverPresence::Absent, false),
        (CoverRecovery::Noop, CoverPresence::Unreachable, false),
    ];
    for (action, presence, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(fresh_manager(dir.path())));
        crate::route_recovery::record_recovery_outcome(Ok(recovery(action, presence)), &proxy).await;
        assert_eq!(
            proxy.lock().await.standing_cover_adopted(),
            expected,
            "({action:?}, {presence:?}) must set the claim to {expected}"
        );
    }
}

/// The panicking-task branch: a REAL [`tokio::task::JoinError`] from an
/// actually-panicked `spawn_blocking`, not a stand-in. Starts from a manager
/// that already read `true` (as an adopted claim from an EARLIER successful
/// recovery would), so this proves the panic path does not merely fail to set
/// `true` — it is exercised over a case where leaving the prior value alone
/// would silently pass. `recover_and_record` runs exactly once per bridge
/// startup, before which the claim is always its `false` default; forcing it
/// `true` first is what makes this a real proof, not a vacuous one.
#[skuld::test]
async fn record_recovery_outcome_leaves_the_claim_false_when_the_task_panics() {
    let dir = tempfile::tempdir().unwrap();
    let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(fresh_manager(dir.path())));
    proxy.lock().await.set_standing_cover_adopted(true);

    let outcome = tokio::task::spawn_blocking(|| -> Recovery { panic!("forced panic for the test") }).await;
    assert!(outcome.is_err(), "the spawned task must have actually panicked");

    crate::route_recovery::record_recovery_outcome(outcome, &proxy).await;
    assert!(
        !proxy.lock().await.standing_cover_adopted(),
        "a panicked recovery task must leave the claim false"
    );
}

/// End-to-end through the real, unmockable `tun_engine::routing::recover_routes`
/// — not the extracted seam above. A clean host with an empty state dir
/// measures `Absent` (no elevation needed to READ) and decides `Noop`, so this
/// is the one outcome reachable without a live OS-level cover to prove
/// `recover_and_record` itself (not just its extracted logic) leaves the
/// claim false.
#[skuld::test]
async fn recover_and_record_on_a_clean_host_leaves_the_claim_false() {
    let dir = tempfile::tempdir().unwrap();
    let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(fresh_manager(dir.path())));

    crate::route_recovery::recover_and_record(dir.path(), &proxy).await;

    assert!(
        !proxy.lock().await.standing_cover_adopted(),
        "a clean host with no recorded intent must not be read as an adopted live cover"
    );
}

/// Structural guard, not a proof: it asserts `routing::recover_routes(` appears
/// exactly once in non-test bridge sources, and that the one call is in
/// `route_recovery.rs`. Three entry points (`foreground`, `platform::windows`,
/// `platform::macos`) used to call it independently and discard its verdict;
/// the escape's visibility now depends on that verdict being recorded, so a
/// fourth ungated caller would be a silent regression rather than a
/// duplication.
///
/// Two evasions it does NOT catch, both by construction: a rename of
/// `recover_routes`, and a call routed through an alias or a re-export under a
/// different path. Modeled on `proxy_manager/cover_tests.rs`'s
/// `the_standing_cover_field_has_exactly_one_reader`, which documents the same
/// class of limitation.
#[skuld::test]
fn recover_routes_has_exactly_one_bridge_caller() {
    let pattern = regex::Regex::new(r"routing::recover_routes\(").unwrap();
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

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
            "recover_routes_has_exactly_one_bridge_caller: pattern `{}` must match exactly once \
             in non-test bridge sources (skipping *_tests.rs and src/test_support/).\n\
             Matches found ({}):\n",
            pattern.as_str(),
            matches.len()
        );
        for (file, line_no, line) in &matches {
            msg.push_str(&format!("  {file}:{line_no}: {line}\n"));
        }
        msg.push_str(
            "A failure here means a caller runs startup recovery without recording its verdict \
             on the ProxyManager, so an adopted standing cover would leave the tray's Unblock \
             item hidden and the connect path unaware that a live cover names the previous run's \
             TUN. The one sanctioned caller is route_recovery::recover_and_record. A comment \
             quoting the pattern is a false positive and should be reworded.",
        );
        msg
    };

    assert_eq!(matches.len(), 1, "{}", diagnostic());
    let (file, _, _) = &matches[0];
    assert!(
        file.ends_with("route_recovery.rs"),
        "the one caller must be in route_recovery.rs:\n{}",
        diagnostic()
    );
}
