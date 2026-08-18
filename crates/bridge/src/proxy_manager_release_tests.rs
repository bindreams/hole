//! Tests for `ProxyManager::turn_lockdown_off` — the whole feature's only
//! stateful decision (the single `running` condition, the ordering that keeps
//! the tray's escape available across a failed release, and the drop of a
//! held transient guard before the OS-level clear). Reuses the mocks and
//! constructors from the sibling `proxy_manager_tests` module rather than
//! redefining them.

// `CancellationToken::new` is the test harness's root signal here, matching
// the sanctioned-test-file exception in `proxy_manager_tests.rs` (clippy.toml's
// "Bridge cancellation contract" carve-out).
#![allow(clippy::disallowed_methods)]

use super::proxy_manager_tests::{rt, test_config, MockProxy, MockRouting, MockRoutingState};
use super::*;
use crate::proxy::ProxyError;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tun_engine::routing::failclosed::lockdown_state;

/// A covered start that fails deterministically (a closed loopback port with
/// the DNS forwarder self-test gate enabled, which `MockProxy` cannot
/// satisfy), leaving the transient cover held. Mirrors
/// `proxy_manager_tests::self_test::covered_gate_setup`.
async fn covered_start_holding_the_cover(
    dir: &tempfile::TempDir,
) -> (ProxyManager<MockProxy, MockRouting>, Arc<MockRoutingState>) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = probe.local_addr().unwrap();
    drop(probe);

    let routing = MockRouting::new(dir.path().to_path_buf());
    let st = routing.state();
    lockdown_state::set_enabled(dir.path(), false, None).unwrap();
    let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
    let mut cfg = test_config();
    cfg.server.server = closed.ip().to_string();
    cfg.server.server_port = closed.port();
    cfg.dns.enabled = true;
    cfg.dns.servers = vec!["127.0.0.1".parse().unwrap()];

    pm.start_cancellable(&cfg, true, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        pm.blocked_until_connected(),
        "setup: the failed covered start must hold the cover"
    );
    (pm, st)
}

#[skuld::test]
fn turn_lockdown_off_records_the_intent_without_clearing_while_a_session_runs() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        pm.start(&test_config()).await.unwrap();

        let outcome = pm.turn_lockdown_off().expect("a running session must not error");
        assert!(matches!(outcome, LockdownOffOutcome::SessionRunning));
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            0,
            "a running session owns its own cover; release_all_covers must not fire"
        );
        assert!(
            !lockdown_state::load_enabled(dir.path()),
            "the intent must still be recorded as off"
        );

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn turn_lockdown_off_reports_an_unsaved_intent_while_a_session_runs() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        // No `.with_state_dir(..)`: the persist fails even though a session
        // is running (there is no cover to clear either way).
        let mut pm = ProxyManager::new(MockProxy::new(), routing);
        pm.start(&test_config()).await.unwrap();

        let err = pm
            .turn_lockdown_off()
            .expect_err("an unpersistable intent must still be reported");
        assert!(
            matches!(err, ProxyError::LockdownIntentNotPersisted),
            "must be the SAME distinguishable error the Cleared branch uses, not an opaque \
             ProxyError::Runtime the IPC layer's generic 500 path can't tell apart from a failed release: {err:?}"
        );
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            0,
            "a running session owns its own cover; release_all_covers must not fire"
        );

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn turn_lockdown_off_clears_covers_then_turns_the_intent_off() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());

        let outcome = pm.turn_lockdown_off().expect("a clean, idle manager must not error");
        assert!(matches!(outcome, LockdownOffOutcome::Cleared));
        assert_eq!(st.release_all_calls.load(Ordering::SeqCst), 1);
        assert!(!lockdown_state::load_enabled(dir.path()));
    });
}

#[skuld::test]
fn turn_lockdown_off_failure_leaves_the_intent_on() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        st.fail_release.store(true, Ordering::SeqCst);
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());

        let err = pm.turn_lockdown_off().expect_err("a failed release must be reported");
        assert!(!matches!(err, ProxyError::LockdownIntentNotPersisted));
        assert!(
            lockdown_state::load_enabled(dir.path()),
            "the intent must stay ON: flipping it off over a still-held cover would hide the tray escape"
        );
    });
}

#[skuld::test]
fn turn_lockdown_off_reports_an_unsaved_intent_distinctly_from_a_failed_release() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        // No `.with_state_dir(..)`: `set_lockdown_intent` hits its existing
        // no-state_dir error path even though the release itself succeeds.
        let mut pm = ProxyManager::new(MockProxy::new(), routing);

        let err = pm
            .turn_lockdown_off()
            .expect_err("an unpersistable intent must still be reported");
        assert!(
            matches!(err, ProxyError::LockdownIntentNotPersisted),
            "must be distinguishable from a failed release: {err:?}"
        );
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            1,
            "the release itself succeeded; only the persist failed"
        );
    });
}

#[skuld::test]
fn turn_lockdown_off_drops_a_held_transient_cover() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (mut pm, st) = covered_start_holding_the_cover(&dir).await;
        assert_eq!(st.cover_disengage_calls.load(Ordering::SeqCst), 0);

        let outcome = pm
            .turn_lockdown_off()
            .expect("clearing a held transient cover must not error");
        assert!(matches!(outcome, LockdownOffOutcome::Cleared));
        assert_eq!(
            st.cover_disengage_calls.load(Ordering::SeqCst),
            1,
            "the held guard's Drop must run before the OS-level clear"
        );
        assert_eq!(st.release_all_calls.load(Ordering::SeqCst), 1);
        assert!(
            !pm.blocked_until_connected(),
            "the held guard must be gone once turn_lockdown_off returns"
        );
    });
}

#[skuld::test]
fn turn_lockdown_off_on_a_clean_manager_is_ok() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());

        let outcome = pm.turn_lockdown_off().expect("a clean manager must not error");
        assert!(matches!(outcome, LockdownOffOutcome::Cleared));
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            1,
            "no presence check may skip the clear"
        );
        assert!(!lockdown_state::load_enabled(dir.path()));
    });
}
