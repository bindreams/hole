//! Tests for `ProxyManager::turn_lockdown_off` — the whole feature's only
//! stateful decision (whether `cover_step` calls for a release given the
//! persisted target and OS-probed presence, the ordering that keeps the
//! tray's escape available across a failed release, and the drop of a held
//! transient guard before the OS-level clear). Reuses the mocks and
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
use tun_engine::routing::CoverPresence;

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
    cfg.server.server = closed.ip().to_string().into();
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
fn turn_lockdown_off_releases_a_stranded_cover_even_while_a_session_runs() {
    // Q4: unblock IS unticking. `cover_step` reads no session posture, so a
    // session that itself installed the standing cover (intent was On) does
    // not shield it from the escape — the persisted target defaults to `Off`
    // (no `bridge-target.json` is ever written by this ProxyManager-level
    // test), and presence reads `Live` because the session's own start
    // engaged it.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        pm.start(&test_config()).await.unwrap();

        pm.turn_lockdown_off().expect("a running session must not error");
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            1,
            "presence Live + target Off must release the cover regardless of the running session"
        );
        assert!(
            !lockdown_state::load_enabled(dir.path()),
            "the intent must be recorded as off"
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
        // No `.with_state_dir(..)`: the persist fails. `standing_cover_expected`
        // also reads no state_dir here, so this covered start engages no
        // standing cover — presence stays `Absent` and `cover_step` holds.
        let mut pm = ProxyManager::new(MockProxy::new(), routing);
        pm.start(&test_config()).await.unwrap();

        let err = pm
            .turn_lockdown_off()
            .expect_err("an unpersistable intent must still be reported");
        assert!(
            matches!(err, ProxyError::LockdownIntentNotPersisted),
            "must be the SAME distinguishable error a failed release uses, not an opaque \
             ProxyError::Runtime the IPC layer's generic 500 path can't tell apart from it: {err:?}"
        );
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            0,
            "presence Absent (no standing cover was ever installed here); cover_step must hold"
        );

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn turn_lockdown_off_clears_a_stranded_standing_cover() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        // Simulate an OS probe finding a standing cover from a prior run —
        // the realistic shape of the escape's stranded-cover case.
        *st.cover_presence.lock().unwrap() = CoverPresence::Live;
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());

        pm.turn_lockdown_off()
            .expect("a stranded cover must clear without error");
        assert_eq!(st.release_all_calls.load(Ordering::SeqCst), 1);
        assert!(!lockdown_state::load_enabled(dir.path()));
    });
}

#[skuld::test]
fn turn_lockdown_off_skips_the_release_when_presence_reads_absent() {
    // A confirmed-clean host has nothing to release; `cover_step` must hold,
    // not call `release_all_covers` for nothing to clear.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        lockdown_state::set_enabled(dir.path(), true, None).unwrap();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());

        pm.turn_lockdown_off().expect("a clean manager must not error");
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            0,
            "presence Absent; cover_step must not call release_all_covers for nothing to clear"
        );
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
        *st.cover_presence.lock().unwrap() = CoverPresence::Live;
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
        *st.cover_presence.lock().unwrap() = CoverPresence::Live;
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

        pm.turn_lockdown_off()
            .expect("clearing a held transient cover must not error");
        assert_eq!(
            st.cover_disengage_calls.load(Ordering::SeqCst),
            1,
            "the held guard's Drop must run unconditionally, before the presence check"
        );
        assert_eq!(
            st.release_all_calls.load(Ordering::SeqCst),
            0,
            "no standing cover was ever installed (a transient engage does not touch presence); \
             cover_step must not call release_all_covers for nothing left to clear"
        );
        assert!(
            !pm.blocked_until_connected(),
            "the held guard must be gone once turn_lockdown_off returns"
        );
    });
}

#[skuld::test]
fn unblock_clears_the_adopted_cover_claim() {
    // The claim is NOT a latch. Once `release_all_covers` confirms, the host is
    // open — continuing to report armed would leave the tray offering an escape
    // from a cover that is already gone, over a host that is already open.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        *st.cover_presence.lock().unwrap() = CoverPresence::Live;
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        pm.set_standing_cover_adopted(true);
        assert!(pm.lockdown_enabled());

        pm.turn_lockdown_off()
            .expect("an adopted, live cover must clear without error");
        assert_eq!(st.release_all_calls.load(Ordering::SeqCst), 1);
        assert!(!pm.lockdown_enabled(), "the claim must clear on a confirmed release");
        assert!(!pm.standing_cover_expected());
    });
}

#[skuld::test]
fn a_failed_release_keeps_the_adopted_cover_claim() {
    // The host may still be held closed, so the escape must stay on the menu
    // for a retry — the same reason the intent is not flipped on this path.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        st.fail_release.store(true, Ordering::SeqCst);
        *st.cover_presence.lock().unwrap() = CoverPresence::Live;
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        pm.set_standing_cover_adopted(true);

        pm.turn_lockdown_off().expect_err("a failed release must be reported");
        assert_eq!(
            lockdown_state::load_intent(dir.path()),
            lockdown_state::Intent::Unset,
            "the intent must be untouched by a failed release"
        );
        assert!(
            pm.lockdown_enabled(),
            "the escape must stay on the menu while the cover may still hold"
        );
    });
}

#[skuld::test]
fn unblock_during_a_session_disarms_a_promoted_adopted_switch() {
    // Rule #0 in the other direction: making the claim durable must not make
    // the kill switch unreleasable. Turning it off mid-session releases the
    // session's own stranded cover (Q4) and nothing re-promotes it once gone.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let mut pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        pm.set_standing_cover_adopted(true);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(
            lockdown_state::load_intent(dir.path()),
            lockdown_state::Intent::On,
            "setup: honouring the claim made it durable"
        );

        pm.turn_lockdown_off()
            .expect("a running session's stranded cover must still release (Q4)");
        pm.stop().await.unwrap();

        assert!(
            !pm.standing_cover_expected(),
            "the switch is off, so the next start must install nothing"
        );
        pm.start(&test_config()).await.unwrap();
        assert_eq!(
            st.lockdown_engage_calls.load(Ordering::SeqCst),
            1,
            "no standing cover may come back after the escape"
        );
        pm.stop().await.unwrap();
    });
}
