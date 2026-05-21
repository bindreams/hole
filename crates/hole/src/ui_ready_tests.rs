use std::sync::Arc;

use super::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

#[skuld::test]
fn signal_before_wait_returns_immediately() {
    rt().block_on(async {
        let ui = Arc::new(UiReady::default());
        ui.signal(UiReadyResult { ok: true, error: None });
        let result = ui.wait().await;
        assert_eq!(result, UiReadyResult { ok: true, error: None });
    });
}

#[skuld::test]
fn signal_and_wait_compose_regardless_of_order() {
    // Tokio's task scheduling determines whether `ui2.wait().await`
    // parks before `ui.signal(...)` fires or after. Either ordering
    // must yield the correct value; this test only asserts the
    // behavior on a successful interleave, not the ordering itself.
    // The `signal_before_wait_returns_immediately` test exercises the
    // signal-first path explicitly.
    rt().block_on(async {
        let ui = Arc::new(UiReady::default());
        let ui2 = Arc::clone(&ui);
        let waiter = tokio::spawn(async move { ui2.wait().await });
        ui.signal(UiReadyResult {
            ok: false,
            error: Some("init blew up".into()),
        });
        let result = waiter.await.unwrap();
        assert_eq!(
            result,
            UiReadyResult {
                ok: false,
                error: Some("init blew up".into())
            }
        );
    });
}

#[skuld::test]
fn multiple_waiters_all_wake() {
    rt().block_on(async {
        let ui = Arc::new(UiReady::default());
        let ui2 = Arc::clone(&ui);
        let ui3 = Arc::clone(&ui);
        let w1 = tokio::spawn(async move { ui2.wait().await });
        let w2 = tokio::spawn(async move { ui3.wait().await });
        ui.signal(UiReadyResult { ok: true, error: None });
        let r1 = w1.await.unwrap();
        let r2 = w2.await.unwrap();
        assert_eq!(r1, UiReadyResult { ok: true, error: None });
        assert_eq!(r2, UiReadyResult { ok: true, error: None });
    });
}

#[skuld::test]
fn second_signal_overwrites_latched_value() {
    rt().block_on(async {
        let ui = Arc::new(UiReady::default());
        ui.signal(UiReadyResult { ok: true, error: None });
        let early = ui.wait().await;
        ui.signal(UiReadyResult {
            ok: false,
            error: Some("late".into()),
        });
        let late = ui.wait().await;
        assert_eq!(early, UiReadyResult { ok: true, error: None });
        assert_eq!(
            late,
            UiReadyResult {
                ok: false,
                error: Some("late".into())
            }
        );
    });
}
