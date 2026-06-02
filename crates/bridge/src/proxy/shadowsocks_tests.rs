//! Unit tests for `ShadowsocksRunning`'s lifecycle, focused on the
//! Drop contract: dropping a wrapper that still owns a live ss task
//! must NOT panic — RAII-unwind paths drop it between
//! `proxy.start().await` and the next `?` in `start_inner`.

use super::ShadowsocksRunning;
use crate::proxy::{ProxyError, RunningProxy};
use std::io;

#[skuld::test]
async fn drop_does_not_panic_when_handle_alive() {
    // A task that pends forever stands in for a freshly-spawned
    // shadowsocks server: it is unambiguously not finished by the
    // time we drop the wrapper.
    let handle = tokio::spawn(std::future::pending::<io::Result<()>>());
    let running = ShadowsocksRunning::from_handle(handle);
    drop(running); // must not panic
}

#[skuld::test]
async fn stop_then_drop_is_no_op() {
    let handle = tokio::spawn(async { Ok::<(), io::Error>(()) });
    let running = ShadowsocksRunning::from_handle(handle);
    let res: Result<(), ProxyError> = running.stop().await;
    res.expect("stop returns Ok on a clean exit");
    // `stop` consumed `running`; nothing to assert beyond "didn't
    // panic" — included as a regression guard so a future change that
    // moves cleanup state out of `stop` triggers a visible failure.
}
