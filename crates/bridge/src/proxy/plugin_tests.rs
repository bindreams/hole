// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-
// test-file exception.
#![allow(clippy::disallowed_methods)]

use tokio_util::sync::CancellationToken;

use super::start_plugin_chain;

#[skuld::test]
async fn start_with_nonexistent_binary_returns_plugin_error() {
    let cancel = CancellationToken::new();
    let result = start_plugin_chain(
        "v2ray-plugin",
        "/nonexistent/binary",
        None,
        "127.0.0.1",
        12345,
        None,
        false,
        &cancel,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::proxy::ProxyError::Plugin(_)),
        "expected ProxyError::Plugin, got: {err:?}"
    );
}
