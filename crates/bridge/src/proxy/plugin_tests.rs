use super::start_plugin_chain;

#[skuld::test]
async fn start_with_nonexistent_binary_returns_plugin_error() {
    let result = start_plugin_chain("/nonexistent/binary", None, "127.0.0.1", 12345, None).await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::proxy::ProxyError::Plugin(_)),
        "expected ProxyError::Plugin, got: {err:?}"
    );
}
