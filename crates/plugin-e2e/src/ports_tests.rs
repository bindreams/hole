use super::*;

/// Smoke test on the seam's shape only — it does not, and cannot, assert
/// anything about reservation width. A port free for one transport is
/// almost always free for the rest, so a width assertion here would pass
/// against the unfixed allocator too.
#[skuld::test]
fn reserve_ss_local_returns_a_concrete_loopback_address() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = rt.block_on(reserve_ss_local()).expect("reserve_ss_local");
    assert!(addr.ip().is_loopback(), "must be loopback: {addr}");
    assert_ne!(addr.port(), 0, "must be a concrete port: {addr}");
}
