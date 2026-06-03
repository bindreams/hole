//! Tests for the native-crash observability module.

// Smoke test: the crate compiles and the public API is reachable. Replaced
// with real per-fault-class + sweep tests in later tasks.
#[skuld::test]
fn module_is_linkable() {
    // `attach` and `sweep` are the public surface; reference them so a
    // broken signature fails to compile here rather than at a call site.
    let _attach: fn(&'static str, &std::path::Path) = crate::attach;
    let _sweep: fn(&std::path::Path) = crate::sweep;
}
