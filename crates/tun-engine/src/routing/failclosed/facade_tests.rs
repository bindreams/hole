use super::*;
use crate::routing::failclosed::luid::LuidResolver;

// A recording resolver that asserts resolve() is called (the LUID is never
// persisted, so every engage must re-resolve).
struct RecordingResolver {
    calls: std::sync::atomic::AtomicU32,
    luid: u64,
}
impl LuidResolver for RecordingResolver {
    fn resolve(&self, _alias: &str) -> Result<u64, crate::error::RoutingError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.luid)
    }
}

#[skuld::test]
fn engage_lockdown_reresolves_luid_every_call() {
    // The facade must call resolver.resolve() before building the spec — the
    // LUID is never cached. We can't run real FWPM here (#165), so this test
    // pins the resolve-then-build ordering via the pure build path exposed for
    // tests.
    let r = RecordingResolver {
        calls: std::sync::atomic::AtomicU32::new(0),
        luid: 0x99,
    };
    let spec = build_lockdown_spec_for_test(&r, "hole-tun", "203.0.113.7".parse().unwrap(), &[]);
    assert_eq!(r.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(spec.filters.iter().any(|f| matches!(
        f.condition,
        platform::Condition::LocalInterface(l) if l == 0x99
    )));
}
