use std::io;

use super::{run, Cosmetic, LeakBearing};
use crate::dns::system::DnsError;

/// A [`LeakBearing`] failure is a DNS leak — it must propagate, never be
/// swallowed. The production regression this guards: `apply_macos` today
/// (pre-Task-3) writes `if let Err(e) = res { warn!(…) }` for exactly this
/// shape of call; under `LeakBearing` that idiom cannot compile-and-pass
/// this test, because `run` itself performs the propagation.
#[skuld::test]
async fn leak_bearing_propagates_the_backend_error() {
    let result: Result<Option<()>, DnsError> =
        run::<LeakBearing, _, _>("test-op", || Err::<(), io::Error>(io::Error::other("backend failed"))).await;

    assert!(
        matches!(result, Err(DnsError::Io(_))),
        "expected Err(Io(_)), got {result:?}"
    );
}

/// A [`Cosmetic`] failure has no leak consequence — logged and swallowed,
/// never propagated.
#[skuld::test]
async fn cosmetic_swallows_the_backend_error() {
    let result: Result<Option<()>, DnsError> = run::<Cosmetic, _, _>("test-op", || {
        Err::<(), io::Error>(io::Error::other("cache flush failed"))
    })
    .await;

    assert!(matches!(result, Ok(None)), "expected Ok(None), got {result:?}");
}

/// Both phases still carry a real success value through on `Ok`, regardless
/// of fatality class — `run` only changes behavior on the `Err` arm.
#[skuld::test]
async fn both_phases_return_the_success_value() {
    let leak_bearing: Result<Option<u32>, DnsError> = run::<LeakBearing, _, io::Error>("test-op", || Ok(7)).await;
    let cosmetic: Result<Option<u32>, DnsError> = run::<Cosmetic, _, io::Error>("test-op", || Ok(7)).await;

    assert!(
        matches!(leak_bearing, Ok(Some(7))),
        "expected Ok(Some(7)), got {leak_bearing:?}"
    );
    assert!(
        matches!(cosmetic, Ok(Some(7))),
        "expected Ok(Some(7)), got {cosmetic:?}"
    );
}

// Phase classification ================================================================================================
//
// Nothing to test at runtime here, mirroring `routing_tests.rs`'s identical
// note for `FatalPhase`/`BestEffortPhase`: which phase is best-effort is a
// `const` already pinned by `phase.rs`'s own `const _: () = assert!(...)`
// pair, so a `#[skuld::test]` over it would be vacuous
// (clippy::assertions_on_constants) — it can only ever pass, at compile
// time, before any test binary runs.

/// The guard against collapsing a backend's own error variant into
/// `DnsError::Io`: a closure returning `DnsConfineError` must yield
/// `DnsError::Confine`, which is exactly the variant
/// `proxy_manager.rs:1805-1810` matches on to decide the start aborted on
/// confinement specifically (as opposed to any other DNS-apply failure).
/// Windows-only: `DnsConfineError` and `DnsError::Confine` exist only on
/// that platform.
#[cfg(target_os = "windows")]
#[skuld::test]
async fn run_preserves_the_backend_error_variant() {
    let result: Result<Option<()>, DnsError> = run::<LeakBearing, _, _>("confine", || {
        Err::<(), tun_engine::dns_confine::DnsConfineError>(tun_engine::dns_confine::DnsConfineError::EngineOpen(
            io::Error::other("mock engine-open failure"),
        ))
    })
    .await;

    assert!(
        matches!(result, Err(DnsError::Confine(_))),
        "expected Err(Confine(_)), got {result:?}"
    );
}
