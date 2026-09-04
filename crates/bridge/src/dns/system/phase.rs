//! Fatality classification for a DNS-apply backend call, enforced by the
//! type system rather than by convention.
//!
//! Mirrors `tun_engine::routing`'s sealed `Phase`/`FatalPhase`/
//! `BestEffortPhase` split (`crates/tun-engine/src/routing.rs`): there, a
//! route command cannot be run by the wrong runner because the runner is
//! generic over a sealed trait. Before this module, `dns/system.rs` had no
//! such split — `if let Err(e) = res { warn!(…) }` was writable, and was
//! written, on the macOS apply path (bindreams/hole#868), where it means a
//! silent DNS leak rather than a cosmetic miss.
//!
//! [`run`] is the *only* place either apply function may consume a backend
//! `Result`. Writing warn-and-continue for a leak-bearing operation now
//! requires choosing [`Cosmetic`] at the call site — a visible, reviewable
//! act instead of an idiom.

use std::io;

use super::DnsError;

mod sealed {
    pub trait Sealed {}
}

/// A DNS-apply backend call's fatality class. Classification is a property
/// of the phase **type**, so pairing a call with the wrong phase is a
/// compile-time choice at the call site, not a runtime convention. Sealed:
/// the two inhabitants below are the only ones.
pub(crate) trait DnsPhase: sealed::Sealed {
    /// Whether a backend failure in this phase is expected/tolerable.
    /// `false` propagates the error; `true` logs and swallows it.
    const BEST_EFFORT: bool;
}

/// A failure here is a DNS leak: the OS keeps resolving off-tunnel while the
/// UI reports a connected, protected session. Must propagate.
pub(crate) enum LeakBearing {}

/// A failure here has no leak consequence — today, only the best-effort
/// resolver-cache flush after resolvers are already set correctly.
pub(crate) enum Cosmetic {}

impl sealed::Sealed for LeakBearing {}
impl DnsPhase for LeakBearing {
    const BEST_EFFORT: bool = false;
}

impl sealed::Sealed for Cosmetic {}
impl DnsPhase for Cosmetic {
    const BEST_EFFORT: bool = true;
}

// Classification is fixed per type, so a runtime test of it would be
// vacuous. Pinned here instead, mirroring `routing.rs`'s
// `const _: () = assert!(...)` pair — this also stops a copy-paste of one
// `impl` block onto the other from landing unnoticed.
const _: () = assert!(!<LeakBearing as DnsPhase>::BEST_EFFORT);
const _: () = assert!(<Cosmetic as DnsPhase>::BEST_EFFORT);

/// Run `f` on the blocking pool and classify its outcome by `P`.
///
/// Owns the `spawn_blocking` hop and the `JoinError` mapping — a panic or a
/// cancelled blocking task is always an anomaly, regardless of `P`, so it
/// always maps to `DnsError::Io` and always propagates. No apply site
/// spawns its own blocking task any more; this is the single place that
/// does, mirroring how `exec_one` is the single spawner in
/// `tun_engine::routing`.
///
/// `E: Into<DnsError>` — generic over the backend's own error type, not
/// hardcoded to `io::Error`, so a call whose backend returns
/// `tun_engine::dns_confine::DnsConfineError` still yields
/// `DnsError::Confine` and not a collapsed `DnsError::Io`. See
/// `proxy_manager.rs`'s match on `DnsError::Confine` for why the variant
/// must survive.
///
/// Returns `Ok(Some(t))` on success. Under [`Cosmetic`], a backend failure
/// is logged at `warn` (tagged with `op`) and returns `Ok(None)` instead of
/// propagating — the caller must treat `None` as "nothing to hold", never
/// as success with a value. Under [`LeakBearing`], a backend failure always
/// returns `Err`, so `Ok(None)` is unreachable there; call sites may
/// `.expect(...)` past the `Option` rather than threading a case that can't
/// happen.
pub(crate) async fn run<P, T, E>(
    op: &'static str,
    f: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<Option<T>, DnsError>
where
    P: DnsPhase,
    T: Send + 'static,
    E: Into<DnsError> + Send + 'static,
{
    let joined = tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| DnsError::Io(io::Error::other(e)))?;
    match joined {
        Ok(t) => Ok(Some(t)),
        Err(e) => {
            let mapped: DnsError = e.into();
            if P::BEST_EFFORT {
                tracing::warn!(op, error = %mapped, "DNS apply step failed; continuing");
                Ok(None)
            } else {
                Err(mapped)
            }
        }
    }
}

#[cfg(test)]
#[path = "phase_tests.rs"]
mod phase_tests;
