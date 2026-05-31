//! Process-stdout sitrep emission for the galoshes binary.
//!
//! galoshes is spawned by the bridge as a `BinaryPlugin` and the bridge
//! reads sitrep events from galoshes' **process stdout**. Internally
//! galoshes builds its own `garter::ChainRunner` over a 2-plugin chain
//! (`YamuxPlugin` outer + embedded `ex-ray` inner); that runner's
//! `on_ready` channel fires the chain-level outcome. This module maps that
//! chain-level outcome onto the PROCESS-level sitrep event galoshes emits
//! on stdout.
//!
//! The mapping logic is split out here (rather than living inline in
//! `main.rs`) so it is unit-testable without spawning the binary or
//! requiring the embedded ex-ray binary to be present.

use std::io::Write as _;

use garter::{ChainReady, SitrepEvent, StartError, Transports};

/// The transports galoshes advertises end-to-end on its process-stdout
/// `ready` event.
///
/// **This is deliberately NOT the inner chain's transport intersection.**
/// galoshes' whole purpose is to carry UDP-over-YAMUX: its outer
/// `YamuxPlugin` hop serves TCP *and* UDP, while the embedded ex-ray
/// inner hop is a TCP-only SIP003 transport (it reports `TCP` via the
/// tier-2 probe). The naive chain intersection (`YamuxPlugin` TCP|UDP ∩
/// ex-ray TCP = TCP) would therefore lose galoshes' UDP capability. But the
/// ex-ray hop being TCP-only is an implementation detail *below* galoshes'
/// abstraction: galoshes frames UDP datagrams over a YAMUX stream and the
/// inner TCP hop carries them transparently. galoshes is precisely the
/// component that ADDS UDP capability, so it reports its own true
/// end-to-end capability (TCP|UDP), a constant, to the bridge.
///
/// The bridge's UDP-drop policy reads this value
/// (`transports.contains(UDP)`) to decide whether to allow proxied UDP, so
/// reporting the naive intersection here would make the bridge wrongly
/// drop UDP that galoshes can in fact carry.
pub const GALOSHES_TRANSPORTS: Transports = Transports::TCP.union(Transports::UDP);

/// Map galoshes' internal `ChainRunner::on_ready` outcome to the
/// process-stdout sitrep event galoshes emits for the bridge.
///
/// On `Ok(ChainReady)` the forwarded `listen` is the real outer bind
/// address (correct to forward), but the forwarded `transports` is
/// [`GALOSHES_TRANSPORTS`] — galoshes' own capability — NOT
/// `chain_ready.transports`. See [`GALOSHES_TRANSPORTS`] for why.
///
/// On `Err(StartError)` the typed start failure maps 1:1 to the
/// corresponding sitrep event.
pub fn chain_result_to_event(result: Result<ChainReady, StartError>) -> SitrepEvent {
    match result {
        Ok(chain_ready) => SitrepEvent::Ready {
            listen: chain_ready.listen,
            // Override: galoshes' end-to-end capability, not the inner
            // chain intersection. See GALOSHES_TRANSPORTS.
            transports: GALOSHES_TRANSPORTS,
        },
        Err(StartError::BindConflict { errno, addr }) => SitrepEvent::BindConflict { errno, addr },
        Err(StartError::Fatal { detail, errno }) => SitrepEvent::Fatal { detail, errno },
    }
}

/// Emit a sitrep event as one JSON line on **process stdout**, then flush.
///
/// Mirrors mock-plugin's `emit`. Flushing matters because the bridge reads
/// galoshes' stdout line-by-line; an unflushed `ready` would leave the
/// bridge blocked waiting for readiness that has already happened.
pub fn emit(ev: &SitrepEvent) {
    println!("{}", serde_json::to_string(ev).expect("serialize sitrep event"));
    let _ = std::io::stdout().flush();
}
