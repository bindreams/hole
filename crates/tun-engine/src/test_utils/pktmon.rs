//! The wire oracle for an unconnected UDP `send_to`: an in-box `pktmon`
//! capture keyed on a per-marker payload nonce.
//!
//! [`super::ProbeFate::Delivered`] is sound for a completed TCP handshake —
//! no firewall drop can manufacture one — but not for `send_to` on a bound,
//! unconnected UDP socket: the kernel accepts the datagram for transmission
//! whether or not a firewall cover then drops it at `ALE_AUTH_CONNECT`, so
//! `Ok` from that call looks identical to a successfully blocked send. The
//! capture, not the return value, is the authority on what left the box.
//!
//! Windows-only: `pktmon` has no cross-platform equivalent, and macOS's BPF
//! tap sits upstream of `pf`, so an en0 capture there would record packets
//! `pf` later drops — an unsound proof on that platform by construction (see
//! `crates/bridge/tests/cutover_nic_capture_privileged.rs`'s module doc).
//!
//! Shared by `tun-engine`'s own `dns_confine` privileged tests and
//! `hole-bridge`'s `cutover_nic_capture_privileged.rs` so the two crates
//! cannot drift — see this crate's `test_utils` module doc.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

/// Run a `pktmon` subcommand, failing loud on a non-zero exit. `pktmon` is the
/// proof's measurement apparatus — a missing or broken pktmon must FAIL the
/// test, never silently skip it.
pub fn pktmon(args: &[&str]) -> std::process::Output {
    let out = Command::new("pktmon")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("pktmon is the measurement apparatus and must be present: spawn {args:?}: {e}"));
    assert!(
        out.status.success(),
        "pktmon {args:?} failed ({}): stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

/// RAII guard that always tears down the live pktmon session and filters, so a
/// panicking assertion never leaves a capture running or filters installed on
/// the runner. Mirrors the cover guard / EtwGuard discipline.
///
/// `stop` ends the capture, `filter remove` clears the filter set (`reset` only
/// zeroes counters, so it does NOT remove filters), `reset` clears counters as a
/// final tidy. Best-effort: Drop must not panic, so failures are swallowed here —
/// the positive assertions live in the test body.
pub struct PktmonGuard;

impl Drop for PktmonGuard {
    fn drop(&mut self) {
        for args in [
            ["stop"].as_slice(),
            ["filter", "remove"].as_slice(),
            ["reset"].as_slice(),
        ] {
            let _ = Command::new("pktmon").args(args).output();
        }
    }
}

/// Send `nonce` followed by 16 zero filler bytes (a 32-byte datagram) to `dst`
/// from the bound `socket`. The nonce is the wire fingerprint matched in the
/// capture.
///
/// A bound, unconnected UDP `send_to` does no handshake: the datagram either
/// egresses (and is captured) or is dropped at `ALE_AUTH_CONNECT` by a cover.
/// `send_to` returning `Ok` means the kernel accepted it for transmission, not
/// that WFP let it leave — the capture is the authority on what left.
pub fn send_marker(
    rt: &tokio::runtime::Runtime,
    socket: &tokio::net::UdpSocket,
    dst: SocketAddr,
    nonce: [u8; 16],
) -> std::io::Result<()> {
    let mut payload = [0u8; 32];
    payload[..16].copy_from_slice(&nonce);
    rt.block_on(socket.send_to(&payload, dst)).map(|_| ())
}

/// Whether the pktmon capture contains `nonce` anywhere in its bytes. The pktmon
/// filter scopes the capture to UDP, the nonce is the leading 16 bytes of our UDP
/// payload, and pktmon logs the full frame verbatim (`--pkt-size 0`), so the
/// nonce appears contiguously in the file iff its packet was captured. A 16-byte
/// random nonce cannot alias unrelated bytes, so a raw scan is sound — and it
/// sidesteps both the pcapng-block quirks that trip strict pure-Rust pcapng
/// parsers on pktmon output and any link-layer (Ethernet II vs raw IP) assumption.
pub fn capture_contains_nonce(pcapng: &Path, nonce: [u8; 16]) -> bool {
    let bytes = std::fs::read(pcapng)
        .unwrap_or_else(|e| panic!("pktmon must have produced the capture {}: {e}", pcapng.display()));
    bytes.windows(16).any(|w| w == nonce)
}

/// Generate a fresh random 16-byte nonce per marker so two markers in one
/// capture never collide and a stale prior-run capture can never match.
pub fn nonce() -> [u8; 16] {
    use rand::RngExt;
    rand::rng().random::<[u8; 16]>()
}
