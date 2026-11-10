//! Privileged-lane MEASUREMENT of bindreams/hole#1075: do the fail-closed covers drop the host's own
//! DHCP lease renewal or IPv6 neighbor discovery?
//!
//! Neither cover has a rule for either. If the OS sends them through the filter, a kill switch held
//! longer than the DHCP lease lets the physical adapter lose its address. Each test arms one cover
//! for real, forces one event, and reads whether it happened, after the same event has been shown to
//! work with no cover (the control).
//!
//! | test | cover | event |
//! |------|-------|-------|
//! | `..._transient_dhcp_renewal` | transient (`engage`) | DHCP lease renewal |
//! | `..._transient_neighbor_discovery` | transient | IPv6 neighbor solicitation |
//! | `..._standing_dhcp_renewal` | standing lockdown (`engage_lockdown`) | DHCP lease renewal |
//! | `..._standing_neighbor_discovery` | standing lockdown | IPv6 neighbor solicitation |
//!
//! **A test ends one of three ways, and the panic message names which:**
//! - passes: the event worked under the cover (printed as `MEASUREMENT #1075 ... covered: worked`);
//! - `DEFECT`: it worked in the control and did not under the cover. The cover drops it, and the fix
//!   is the wireguard-windows permits (DHCPv4 68 to 67, DHCPv6, ICMPv6 RS/RA/NS/NA);
//! - `COULD NOT MEASURE`: the control failed or the apparatus could not observe the event (a NIC
//!   without DHCP, no `pktmon`, a capture that lost packets, a capture that sees packets the filter
//!   drops). Nothing is concluded, and the message says why.
//!
//! **What "worked" means.**
//! - DHCP renewal, Windows: `ipconfig /renew` ran and the adapter's `DHCPLeaseObtained` (one-second
//!   resolution) dates from the renewal's second or later; the reading first waits for the clock to pass
//!   the current lease's second. `ipconfig`'s exit status is not read (a timed-out renewal exits 0). A
//!   renewal that left the lease unmoved is "did not happen" only because the control's identical
//!   command just moved it.
//! - DHCP renewal, macOS: whether the T1 renewal the DHCP client sends when BOUND, a unicast DHCPREQUEST
//!   from port 68 to its server, sent by the test itself (`ipconfig set <nic> DHCP` is an INIT-REBOOT
//!   through BPF, which pf does not see, and drops the lease), leaves the NIC. Outbound only: the
//!   runner's server answers no crafted renewal, and neither cover's ruleset has a `block in`. pf's
//!   drop of an outbound IPv4 datagram is silent to the sender, so the wire decides, through a `tcpdump`
//!   filtered to the request's transaction id: the request captured is "worked"; the request not
//!   captured although a later packet (one TCP connection to the address both covers permit, whose
//!   own answer ends the wait) was is "did not happen". That ordering needs the request not to be held
//!   behind a neighbor lookup, so a covered reading first requires the server's link-layer address to be
//!   resolved.
//! - Neighbor discovery: a neighbor solicitation reaches the wire. The test adds a throwaway ULA
//!   address to the egress NIC, so the stack runs DAD (a neighbor solicitation sent through the same
//!   output path as a resolution), waits for DAD to end (the rendezvous: DAD ending is the kernel's
//!   own signal that every solicitation was sent) and asks a capture whether it left the box.
//!   Windows reads a `pktmon` capture of every NIC component and refuses a capture that lost events;
//!   macOS reads `tcpdump` on the NIC and refuses a capture with kernel drops.
//! - Calibration (covered runs only; Windows DHCP has none): neither tap is known to sit below the
//!   filter, so the run sends a datagram the cover is known to drop and treats a capture that shows it as
//!   `COULD NOT MEASURE`. macOS calibrates in the family of the event (IPv4 for DHCP, IPv6 for ND).
//!   Windows ND calibrates with an IPv4 datagram that the cover's ALE filters reject before it reaches
//!   any NIC, which cannot show whether the capture sees packets dropped at the layer ND uses.
//!
//! The neighbor-discovery tests also print an `ND-STATE #1075` record (neighbor table, routers or routes, and on
//! Windows the cover's inbound filters) before the cover engages and while it is engaged. It decides nothing: it is
//! evidence for whether inbound neighbor/router advertisements need a test of their own.
//!
//! The control is a measurement of the apparatus, not of the cover: a test whose control did not work
//! says `COULD NOT MEASURE`, never `DEFECT`.
//!
//! Runs on the elevated `tun` lane (WFP/pf and the capture tools need the elevated token). Like the other
//! privileged binaries it is not `#[ignore]`d and does not skip on missing privilege; a developer machine
//! opts out with `SKULD_LABELS="!tun"`. It engages a real system-wide cover and adds, then removes, an
//! address on the egress NIC; CI provisions the elevation.
//!
//! COUPLED NAMES: `.config/nextest.toml`'s `global_net_state` group matches these tests by the
//! `cover_dhcp_nd_global_net_state_` prefix. Renaming one without the filter drops it from the group.
//!
//! Its own binary rather than a module of the lib: skuld allows one declaration of a label per binary
//! and the lib already declares `TUN`; it needs only the crate's public surface. The one function that
//! names the cover API is `trial::engage`.

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// Binds to `.config/nextest.toml`'s `global_net_state` test-group via
/// `cargo xtask verify-global-net-state-labels`; one declaration per test binary.
#[skuld::label]
const GLOBAL_NET_STATE: skuld::Label;

#[cfg(target_os = "windows")]
#[path = "cover_dhcp_nd_privileged/windows.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "cover_dhcp_nd_privileged/macos.rs"]
mod platform;

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[path = "cover_dhcp_nd_privileged/trial.rs"]
mod trial;

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod tests {
    use crate::trial::{run, CoverKind, Probe};
    use crate::{GLOBAL_NET_STATE, TUN};

    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn cover_dhcp_nd_global_net_state_transient_dhcp_renewal() {
        run(CoverKind::Transient, Probe::DhcpRenewal);
    }

    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn cover_dhcp_nd_global_net_state_transient_neighbor_discovery() {
        run(CoverKind::Transient, Probe::NeighborDiscovery);
    }

    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn cover_dhcp_nd_global_net_state_standing_dhcp_renewal() {
        run(CoverKind::Standing, Probe::DhcpRenewal);
    }

    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn cover_dhcp_nd_global_net_state_standing_neighbor_discovery() {
        run(CoverKind::Standing, Probe::NeighborDiscovery);
    }
}
