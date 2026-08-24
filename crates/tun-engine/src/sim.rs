//! In-memory doubles for engine-owned types, so the datapath's policy can
//! be driven without an OS device.
//!
//! Some of the engine's caller-facing types are handed out by the driver
//! and have no constructor reachable from outside this crate. A consumer
//! writing a `Router` therefore cannot call its own `route_*` methods in
//! a test, however pure they are. `sim` closes exactly that gap, and
//! nothing more.
//!
//! ## What this module models
//!
//! - A [`UdpFlow`](crate::UdpFlow) with both of its channel ends in the
//!   caller's hands: inbound datagrams can be delivered to it, and
//!   replies the router injects can be read back.
//!
//! ## What proves the rest
//!
//! These five properties are reachable only from the elevated test lane
//! (`SKULD_LABELS=tun`, plus the `hole bridge run` subprocess e2e), and
//! nothing here stands in for them:
//!
//! 1. `Device::build` creating a real adapter with the requested name,
//!    MTU and address.
//! 2. The OS routing packets *into* that adapter.
//! 3. The OS *accepting* packets written out of it.
//! 4. Adapter-handle lifetime, including the wintun drain on teardown and
//!    `adapter_cleanup`'s sweep.
//! 5. Real egress from a consumer's proxy and bypass mechanisms.
//!
//! CONTRIBUTING.md's "Datapath coverage: which lane proves what" section
//! carries the full split. See bindreams/hole#892.

// Under `cfg(test)` this crate's lib target is a binary (`harness = false`
// plus a `main`), which makes even `pub` items dead-code-checked. The
// doubles are consumed by downstream crates, so that check cannot see
// their callers.
#![allow(dead_code)]

pub mod flow;

pub use flow::{udp_flow, Reply, UdpFlowPeer};
