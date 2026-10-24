//! Harness shared by the privileged (elevated) test lanes of this crate and
//! of `hole-bridge`: rendering a shelled-out command's failure, owning a
//! probe route for exactly as long as a test needs it, classifying what a
//! probe's result says about the network stack, the escape from a
//! fail-closed cover a killed test would otherwise strand on the host, and
//! the resolver set and the configd change notification the macOS DNS tests compare and wait on.
//!
//! Both lanes drive the same OS objects, so one copy is one place to fix an
//! OS quirk: when the two crates each kept their own, a single `netsh`
//! argument-quoting bug had to be found and patched twice.
//!
//! `command`, `escape`, `probe`, `resolvers`, and `route` carry no `#[cfg(target_os)]`
//! attribute — platform choices are `cfg!()` branches instead, so every
//! branch is typechecked on every target and a change that breaks one
//! platform's harness cannot hide until that platform's lane runs. `pktmon`
//! (a Windows-only tool), `cover` (it reads the Windows/macOS firewall
//! back, and `routing::failclosed` has no other target) and `dns_notify`
//! (a macOS-only libSystem API) are the exceptions, gated at the `mod`
//! declaration instead.
//!
//! Off unless the `test-utils` feature is on (this crate's own tests turn it
//! on through `cfg(test)`), so no production binary links it.

pub mod command;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub mod cover;
#[cfg(target_os = "macos")]
pub mod dns_notify;
pub mod escape;
#[cfg(target_os = "windows")]
pub mod pktmon;
pub mod probe;
pub mod resolvers;
pub mod route;

pub use command::{describe_output, ps_capture, ps_output};
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use cover::held_covers;
#[cfg(target_os = "macos")]
pub use dns_notify::DnsConfigNotify;
pub use escape::{recovery_command, write_recovery_record, EscapeGuard, RecordSpec};
#[cfg(target_os = "windows")]
pub use pktmon::{capture_contains_nonce, nonce, pktmon, send_marker, PktmonGuard};
pub use probe::{classify, classify_send, ProbeFate, SendFate};
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use resolvers::resolver_set_uncovered;
pub use resolvers::{nameservers, resolver_set, scutil_dns_checked, NETWORK_CONTROL};
pub use route::OwnedRoute;
