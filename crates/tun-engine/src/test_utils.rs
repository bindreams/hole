//! Harness shared by the privileged (elevated) test lanes of this crate and
//! of `hole-bridge`: rendering a shelled-out command's failure, owning a
//! probe route for exactly as long as a test needs it, classifying what a
//! probe's result says about the network stack, and the escape from a
//! fail-closed cover a killed test would otherwise strand on the host.
//!
//! Both lanes drive the same OS objects, so one copy is one place to fix an
//! OS quirk: when the two crates each kept their own, a single `netsh`
//! argument-quoting bug had to be found and patched twice.
//!
//! Nothing here carries a `#[cfg(target_os)]` attribute — platform choices are
//! `cfg!()` branches instead, so every branch is typechecked on every target
//! and a change that breaks one platform's harness cannot hide until that
//! platform's lane runs.
//!
//! Off unless the `test-utils` feature is on (this crate's own tests turn it
//! on through `cfg(test)`), so no production binary links it.

pub mod command;
pub mod escape;
pub mod probe;
pub mod route;

pub use command::{describe_output, ps_capture, ps_output};
pub use escape::{recovery_command, write_recovery_record, EscapeGuard, RecordSpec};
pub use probe::{classify, ProbeFate};
pub use route::OwnedRoute;
