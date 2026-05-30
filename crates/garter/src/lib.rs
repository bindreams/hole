pub mod binary;
pub mod chain;
pub mod counting;
pub mod error;
pub mod plugin;
pub mod shutdown;
pub mod sip003;
pub mod sitrep;
pub mod tap;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_utils;
#[doc(hidden)]
pub mod tracing_test;

pub use binary::{BinaryPlugin, PidSink, ReadinessMode};
pub use chain::{ChainReady, ChainRunner, Mode};
pub use counting::{CountingStream, StreamCounters};
pub use error::{Error, Result};
pub use plugin::ChainPlugin;
pub use sip003::parse_plugin_options;
pub use sip003::PluginEnv;
pub use sitrep::{PluginReady, ProtocolSupport, SitrepEvent, StartError, Transports, SITREP_PROTOCOL};
pub use tap::TapPlugin;

#[cfg(test)]
mod binary_tests;
#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod counting_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod plugin_tests;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod sip003_tests;
#[cfg(test)]
mod sitrep_tests;
#[cfg(test)]
mod tap_tests;
#[cfg(test)]
mod tracing_test_tests;

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}
