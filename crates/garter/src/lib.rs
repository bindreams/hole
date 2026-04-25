pub mod binary;
pub mod chain;
pub mod counting;
pub mod error;
pub mod plugin;
pub mod shutdown;
pub mod sip003;
pub mod tap;

pub use binary::{BinaryPlugin, PidSink};
pub use chain::ChainRunner;
pub use counting::{CountingStream, StreamCounters};
pub use error::{Error, Result};
pub use plugin::ChainPlugin;
pub use sip003::parse_plugin_options;
pub use sip003::PluginEnv;
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
mod tap_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
