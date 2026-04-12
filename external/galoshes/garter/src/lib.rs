pub mod binary;
pub mod chain;
pub mod error;
pub mod plugin;
pub mod shutdown;
pub mod sip003;

pub use binary::{BinaryPlugin, PidSink};
pub use chain::ChainRunner;
pub use error::{Error, Result};
pub use plugin::ChainPlugin;
pub use sip003::parse_plugin_options;
pub use sip003::PluginEnv;

#[cfg(test)]
mod binary_tests;
#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod plugin_tests;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod sip003_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
