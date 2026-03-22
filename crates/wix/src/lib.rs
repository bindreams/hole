pub mod builder;
pub mod config;
pub mod error;
pub mod toolchain;

pub use builder::Builder;
pub use error::Error;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
