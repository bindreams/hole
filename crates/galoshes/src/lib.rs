#![cfg_attr(v2ray_plugin_missing, allow(dead_code, unused_imports))]

pub mod embedded;
pub mod yamux;

#[cfg(test)]
mod embedded_tests;
#[cfg(test)]
mod yamux_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
