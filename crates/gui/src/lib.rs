pub mod commands;
pub mod daemon_client;
pub mod logging;
pub mod path_management;
pub mod setup;
pub mod state;
pub mod version;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
