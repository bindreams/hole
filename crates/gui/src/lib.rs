pub mod commands;
pub mod daemon_client;
pub mod elevation;
pub mod logging;
pub mod path_management;
pub mod setup;
pub mod state;
pub mod update;
pub mod version;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
