pub mod gateway;
pub mod ipc;
pub mod platform;
pub mod proxy;
pub mod proxy_manager;
pub mod routing;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
