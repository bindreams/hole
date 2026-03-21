pub mod config;
pub mod import;
pub mod protocol;
pub mod version;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
