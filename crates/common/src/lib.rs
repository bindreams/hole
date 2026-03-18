pub mod config;
pub mod import;
pub mod protocol;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
