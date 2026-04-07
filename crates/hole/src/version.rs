/// The application version, computed at build time from git tags.
///
/// Format: `MAJOR.MINOR.PATCH[-snapshot+git.HASH][.dirty]`
pub const VERSION: &str = env!("HOLE_VERSION");

#[cfg(test)]
#[path = "version_tests.rs"]
mod version_tests;
