// Shared release version type for semver parsing and comparison.

use std::fmt;
use std::ops::Deref;

use thiserror::Error;

// Error ===============================================================================================================

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("invalid semver: {0}")]
    Semver(#[from] semver::Error),
    #[error("{0}")]
    Custom(String),
}

// ReleaseVersion ======================================================================================================

/// A strict `MAJOR.MINOR.PATCH` version with no pre-release or build metadata.
///
/// Wraps [`semver::Version`] and enforces the invariant that `pre` and `build`
/// are both empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseVersion(semver::Version);

impl ReleaseVersion {
    /// Parse a strict `MAJOR.MINOR.PATCH` version string.
    ///
    /// Accepts an optional `v` prefix (e.g. `"v1.2.3"` or `"1.2.3"`).
    /// Rejects pre-release suffixes and build metadata.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let v = semver::Version::parse(s)?;
        if !v.pre.is_empty() {
            return Err(VersionError::Custom(format!(
                "pre-release versions are not allowed: {v}"
            )));
        }
        if !v.build.is_empty() {
            return Err(VersionError::Custom(format!("build metadata is not allowed: {v}")));
        }
        Ok(Self(v))
    }

    /// Extract the base release version from a build-time version string.
    ///
    /// The build-time format is: `MAJOR.MINOR.PATCH[-snapshot+git.HASH][.dirty]`
    ///
    /// Returns `(version, is_snapshot)` where `is_snapshot` is `true` when the
    /// build is ahead of the last release tag (contains `-snapshot`).
    pub fn from_build_version(s: &str) -> Result<(Self, bool), VersionError> {
        // The base version is everything before the first '-' or '.dirty' suffix.
        // Possible formats:
        //   "0.1.0"
        //   "0.1.0.dirty"
        //   "0.1.0-snapshot+git.abc123"
        //   "0.1.0-snapshot+git.abc123.dirty"
        let is_snapshot = s.contains("-snapshot");

        let base = match s.find('-') {
            Some(idx) => &s[..idx],
            None => s,
        };

        // Strip ".dirty" suffix if present on the base (only for on-tag dirty builds).
        let base = base.strip_suffix(".dirty").unwrap_or(base);

        let version = Self::parse(base)?;
        Ok((version, is_snapshot))
    }
}

impl Deref for ReleaseVersion {
    type Target = semver::Version;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0.major, self.0.minor, self.0.patch)
    }
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod version_tests;
