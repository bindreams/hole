//! The on-disk framing: one JSON object with a `"version"` key beside the
//! payload's own fields.
//!
//! The version is read first, on its own; the payload is then parsed from the
//! same bytes by the schema for that version, which ignores the `version` key
//! like any other field it does not know. That keeps a payload error's
//! position in the file.

use serde::de::{Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::parse_error::ParseFailure;

const KEY: &str = "version";

/// A `version` that is a positive integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    Known(u32),
    /// Above `u32::MAX`: newer than any version this build can name.
    BeyondU32,
}

impl Version {
    /// `Ok(found)` when a schema at `current` can read it; `Err(found)` when
    /// it is newer, `None` for a version too large for a `u32`.
    pub(crate) fn within(self, current: u32) -> Result<u32, Option<u32>> {
        match self {
            Version::Known(found) if found <= current => Ok(found),
            Version::Known(found) => Err(Some(found)),
            Version::BeyondU32 => Err(None),
        }
    }
}

/// The `version` of a framed document, or why there is none.
///
/// `unversioned_as` is what a document with no `version` key reads as; a key
/// that is present and not a positive integer is corrupt whatever it says.
pub(crate) fn read_version(bytes: &[u8], unversioned_as: Option<u32>) -> Result<Version, ParseFailure> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let found = de
        .deserialize_map(VersionOnly)
        .and_then(|found| de.end().map(|()| found))
        .map_err(|e| ParseFailure::from(&e))?;
    match (found, unversioned_as) {
        (Some(token), _) => version_of(token),
        (None, Some(default)) => Ok(Version::Known(default)),
        (None, None) => Err(ParseFailure::framing("no version")),
    }
}

/// Integer syntax only: JSON has no leading zeros, so a token of digits alone
/// is a non-negative integer of any size.
fn version_of(token: &str) -> Result<Version, ParseFailure> {
    const NOT_POSITIVE: &str = "version is not a positive integer";
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseFailure::framing(NOT_POSITIVE));
    }
    match token.parse::<u32>() {
        Ok(0) => Err(ParseFailure::framing(NOT_POSITIVE)),
        Ok(version) => Ok(Version::Known(version)),
        Err(e) => {
            // Non-empty and all digits: overflow is the only way to fail.
            assert_eq!(*e.kind(), std::num::IntErrorKind::PosOverflow, "{token:?}");
            Ok(Version::BeyondU32)
        }
    }
}

/// Reads the `version` entry of a JSON object and skips everything else.
struct VersionOnly;

impl<'de> Visitor<'de> for VersionOnly {
    type Value = Option<&'de str>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut version = None;
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            if key != KEY {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if version.is_some() {
                return Err(A::Error::duplicate_field(KEY));
            }
            version = Some(map.next_value::<&'de RawValue>()?.get());
        }
        Ok(version)
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod frame_tests;
