//! The on-disk framing: one JSON object with a `"version"` key beside the
//! payload's own fields.
//!
//! The version is read first, on its own; the payload is then parsed from the
//! same bytes by the schema for that version, which ignores the `version` key
//! like any other field it does not know. That keeps a payload error's
//! position in the file.

use serde::de::{Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

use crate::parse_error::ParseFailure;

const KEY: &str = "version";

/// The `version` of a framed document, or why there is none.
///
/// `unversioned_as` is what a document with no `version` key reads as; a key
/// that is present and not a positive integer is corrupt whatever it says.
pub(crate) fn read_version(bytes: &[u8], unversioned_as: Option<u32>) -> Result<u32, ParseFailure> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let found = de
        .deserialize_map(VersionOnly)
        .and_then(|found| de.end().map(|()| found))
        .map_err(|e| ParseFailure::from(&e))?;
    match (found, unversioned_as) {
        (Some(value), _) => version_of(&value),
        (None, Some(default)) => Ok(default),
        (None, None) => Err(ParseFailure::framing("no version")),
    }
}

fn version_of(value: &Value) -> Result<u32, ParseFailure> {
    value
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|&v| v > 0)
        .ok_or(ParseFailure::framing("version is not a positive integer"))
}

/// Reads the `version` entry of a JSON object and skips everything else.
struct VersionOnly;

impl<'de> Visitor<'de> for VersionOnly {
    type Value = Option<Value>;

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
            version = Some(map.next_value::<Value>()?);
        }
        Ok(version)
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod frame_tests;
