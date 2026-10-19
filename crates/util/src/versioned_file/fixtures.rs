//! Schema chains the `versioned_file` tests run against.

use serde::{Deserialize, Serialize};

use super::{Obsolete, Role, Schema, VersionedState};

/// What the three `Note` versions all decode to, hand-written from the
/// upgrade rules below (v1 gains `tags = ["imported"]`, v2 gains
/// `pinned = false`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NoteV1 {
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NoteV2 {
    pub title: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NoteV3 {
    pub title: String,
    pub tags: Vec<String>,
    pub pinned: bool,
}

impl Schema for NoteV1 {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl Schema for NoteV2 {
    const VERSION: u32 = 2;
    type Prev = NoteV1;
    fn upgrade(prev: NoteV1) -> Self {
        Self {
            title: prev.title,
            tags: vec!["imported".to_string()],
        }
    }
}

impl Schema for NoteV3 {
    const VERSION: u32 = 3;
    type Prev = NoteV2;
    fn upgrade(prev: NoteV2) -> Self {
        Self {
            title: prev.title,
            tags: prev.tags,
            pinned: false,
        }
    }
}

/// A chain whose floor sits at 1: version 1 is deliberately dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DroppedFile {
    pub value: u32,
}

impl Schema for DroppedFile {
    const VERSION: u32 = 2;
    type Prev = Obsolete<1>;
    fn upgrade(prev: Obsolete<1>) -> Self {
        match prev {}
    }
}

impl VersionedState for DroppedFile {
    const FILE_NAME: &'static str = "dropped.json";
    const ROLE: Role = Role::Decision;
}

/// One current type per [`Role`], so the role table is exercised through
/// the real store paths.
macro_rules! role_file {
    ($name:ident, $file:literal, $role:expr) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub(crate) struct $name {
            pub value: String,
        }

        impl Schema for $name {
            const VERSION: u32 = 1;
            type Prev = Obsolete<0>;
            fn upgrade(prev: Obsolete<0>) -> Self {
                match prev {}
            }
        }

        impl VersionedState for $name {
            const FILE_NAME: &'static str = $file;
            const ROLE: Role = $role;
        }
    };
}

role_file!(DecisionFile, "decision.json", Role::Decision);
role_file!(OsRecordFile, "os-record.json", Role::OsRecord);
role_file!(LegacyRecordFile, "legacy-record.json", Role::LegacyRecord);
role_file!(ConfigFile, "config.json", Role::Config);

/// The current `Note`, as an `OsRecord`.
impl VersionedState for NoteV3 {
    const FILE_NAME: &'static str = "note.json";
    const ROLE: Role = Role::OsRecord;
}

/// A config-shaped file: an absent `version` reads as 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct UnversionedConfig {
    #[serde(default)]
    pub value: String,
}

impl Schema for UnversionedConfig {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for UnversionedConfig {
    const FILE_NAME: &'static str = "unversioned.json";
    const ROLE: Role = Role::Config;
    const UNVERSIONED_AS: Option<u32> = Some(1);
}

/// A payload that declares its own `version` key: the framing would
/// silently overwrite it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OwnsVersionKey {
    pub version: u32,
}

impl Schema for OwnsVersionKey {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for OwnsVersionKey {
    const FILE_NAME: &'static str = "owns-version.json";
    const ROLE: Role = Role::Decision;
}

pub(crate) fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// The sorted names in `dir`: what a test asserts on to prove nothing else
/// (a temp file, a backup) was left behind.
pub(crate) fn names(dir: &tempfile::TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Bytes a release cannot read, for each cause, carrying something that must
/// never be echoed.
pub(crate) fn unreadable_bytes(cause: super::CannotRead) -> &'static [u8] {
    match cause {
        super::CannotRead::Newer => br#"{"version":99,"value":"hunter2"}"#,
        super::CannotRead::Corrupt => br#"{"version":1,"value":"hunter2"#,
    }
}

/// A fresh file in `dir`.
pub(crate) fn put(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("fixture write");
    path
}

/// A payload that does not serialize as a JSON object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NotAnObject(pub Vec<u32>);

impl Schema for NotAnObject {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for NotAnObject {
    const FILE_NAME: &'static str = "not-an-object.json";
    const ROLE: Role = Role::Decision;
}

/// Nested structs, a list and an enum variant with a body: every depth an
/// unknown field can turn up at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Inner {
    pub n: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum Kind {
    Plain,
    Tagged { label: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Nested {
    pub inner: Inner,
    pub list: Vec<Inner>,
    pub kind: Kind,
}

impl Schema for Nested {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Nested {
    const FILE_NAME: &'static str = "nested.json";
    const ROLE: Role = Role::OsRecord;
}

/// A payload with a float: NaN and the infinities serialize as `null`, which a
/// `f64` field does not read back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WithFloat {
    pub x: f64,
}

impl Schema for WithFloat {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for WithFloat {
    const FILE_NAME: &'static str = "with-float.json";
    const ROLE: Role = Role::OsRecord;
}

/// A payload whose top level is an externally tagged enum: flattened beside
/// `version`, the tag would be the key `version` itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum TopEnum {
    Tagged { label: String },
}

impl Schema for TopEnum {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for TopEnum {
    const FILE_NAME: &'static str = "top-enum.json";
    const ROLE: Role = Role::Decision;
}

/// An integer wider than `u64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Wide {
    pub n: u128,
}

impl Schema for Wide {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Wide {
    const FILE_NAME: &'static str = "wide.json";
    const ROLE: Role = Role::Config;
}

/// The highest version a schema can have.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct MaxVersionFile {
    pub value: String,
}

impl Schema for MaxVersionFile {
    const VERSION: u32 = u32::MAX;
    type Prev = Obsolete<{ u32::MAX - 1 }>;
    fn upgrade(prev: Obsolete<{ u32::MAX - 1 }>) -> Self {
        match prev {}
    }
}

impl VersionedState for MaxVersionFile {
    const FILE_NAME: &'static str = "max-version.json";
    const ROLE: Role = Role::Config;
}
