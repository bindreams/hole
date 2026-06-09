//! `build.yaml` manifest: target registry for `cargo xtask build|run|list`.
//!
//! See `build.yaml` at the repo root for the user-facing schema.
//!
//! This module owns the **types**, the **serde shape** (with all the
//! short-syntax shorthand), and **structural validation** (no missing deps,
//! no cycles, known platform set). It does *not* execute steps — that's
//! `orchestrate.rs`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

// ===== Os / Arch / Platform ==========================================================================================

/// Operating system component of a [`Platform`].
///
/// Docker / GOOS-style identifiers: matches the project's release-artifact
/// naming convention (`hole-<version>-windows-amd64.msi`) and the `matrix.os`
/// dimension already used in `.github/workflows/ci.yaml`.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Windows,
    Darwin,
    Linux,
}

impl Os {
    /// The host OS, or `None` if running on a platform the manifest doesn't
    /// know about (FreeBSD, illumos, etc.).
    pub fn host() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Os::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Os::Darwin)
        } else if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else {
            None
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Darwin => "darwin",
            Os::Linux => "linux",
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Os {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "windows" => Ok(Os::Windows),
            "darwin" => Ok(Os::Darwin),
            "linux" => Ok(Os::Linux),
            other => Err(anyhow!(
                "unknown os {other:?} (expected one of: windows, darwin, linux)"
            )),
        }
    }
}

/// CPU architecture component of a [`Platform`].
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    /// The host architecture, or `None` if running on an arch the manifest
    /// doesn't know about (riscv64, ppc64, etc.).
    pub fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::Amd64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Arm64)
        } else {
            None
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Arch {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "amd64" => Ok(Arch::Amd64),
            "arm64" => Ok(Arch::Arm64),
            other => Err(anyhow!("unknown arch {other:?} (expected one of: amd64, arm64)")),
        }
    }
}

/// One target platform: an `<os>/<arch>` pair like `windows/amd64`.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
}

impl Platform {
    pub fn new(os: Os, arch: Arch) -> Self {
        Self { os, arch }
    }

    /// The host platform, or `None` if either component is unknown.
    pub fn host() -> Option<Self> {
        Some(Self::new(Os::host()?, Arch::host()?))
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)
    }
}

impl FromStr for Platform {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (os, arch) = s
            .split_once('/')
            .ok_or_else(|| anyhow!("platform must have shape <os>/<arch>, got {s:?}"))?;
        let os = Os::from_str(os).with_context(|| format!("in platform {s:?}"))?;
        let arch = Arch::from_str(arch).with_context(|| format!("in platform {s:?}"))?;
        Ok(Self::new(os, arch))
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

// ===== Steps =========================================================================================================

/// A single build step. Either runs a bash command or spawns a process directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Bash {
        command: String,
        environment: HashMap<String, String>,
        elevated: bool,
    },
    Process {
        args: Vec<String>,
        environment: HashMap<String, String>,
        elevated: bool,
    },
}

// Raw shapes used for deserialization, immediately normalized into [`Step`].
//
// Two layers of shorthand collapse here:
//   - bare string         ↔ { bash: <string> }
//   - { bash: <string> }  ↔ { bash: { command: <string> } }
// Symmetric collapse for `process:` (bare list ↔ { process: { args: [...] } }).

#[derive(Deserialize)]
#[serde(untagged)]
enum BashRaw {
    Short(String),
    Full {
        command: String,
        #[serde(default)]
        environment: HashMap<String, String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProcessRaw {
    Args(Vec<String>),
    Full {
        args: Vec<String>,
        #[serde(default)]
        environment: HashMap<String, String>,
    },
}

// A raw step is a `bash:` or `process:` kind, optionally carrying an `elevated:`
// sibling key. Hand-rolled `Deserialize` (rather than untagged enum) so the
// `elevated:` flag can ride alongside `bash:`/`process:` in the same mapping and
// produce clear "both keys"/"unknown field" errors.
struct StepRaw {
    kind: StepKindRaw,
    elevated: Option<bool>,
}
enum StepKindRaw {
    Bash(BashRaw),
    Process(ProcessRaw),
}

impl<'de> Deserialize<'de> for StepRaw {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StepRaw;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bash string, or a `{ bash|process: ..., elevated?: <bool> }` mapping")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Self::Value, E> {
                Ok(StepRaw {
                    kind: StepKindRaw::Bash(BashRaw::Short(s.to_owned())),
                    elevated: None,
                })
            }
            fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<Self::Value, E> {
                self.visit_str(&s)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
                let mut kind: Option<StepKindRaw> = None;
                let mut elevated: Option<bool> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "bash" => {
                            if kind.is_some() {
                                return Err(de::Error::custom("step has both `bash:` and `process:`"));
                            }
                            kind = Some(StepKindRaw::Bash(map.next_value()?));
                        }
                        "process" => {
                            if kind.is_some() {
                                return Err(de::Error::custom("step has both `bash:` and `process:`"));
                            }
                            kind = Some(StepKindRaw::Process(map.next_value()?));
                        }
                        "elevated" => {
                            if elevated.is_some() {
                                return Err(de::Error::duplicate_field("elevated"));
                            }
                            elevated = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, &["bash", "process", "elevated"])),
                    }
                }
                let kind = kind.ok_or_else(|| de::Error::custom("step needs a `bash:` or `process:` key"))?;
                Ok(StepRaw { kind, elevated })
            }
        }
        d.deserialize_any(V)
    }
}

impl Step {
    fn from_raw(kind: StepKindRaw, elevated: bool) -> Self {
        match kind {
            StepKindRaw::Bash(BashRaw::Short(command)) => Step::Bash {
                command,
                environment: HashMap::new(),
                elevated,
            },
            StepKindRaw::Bash(BashRaw::Full { command, environment }) => Step::Bash {
                command,
                environment,
                elevated,
            },
            StepKindRaw::Process(ProcessRaw::Args(args)) => Step::Process {
                args,
                environment: HashMap::new(),
                elevated,
            },
            StepKindRaw::Process(ProcessRaw::Full { args, environment }) => Step::Process {
                args,
                environment,
                elevated,
            },
        }
    }
    /// Whether this step runs elevated after `elevated:` resolution.
    pub fn is_elevated(&self) -> bool {
        match self {
            Step::Bash { elevated, .. } | Step::Process { elevated, .. } => *elevated,
        }
    }
}

// ===== Target ========================================================================================================

/// One target in the build graph. Public, post-normalization shape.
#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub depends: Vec<String>,
    pub platforms: Vec<Platform>,
    pub build: Vec<Step>,
    pub run: Vec<Step>,
}

impl Target {
    /// Returns `true` if this target applies to `platform` (i.e. its
    /// `platforms:` list contains `platform`).
    pub fn applies_to(&self, platform: Platform) -> bool {
        self.platforms.contains(&platform)
    }

    /// Returns `true` if this target declares any `run:` steps. The
    /// `cargo xtask list` output marks runnable targets in the `RUN?` column.
    pub fn has_run(&self) -> bool {
        !self.run.is_empty()
    }
}

// Raw shape for a target — the post-deserialization step is normalizing
// `Option<DependsRaw>` and `Option<BuildRaw>` into `Vec<...>` and resolving
// `PlatformsRaw` into `Vec<Platform>`. `run:` reuses `BuildRaw` because the
// underlying shape (one step or a list of steps) is identical; the type's
// name describes structure, not semantics.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetRaw {
    #[serde(default)]
    depends: Option<DependsRaw>,
    platforms: PlatformsRaw,
    #[serde(default)]
    build: Option<BuildRaw>,
    #[serde(default)]
    run: Option<BuildRaw>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DependsRaw {
    One(String),
    Many(Vec<String>),
}

impl DependsRaw {
    fn into_vec(self) -> Vec<String> {
        match self {
            DependsRaw::One(s) => vec![s],
            DependsRaw::Many(v) => v,
        }
    }
}

// `build:`/`run:` accept a single step, a list of steps, or a
// `{ elevated: <bool>, steps: [...] }` block carrying a per-block `elevated`
// default. The block form shares its mapping shape with a tagged single step
// (`{ bash: ... }`), so a clean untagged enum can't disambiguate; we hand-roll
// a Visitor and branch on the presence of a `steps:` key.
enum BuildRaw {
    Steps {
        block_elevated: Option<bool>,
        steps: Vec<StepRaw>,
    },
}

impl BuildRaw {
    fn into_steps(self) -> Vec<Step> {
        let BuildRaw::Steps { block_elevated, steps } = self;
        steps
            .into_iter()
            .map(|r| {
                let elevated = r.elevated.or(block_elevated).unwrap_or(false);
                Step::from_raw(r.kind, elevated)
            })
            .collect()
    }
}

impl<'de> Deserialize<'de> for BuildRaw {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BuildRaw;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a step, a list of steps, or a `{ elevated: <bool>, steps: [...] }` block")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Self::Value, E> {
                Ok(BuildRaw::Steps {
                    block_elevated: None,
                    steps: vec![StepRaw {
                        kind: StepKindRaw::Bash(BashRaw::Short(s.to_owned())),
                        elevated: None,
                    }],
                })
            }
            fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<Self::Value, E> {
                self.visit_str(&s)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error> {
                let mut steps = Vec::new();
                while let Some(s) = seq.next_element::<StepRaw>()? {
                    steps.push(s);
                }
                Ok(BuildRaw::Steps {
                    block_elevated: None,
                    steps,
                })
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<Self::Value, A::Error> {
                // Buffer the map so we can branch on a `steps:` key, then re-deserialize.
                let value = serde_yml::Value::deserialize(MapAccessDeserializer::new(map))?;
                let is_block = value.as_mapping().map(|m| m.contains_key("steps")).unwrap_or(false);
                if is_block {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct BlockRaw {
                        #[serde(default)]
                        elevated: Option<bool>,
                        steps: Vec<StepRaw>,
                    }
                    let b = BlockRaw::deserialize(value).map_err(de::Error::custom)?;
                    Ok(BuildRaw::Steps {
                        block_elevated: b.elevated,
                        steps: b.steps,
                    })
                } else {
                    let step = StepRaw::deserialize(value).map_err(de::Error::custom)?;
                    Ok(BuildRaw::Steps {
                        block_elevated: None,
                        steps: vec![step],
                    })
                }
            }
        }
        d.deserialize_any(V)
    }
}

/// `platforms:` field — three valid shapes:
///   - bare scalar: `platforms: windows/amd64`
///   - explicit list: `platforms: [windows/amd64, darwin/arm64]`
///   - matrix: `platforms: { matrix: { os: [...], arch: [...] } }`
enum PlatformsRaw {
    Single(Platform),
    List(Vec<Platform>),
    Matrix(PlatformMatrix),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformMatrix {
    os: Vec<Os>,
    arch: Vec<Arch>,
}

impl PlatformsRaw {
    fn into_vec(self) -> Result<Vec<Platform>> {
        match self {
            PlatformsRaw::Single(p) => Ok(vec![p]),
            PlatformsRaw::List(v) => Ok(v),
            PlatformsRaw::Matrix(m) => {
                if m.os.is_empty() {
                    return Err(anyhow!("platforms.matrix.os must list at least one os"));
                }
                if m.arch.is_empty() {
                    return Err(anyhow!("platforms.matrix.arch must list at least one arch"));
                }
                Ok(m.os
                    .into_iter()
                    .flat_map(|os| m.arch.iter().map(move |&arch| Platform::new(os, arch)))
                    .collect())
            }
        }
    }
}

// `platforms:` is awkward to express as a clean #[serde(untagged)] enum because
// the matrix variant is a single-key map sharing shape with a plain mapping. We
// hand-roll a Visitor instead so error messages stay clear.
impl<'de> Deserialize<'de> for PlatformsRaw {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PlatformsRaw;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a platform string (e.g. `windows/amd64`), a list of them, \
                     or a `{ matrix: { os: [...], arch: [...] } }` mapping",
                )
            }

            fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Self::Value, E> {
                Platform::from_str(s).map(PlatformsRaw::Single).map_err(E::custom)
            }

            fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<Self::Value, E> {
                self.visit_str(&s)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(p) = seq.next_element::<Platform>()? {
                    out.push(p);
                }
                Ok(PlatformsRaw::List(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
                let mut matrix: Option<PlatformMatrix> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "matrix" => {
                            if matrix.is_some() {
                                return Err(de::Error::duplicate_field("matrix"));
                            }
                            matrix = Some(map.next_value()?);
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["matrix"]));
                        }
                    }
                }
                let matrix = matrix.ok_or_else(|| de::Error::custom("expected `matrix:` key in platforms mapping"))?;
                Ok(PlatformsRaw::Matrix(matrix))
            }
        }
        d.deserialize_any(V)
    }
}

// ===== Manifest ======================================================================================================

/// Parsed `build.yaml`. Targets keep their declaration order (driven by
/// [`IndexMap`]) so `cargo xtask list` prints them in a predictable order.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub targets: IndexMap<String, Target>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRaw {
    targets: IndexMap<String, TargetRaw>,
}

impl Manifest {
    /// Parse and validate a `build.yaml` document.
    pub fn parse(yaml: &str) -> Result<Self> {
        let raw: ManifestRaw = serde_yml::from_str(yaml).context("parsing build.yaml")?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: ManifestRaw) -> Result<Self> {
        let mut targets = IndexMap::with_capacity(raw.targets.len());
        for (name, t) in raw.targets {
            let depends = t.depends.map(DependsRaw::into_vec).unwrap_or_default();
            let platforms = t.platforms.into_vec().with_context(|| format!("in target {name:?}"))?;
            let build = t.build.map(BuildRaw::into_steps).unwrap_or_default();
            let run = t.run.map(BuildRaw::into_steps).unwrap_or_default();

            if let Some(i) = build.iter().position(Step::is_elevated) {
                return Err(anyhow!(
                    "target {name:?}: build step #{} is `elevated: true`; build steps cannot be \
                     elevated (build artifacts must stay unprivileged)",
                    i + 1
                ));
            }

            // Reject platform duplicates inside one target — silent dedup would
            // hide a real authoring mistake.
            let mut seen = HashSet::new();
            for p in &platforms {
                if !seen.insert(*p) {
                    return Err(anyhow!("target {name:?} lists platform {p} more than once"));
                }
            }

            targets.insert(
                name.clone(),
                Target {
                    name,
                    depends,
                    platforms,
                    build,
                    run,
                },
            );
        }

        let m = Self { targets };
        m.validate_deps()?;
        Ok(m)
    }

    /// Every name in `depends:` must resolve to a declared target.
    fn validate_deps(&self) -> Result<()> {
        for t in self.targets.values() {
            for dep in &t.depends {
                if !self.targets.contains_key(dep) {
                    return Err(anyhow!("target {:?} depends on unknown target {:?}", t.name, dep));
                }
            }
        }
        Ok(())
    }

    /// Look up a target by name.
    pub fn get(&self, name: &str) -> Option<&Target> {
        self.targets.get(name)
    }

    /// Iterate targets in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = &Target> {
        self.targets.values()
    }
}
