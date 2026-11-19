//! `.config/notices.yaml`: the ordered list of licences, the components no package manager declares, and what a
//! component's own files lack.

use std::path::Path;

use serde::Deserialize;
use spdx::LicenseReq;

use super::take::{choose_licences, standard_text_of};
use super::{Component, NoticesError};
use crate::manifest::{Arch, Os, Platform};

/// The config file, relative to the repository root.
pub const CONFIG_PATH: &str = ".config/notices.yaml";

/// What `.config/notices.yaml` holds.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Licences a component may be taken under. Membership allows, position prefers: where an expression offers a
    /// choice, the first listed licence it allows is the one followed.
    pub licenses: Vec<ListedLicense>,
    /// Components no package manager declares: fonts, shipped binaries, the Go standard library.
    #[serde(default)]
    pub declared: Vec<Declared>,
    /// What a component's own files lack: a licence, a text, a holder line.
    #[serde(default)]
    pub overrides: Vec<Override>,
}

/// One licence of the list and how its text is printed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListedLicense {
    pub id: String,
    pub text: TextPolicy,
}

/// Where the text printed for a licence comes from.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextPolicy {
    /// The standard text names no holder: it is printed once, followed by the components under it.
    Shared,
    /// As `shared`, and the component's `NOTICE` files are printed too (Apache-2.0 section 4(d)).
    SharedWithNotice,
    /// The text names a holder: the component's own licence files are printed whole, exactly as it distributes them.
    Own,
}

/// Where the text a [`TextPolicy`] prints comes from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TextBasis {
    /// The licence's standard text, printed once with the components under it.
    Standard,
    /// The component's own licence files, whole, or the text the config supplies for it.
    OwnFiles,
}

impl TextPolicy {
    /// Where the policy's text comes from: the one decision that splits what is printed for a licence.
    pub fn basis(self) -> TextBasis {
        match self {
            TextPolicy::Shared => TextBasis::Standard,
            TextPolicy::SharedWithNotice => TextBasis::Standard,
            TextPolicy::Own => TextBasis::OwnFiles,
        }
    }

    /// Whether the component's `NOTICE` files are printed.
    pub fn prints_notice_files(self) -> bool {
        match self {
            TextPolicy::Shared => false,
            TextPolicy::SharedWithNotice => true,
            TextPolicy::Own => false,
        }
    }
}

/// A component no package manager declares.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declared {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// Where the version is read from, for a component whose version the repository already pins elsewhere.
    #[serde(default)]
    pub version_from: Option<VersionSource>,
    /// Where the text printed for it comes from, for a component whose texts no licence file or supplied text carries.
    #[serde(default)]
    pub text_from: Option<TextSource>,
    /// An SPDX expression, or `LicenseRef-<name>` for a licence SPDX does not list.
    pub license: String,
    #[serde(default)]
    pub url: Option<String>,
    /// The artifacts that carry it ([`PlatformScope`]); empty means every artifact.
    #[serde(default)]
    pub platforms: Vec<PlatformScope>,
    /// Repository-relative files it covers: each must exist, and each must belong to some entry.
    #[serde(default)]
    pub files: Vec<String>,
    /// The repository-relative folder holding its own licence files.
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default)]
    pub texts: Vec<SuppliedText>,
}

impl Declared {
    /// Whether the entry is the one for `component`: a declared component, by name and, when the entry states one, version.
    pub fn applies_to(&self, component: &Component) -> bool {
        component.origin.is_declared_by_hand()
            && self.name == component.name
            && self
                .version
                .as_deref()
                .is_none_or(|version| version == component.version)
    }

    /// Whether some component can be the one of both entries: a version one of them leaves open (or reads from a file)
    /// matches the other's, and their platforms share one.
    fn overlaps(&self, other: &Declared) -> bool {
        self.name == other.name
            && versions_overlap(self.version.as_deref(), other.version.as_deref())
            && platforms_overlap(&self.platforms, &other.platforms)
    }

    fn describe(&self) -> String {
        describe_entry(&self.name, self.version.as_deref(), &self.platforms)
    }
}

/// The artifacts an entry applies to: those of one OS (`windows`) or of one architecture of it (`darwin/arm64`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PlatformScope {
    os: Os,
    arch: Option<Arch>,
}

impl PlatformScope {
    /// Whether the artifact of `platform` is one of them.
    pub fn covers(&self, platform: &Platform) -> bool {
        self.os == platform.os && self.arch.is_none_or(|arch| arch == platform.arch)
    }

    /// Whether some platform is covered by both.
    fn overlaps(&self, other: &PlatformScope) -> bool {
        self.os == other.os && (self.arch.is_none() || other.arch.is_none() || self.arch == other.arch)
    }
}

impl std::fmt::Display for PlatformScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.arch {
            Some(arch) => write!(f, "{}/{arch}", self.os),
            None => write!(f, "{}", self.os),
        }
    }
}

impl std::str::FromStr for PlatformScope {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        if text.contains('/') {
            let Platform { os, arch } = text
                .parse::<Platform>()
                .map_err(|e| format!("platform {text:?}: {e:#}"))?;
            return Ok(PlatformScope { os, arch: Some(arch) });
        }
        let os = text.parse::<Os>().map_err(|e| format!("platform {text:?}: {e}"))?;
        Ok(PlatformScope { os, arch: None })
    }
}

impl<'de> Deserialize<'de> for PlatformScope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// A file of the repository that pins the version of a declared component.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionSource {
    /// The `channel` of `rust-toolchain.toml`: the Rust standard library is the toolchain's.
    RustToolchain,
    /// The release of the Go toolchain that builds `ex-ray` (`go env GOVERSION` in its folder): the Go standard library is
    /// the toolchain's, and `go.mod`'s `toolchain` line is a minimum, so no file pins the release.
    GoToolchain,
}

/// A file outside the repository that carries a declared component's notices.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextSource {
    /// The pinned toolchain's own copyright file for the Rust standard library.
    RustToolchainCopyright,
    /// The `LICENSE` file of the Go toolchain that builds `ex-ray`, in its `GOROOT`.
    GoToolchain,
}

/// The package ecosystem a component comes from: the namespace its name is unique in.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Crate,
    Go,
    Npm,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Crate => "crate",
            Ecosystem::Go => "go",
            Ecosystem::Npm => "npm",
        }
    }

    /// The sentence that tells a reader to add `field` to the component `name`'s `overrides:` entry, which is how any
    /// component of an ecosystem is given what its own files lack.
    pub fn entry_to_add(self, name: &str, field: &str) -> String {
        format!(
            "Add `overrides: [{{name: {name}, ecosystem: {}, {field}}}]` to .config/notices.yaml",
            self.as_str()
        )
    }
}

/// What a component's own files lack.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// The ecosystem the entry is for: `widget` the crate and `widget` the npm package are two components.
    pub ecosystem: Ecosystem,
    pub name: String,
    /// Matches this version only; absent matches every version. An entry that sets `license` must set it: a licence read
    /// from a component's files is true of the version it was read from.
    #[serde(default)]
    pub version: Option<String>,
    /// The artifacts the entry applies to ([`PlatformScope`]); empty means every artifact.
    #[serde(default)]
    pub platforms: Vec<PlatformScope>,
    /// The licence expression, for a component whose ecosystem declares none (a Go module) or declares one that does
    /// not parse. It is one the generator follows, as for a component: [`Config::parse`] checks.
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub texts: Vec<SuppliedText>,
}

impl Override {
    /// Whether the entry is the one for `component`: its ecosystem, its name and, when the entry states one, its
    /// version.
    pub fn applies_to(&self, component: &Component) -> bool {
        component.origin.ecosystem() == Some(self.ecosystem)
            && self.name == component.name
            && self
                .version
                .as_deref()
                .is_none_or(|version| version == component.version)
    }

    /// Whether some component can be the one of both entries: same ecosystem and name, a common version, a common
    /// platform.
    fn overlaps(&self, other: &Override) -> bool {
        self.ecosystem == other.ecosystem
            && self.name == other.name
            && versions_overlap(self.version.as_deref(), other.version.as_deref())
            && platforms_overlap(&self.platforms, &other.platforms)
    }

    fn describe(&self) -> String {
        describe_entry(&self.name, self.version.as_deref(), &self.platforms)
    }
}

fn versions_overlap(a: Option<&str>, b: Option<&str>) -> bool {
    a.is_none() || b.is_none() || a == b
}

fn platforms_overlap(a: &[PlatformScope], b: &[PlatformScope]) -> bool {
    a.is_empty() || b.is_empty() || a.iter().any(|x| b.iter().any(|y| x.overlaps(y)))
}

fn describe_entry(name: &str, version: Option<&str>, platforms: &[PlatformScope]) -> String {
    let version = version.map_or("every version".to_owned(), |version| format!("version {version}"));
    let platforms = match platforms {
        [] => "every platform".to_owned(),
        platforms => platforms
            .iter()
            .map(PlatformScope::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    };
    format!("`{name}`, {version}, {platforms}")
}

/// A text or holder line read from a component's upstream repository.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedText {
    pub license: String,
    /// The whole text, exactly as upstream distributes it.
    #[serde(default)]
    pub text: Option<String>,
    /// The holder line alone, exactly as upstream writes it: printed above the licence's standard text.
    #[serde(default)]
    pub notice: Option<String>,
    /// For a component whose upstream ships no licence text at all: what upstream does state about its licence (a
    /// manifest line, a README section), exactly as written. It is printed as upstream's own words, followed by the
    /// licence's standard text without a copyright line, because upstream names no holder.
    #[serde(default)]
    pub upstream_words: Option<String>,
    /// The URL it was read from.
    pub source: String,
}

impl Config {
    /// Read and validate `<repo_root>/.config/notices.yaml`.
    pub fn load(repo_root: &Path) -> Result<Config, NoticesError> {
        let path = repo_root.join(CONFIG_PATH);
        let text = std::fs::read_to_string(&path).map_err(|source| NoticesError::Io { path, source })?;
        Config::parse(&text)
    }

    /// Parse and validate the text of a config file.
    pub fn parse(text: &str) -> Result<Config, NoticesError> {
        let config: Config = serde_yml::from_str(text).map_err(|e| config_error(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// The config as it applies to one platform's artifact: entries for other platforms left out.
    pub fn for_platform(&self, platform: &Platform) -> Config {
        let applies = |scopes: &[PlatformScope]| scopes.is_empty() || scopes.iter().any(|scope| scope.covers(platform));
        Config {
            licenses: self.licenses.clone(),
            declared: self
                .declared
                .iter()
                .filter(|e| applies(&e.platforms))
                .cloned()
                .collect(),
            overrides: self
                .overrides
                .iter()
                .filter(|e| applies(&e.platforms))
                .cloned()
                .collect(),
        }
    }

    /// The position of `id` in the list: lower is preferred.
    pub fn rank(&self, id: &str) -> Option<usize> {
        self.licenses.iter().position(|listed| listed.id == id)
    }

    /// The position in the list of the requirement of an expression: the entry spelled as SPDX spells the requirement.
    /// An exception (`WITH`) changes the terms, so only an entry that names the same exception covers it, and a plain
    /// entry never covers a licence with one.
    pub fn rank_of(&self, requirement: &LicenseReq) -> Option<usize> {
        self.rank(&requirement.to_string())
    }

    pub fn text_policy(&self, id: &str) -> Option<TextPolicy> {
        self.rank(id).map(|rank| self.licenses[rank].text)
    }

    pub fn overrides_for<'a>(&'a self, component: &'a Component) -> impl Iterator<Item = &'a Override> + 'a {
        self.overrides.iter().filter(move |entry| entry.applies_to(component))
    }

    /// Every text the config supplies for a component, from its overrides and its `declared` entry.
    pub fn supplied_texts<'a>(&'a self, component: &'a Component) -> Vec<&'a SuppliedText> {
        let from_overrides = self.overrides_for(component).flat_map(|entry| entry.texts.iter());
        let from_declared = self
            .declared
            .iter()
            .filter(move |entry| entry.applies_to(component))
            .flat_map(|entry| entry.texts.iter());
        from_overrides.chain(from_declared).collect()
    }

    /// Where the declared component has its text read from, when its entry says.
    pub fn text_source(&self, component: &Component) -> Option<TextSource> {
        self.declared
            .iter()
            .filter(|entry| entry.applies_to(component))
            .find_map(|entry| entry.text_from)
    }

    fn validate(&self) -> Result<(), NoticesError> {
        for (at, listed) in self.licenses.iter().enumerate() {
            let (licence, exception) = split_exception(&listed.id);
            if !is_known_licence(licence) {
                return Err(config_error(format!(
                    "`licenses` lists `{}`, which is neither an SPDX identifier nor `LicenseRef-<name>`",
                    listed.id
                )));
            }
            if let Some(exception) = exception {
                if spdx::exception_id(exception).is_none() {
                    return Err(config_error(format!(
                        "`licenses` lists `{}`, and `{exception}` is not an SPDX exception identifier",
                        listed.id
                    )));
                }
                match listed.text.basis() {
                    TextBasis::OwnFiles => {}
                    TextBasis::Standard => {
                        return Err(config_error(format!(
                            "`licenses` lists `{}` with a `text` that prints the standard text of `{licence}`, which leaves                              the exception out: set it to `text: own`, which prints the component's own licence files",
                            listed.id
                        )));
                    }
                }
            }
            match listed.text.basis() {
                TextBasis::Standard if standard_text_of(&listed.id).is_none() => {
                    return Err(config_error(format!(
                        "`licenses` lists `{}` with a `text` that prints the standard text, and the spdx crate has none for \
                         it: set it to `text: own`, which prints the component's own licence files",
                        listed.id
                    )));
                }
                TextBasis::Standard | TextBasis::OwnFiles => {}
            }
            if self.licenses[..at].iter().any(|earlier| earlier.id == listed.id) {
                return Err(config_error(format!("`licenses` lists `{}` twice", listed.id)));
            }
        }
        // A licence the config states always parses and is on the list, so no component is later refused for one.
        for (at, entry) in self.declared.iter().enumerate() {
            let named = format!("the `declared:` entry #{} ({})", at + 1, entry.describe());
            self.check_licence(&named, &entry.license)?;
        }
        for (at, entry) in self.overrides.iter().enumerate() {
            let Some(expression) = &entry.license else { continue };
            let named = format!("the `overrides:` entry #{} ({})", at + 1, entry.describe());
            if entry.version.is_none() {
                return Err(config_error(format!(
                    "{named} sets `license` and no `version`: a licence read from a component's files is true of the \
                     version it was read from, so name that version; a bump then leaves the entry unused, which asks \
                     for the licence to be read again"
                )));
            }
            self.check_licence(&named, expression)?;
        }
        // The generator takes one `license` and one `text_from` for a component: a second would be ignored.
        for (at, later) in self.declared.iter().enumerate() {
            for (earlier_at, earlier) in self.declared[..at].iter().enumerate() {
                if earlier.overlaps(later) {
                    let fields = match earlier.text_from.is_some() && later.text_from.is_some() {
                        true => "`license` and `text_from`",
                        false => "`license`",
                    };
                    return Err(config_error(format!(
                        "the `declared:` entries #{} ({}) and #{} ({}) apply to one component and both set {fields}; \
                         give one of them a `version` or `platforms` the other lacks, or remove one",
                        earlier_at + 1,
                        earlier.describe(),
                        at + 1,
                        later.describe()
                    )));
                }
            }
        }
        for (at, later) in self.overrides.iter().enumerate() {
            for (earlier_at, earlier) in self.overrides[..at].iter().enumerate() {
                if earlier.overlaps(later) && earlier.license.is_some() && later.license.is_some() {
                    return Err(config_error(format!(
                        "the `overrides:` entries #{} ({}) and #{} ({}) apply to one component and both set `license`; \
                         give one of them a `version` or `platforms` the other lacks, or remove one",
                        earlier_at + 1,
                        earlier.describe(),
                        at + 1,
                        later.describe()
                    )));
                }
            }
        }
        for entry in &self.declared {
            if entry.version.is_some() && entry.version_from.is_some() {
                return Err(config_error(format!(
                    "the entry for `{}` gives both `version` and `version_from`; give one",
                    entry.name
                )));
            }
            if entry.text_from.is_some() {
                // The texts come from the file `text_from` names: these would be read by nothing.
                for (field, given) in [("texts", !entry.texts.is_empty()), ("dir", entry.dir.is_some())] {
                    if given {
                        return Err(config_error(format!(
                            "the entry for `{}` gives `text_from` and `{field}`; its texts come from the file `text_from` names, so `{field}` would be ignored",
                            entry.name
                        )));
                    }
                }
            }
            for text in &entry.texts {
                check_text(&entry.name, text)?;
            }
        }
        for entry in &self.overrides {
            for text in &entry.texts {
                check_text(&entry.name, text)?;
            }
        }
        Ok(())
    }

    /// Fails unless `expression`, the `license` of the entry `named`, is one the generator follows: exactly when
    /// [`choose_licences`] follows a licence under it, for a component as well as for the config.
    fn check_licence(&self, named: &str, expression: &str) -> Result<(), NoticesError> {
        choose_licences(expression, self).map(drop).map_err(|refusal| {
            config_error(format!(
                "{named} sets `license: {expression}`, which cannot be followed: {refusal}"
            ))
        })
    }
}

/// A listed id as a licence and, for a requirement written `<licence> WITH <exception>`, its exception.
fn split_exception(id: &str) -> (&str, Option<&str>) {
    match id.split_once(" WITH ") {
        Some((licence, exception)) => (licence, Some(exception)),
        None => (id, None),
    }
}

fn is_known_licence(id: &str) -> bool {
    spdx::license_id(id).is_some_and(|known| known.name == id) || id.starts_with("LicenseRef-")
}

/// The licences whose standard text a holder line (`notice`) or upstream's words may be printed with. The standard text
/// is printed without the line its template leaves for a holder, and that line is found by its shape
/// (`Copyright ... <...>`): a licence is listed only once its standard text is shown to have no such line left. Any
/// other licence supplies the whole `text:`.
pub const HOLDER_LINE_LICENCES: &[&str] = &["OFL-1.1", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC"];

fn check_text(name: &str, text: &SuppliedText) -> Result<(), NoticesError> {
    if (text.notice.is_some() || text.upstream_words.is_some())
        && !HOLDER_LINE_LICENCES.contains(&text.license.as_str())
    {
        return Err(config_error(format!(
            "the entry for `{name}` gives `{}` a `notice` or `upstream_words`, which are accepted only for {}: supply the whole `text:` instead",
            text.license,
            HOLDER_LINE_LICENCES.join(", ")
        )));
    }
    let given = [&text.text, &text.notice, &text.upstream_words]
        .into_iter()
        .filter(|field| field.is_some())
        .count();
    if given != 1 {
        return Err(config_error(format!(
            "the entry for `{name}` supplies `{}` with {given} of `text`, `notice` and `upstream_words`; give exactly one",
            text.license
        )));
    }
    Ok(())
}

fn config_error(reason: String) -> NoticesError {
    NoticesError::Config {
        path: CONFIG_PATH.to_owned(),
        reason,
    }
}
