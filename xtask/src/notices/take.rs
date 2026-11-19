//! Which licence a component is followed under, and the text printed for it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use spdx::expression::{ExprNode, Operator};
use spdx::{Expression, ParseMode};

use super::config::{Ecosystem, SuppliedText, TextBasis, TextPolicy, TextSource, HOLDER_LINE_LICENCES};
use super::{go, rust_std, Component, Config, NoticesError};

/// How a licence expression is read: what crates.io accepts (`/` for `OR`, `GPL-3.0+`, deprecated identifiers), except a
/// vague name (`Apache`, `BSD`, `MPL`), which is not read as one specific licence: the metadata does not say which
/// version it means.
pub(super) const EXPRESSION_MODE: ParseMode = ParseMode {
    allow_slash_as_or_operator: true,
    allow_imprecise_license_names: false,
    allow_postfix_plus_on_gpl: true,
    allow_deprecated: true,
    allow_unknown: false,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    /// The licence ids followed, in list order, joined by ` AND `.
    pub license: String,
    pub texts: Vec<LicenseText>,
    /// A sentence printed under the component's heading, before its texts.
    pub note: Option<String>,
}

/// One text to print for a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseText {
    /// The licence id of a standard or supplied text; the file name of a file of the component's.
    pub title: String,
    pub body: String,
    pub kind: TextKind,
    /// The upstream URL a supplied text was read from.
    pub source: Option<String>,
}

/// Whether a text is printed once for every component under it, or under the one component it belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TextKind {
    /// A standard text that names no holder.
    Shared,
    /// A text that belongs to this component: its file, a supplied text, a notice.
    Own,
}

impl TextKind {
    /// Whether the text is printed once for every component under it.
    pub fn is_printed_once(self) -> bool {
        match self {
            TextKind::Shared => true,
            TextKind::Own => false,
        }
    }
}

/// The licence followed for `component` and the text to print for it.
///
/// The licence is the component's SPDX expression read against the list in `config`: `AND` takes every part, `OR`
/// takes the alternative whose first-listed licence comes earliest. A licence that is not on the list fails.
///
/// What is printed follows each taken licence's [`TextPolicy`]:
/// - a licence whose standard text names no holder prints that text, shared with every component under it;
/// - a licence that asks for its own text prints every supplied text from the config when there is one, and otherwise
///   every licence file of the component, whole and as distributed. Metadata does not say which file belongs to which
///   licence (`ring` ships `LICENSE`, `LICENSE-BoringSSL` and `LICENSE-other-bits` under `Apache-2.0 AND ISC`; `aws-lc-sys`
///   puts several licences in one `LICENSE`), so printing all of them is the rule that never drops a required notice;
/// - a licence that asks for its `NOTICE` files prints the component's.
pub fn take(component: &Component, config: &Config) -> Result<Taken, NoticesError> {
    let label = component.label();
    let expression = expression_of(component, config)?;
    let ids = choose(component, &expression, config)?;
    if let Some(source) = config.text_source(component) {
        return text_from(source, component, ids.join(" AND "));
    }
    let supplied = config.supplied_texts(component);

    // A supplied text is for a followed licence whose text is the component's own.
    let asks_for_own_text = |id: &str| match config.text_policy(id).map(TextPolicy::basis) {
        Some(TextBasis::OwnFiles) => true,
        Some(TextBasis::Standard) | None => false,
    };
    for text in &supplied {
        let wanted = ids.iter().any(|id| *id == text.license && asks_for_own_text(id));
        if !wanted {
            return Err(NoticesError::UnusedText {
                component: label,
                name: component.name.clone(),
                license: text.license.clone(),
            });
        }
    }

    let mut texts = Vec::new();
    let mut unsupplied = None;
    let mut wants_notice = false;
    for id in &ids {
        let policy = config.text_policy(id).expect("a chosen licence is on the list");
        wants_notice |= policy.prints_notice_files();
        match policy.basis() {
            TextBasis::Standard => texts.push(standard_text(id)),
            TextBasis::OwnFiles => {
                let mut given = supplied.iter().filter(|text| text.license == *id).peekable();
                if given.peek().is_none() {
                    unsupplied = unsupplied.or(Some(id));
                }
                for text in given {
                    texts.extend(supplied_text(text));
                }
            }
        }
    }

    if let Some(id) = unsupplied {
        let files = read_files(component.source_dir.as_deref(), is_licence_file)?;
        if files.is_empty() {
            return Err(NoticesError::NoText {
                component: label,
                origin: component.origin,
                name: component.name.clone(),
                license: id.clone(),
            });
        }
        texts.extend(files);
    }
    if wants_notice {
        texts.extend(read_files(component.source_dir.as_deref(), is_notice_file)?);
    }

    Ok(Taken {
        license: ids.join(" AND "),
        texts,
        note: None,
    })
}

/// The texts of a component whose declared entry names a file outside the repository: that file, whole, and nothing
/// else, under the licence `license` that was chosen from the component's expression.
fn text_from(source: TextSource, component: &Component, license: String) -> Result<Taken, NoticesError> {
    match source {
        TextSource::RustToolchainCopyright => {
            let dir = component
                .text_dir
                .as_deref()
                .expect("`declared::collect` gives an entry with `text_from` its folder");
            rust_std::taken(dir, license)
        }
        TextSource::GoToolchain => {
            let dir = component
                .text_dir
                .as_deref()
                .expect("`declared::collect` gives an entry with `text_from` its folder");
            go::taken(dir, license)
        }
    }
}

/// The expression to read: the component's own, or the one the config sets for a component whose ecosystem declares none
/// or declares one that does not parse. A declared expression that parses is never replaced.
fn expression_of(component: &Component, config: &Config) -> Result<String, NoticesError> {
    let from_config = config
        .overrides_for(component)
        .find_map(|entry| entry.license.as_deref());
    match (&component.license, from_config) {
        (Some(declared), Some(entry)) if parses(declared) && declared != entry => Err(NoticesError::LicenseConflict {
            component: component.label(),
            name: component.name.clone(),
            version: component.version.clone(),
            declared: declared.clone(),
            entry: entry.to_owned(),
        }),
        (Some(declared), Some(_)) if parses(declared) => Ok(declared.clone()),
        (Some(_), Some(entry)) => Ok(entry.to_owned()),
        (Some(declared), None) => Ok(declared.clone()),
        (None, Some(entry)) => Ok(entry.to_owned()),
        (None, None) => Err(NoticesError::NoLicense {
            component: component.label(),
            ecosystem: ecosystem_of(component),
            name: component.name.clone(),
            version: component.version.clone(),
        }),
    }
}

/// The ecosystem of a component whose licence is missing or does not parse. A declared component has neither: its
/// licence is checked when the config loads.
fn ecosystem_of(component: &Component) -> Ecosystem {
    component
        .origin
        .ecosystem()
        .expect("a declared component's licence parses and is followed: `Config::parse` checked it")
}

fn parses(expression: &str) -> bool {
    Expression::parse_mode(expression, EXPRESSION_MODE).is_ok()
}

/// The ids of the licences followed under `expression`, in list order.
fn choose(component: &Component, expression: &str, config: &Config) -> Result<Vec<String>, NoticesError> {
    choose_licences(expression, config).map_err(|refusal| match refusal {
        Refusal::Unparsed(reason) => NoticesError::BadExpression {
            component: component.label(),
            ecosystem: ecosystem_of(component),
            name: component.name.clone(),
            version: component.version.clone(),
            expression: expression.to_owned(),
            reason,
        },
        Refusal::Unfollowable(_) => NoticesError::LicenseNotOnList {
            component: component.label(),
            expression: expression.to_owned(),
        },
    })
}

/// Why no licence is followed under an expression.
#[derive(Debug)]
pub(super) enum Refusal {
    /// The expression does not parse; holds the parser's reason.
    Unparsed(String),
    /// Every way to satisfy the expression needs a licence the list does not cover: what is not covered.
    Unfollowable(Vec<Uncovered>),
}

/// A part of an expression that the list does not cover.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Uncovered {
    /// A licence that is not on the list.
    NotListed(String),
    /// A licence with an exception: it changes the terms, so only an entry that lists it with the exception covers it.
    WithException(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Unparsed(reason) => write!(f, "it does not parse: {reason}"),
            Refusal::Unfollowable(uncovered) => {
                let reasons: Vec<String> = uncovered.iter().map(Uncovered::to_string).collect();
                f.write_str(&reasons.join("; "))
            }
        }
    }
}

impl std::fmt::Display for Uncovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Uncovered::NotListed(id) => write!(
                f,
                "`{id}` is not on `licenses:`: list it there, or state the licence the component's files carry"
            ),
            Uncovered::WithException(requirement) => write!(
                f,
                "`{requirement}` has an exception, which changes the terms, so no listed licence covers it: list \
                 `{requirement}` on `licenses:` with `text: own` when its terms are acceptable, or state the licence the \
                 component's files carry"
            ),
        }
    }
}

/// The ids of the licences followed under `expression`, in list order: what [`take()`] follows for a component, and what
/// [`Config`] accepts for a licence it states, so the two never disagree.
pub(super) fn choose_licences(expression: &str, config: &Config) -> Result<Vec<String>, Refusal> {
    let parsed = Expression::parse_mode(expression, EXPRESSION_MODE).map_err(|e| Refusal::Unparsed(e.to_string()))?;

    // Each stack entry is the list positions followed so far, or `None` when the part cannot be satisfied.
    let mut stack: Vec<Option<Vec<usize>>> = Vec::new();
    for node in parsed.iter() {
        match node {
            ExprNode::Req(req) => stack.push(config.rank_of(&req.req).map(|rank| vec![rank])),
            ExprNode::Op(operator) => {
                let right = stack.pop().expect("a parsed expression is well formed");
                let left = stack.pop().expect("a parsed expression is well formed");
                stack.push(match operator {
                    Operator::And => both(left, right),
                    Operator::Or => earlier(left, right),
                });
            }
        }
    }

    match stack.pop().flatten() {
        Some(followed) => Ok(followed
            .into_iter()
            .map(|rank| config.licenses[rank].id.clone())
            .collect()),
        None => {
            let mut uncovered = Vec::new();
            for requirement in parsed.requirements().filter(|r| config.rank_of(&r.req).is_none()) {
                let part = match requirement.req.addition {
                    Some(_) => Uncovered::WithException(requirement.req.to_string()),
                    None => Uncovered::NotListed(requirement.req.license.to_string()),
                };
                if !uncovered.contains(&part) {
                    uncovered.push(part);
                }
            }
            Err(Refusal::Unfollowable(uncovered))
        }
    }
}

fn both(left: Option<Vec<usize>>, right: Option<Vec<usize>>) -> Option<Vec<usize>> {
    let (mut left, right) = (left?, right?);
    left.extend(right);
    left.sort_unstable();
    left.dedup();
    Some(left)
}

/// Of two alternatives, the one whose first-listed licence is listed earlier.
fn earlier(left: Option<Vec<usize>>, right: Option<Vec<usize>>) -> Option<Vec<usize>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (left, right) => left.or(right),
    }
}

fn standard_text(id: &str) -> LicenseText {
    LicenseText {
        title: id.to_owned(),
        body: standard_body(id).to_owned(),
        kind: TextKind::Shared,
        source: None,
    }
}

/// The standard text of the licence `id`, when the spdx crate has one.
pub(super) fn standard_text_of(id: &str) -> Option<&'static str> {
    spdx::license_id(id)
        .map(|known| known.text())
        .filter(|text| !text.is_empty())
}

/// The standard text of `id`, a licence the generator knows has one: [`Config::parse`] refuses a listed licence that
/// prints its standard text and has none, a test pins [`HOLDER_LINE_LICENCES`], and every render prints Hole's own.
pub(super) fn standard_body(id: &str) -> &'static str {
    standard_text_of(id).expect("the licence is one whose standard text the config or a test checked")
}

/// What a supplied text prints: the text itself; a holder line above the standard text; or, for an upstream that ships
/// no licence text, its own words and then the standard text without a copyright line.
fn supplied_text(supplied: &SuppliedText) -> Vec<LicenseText> {
    let own = |title: String, body: String| LicenseText {
        title,
        body,
        kind: TextKind::Own,
        source: Some(supplied.source.clone()),
    };
    let id = &supplied.license;
    match (&supplied.text, &supplied.notice, &supplied.upstream_words) {
        (Some(text), None, None) => vec![own(id.clone(), text.clone())],
        (None, Some(notice), None) => vec![own(
            id.clone(),
            format!("{notice}\n\n{}", standard_text_without_holder(id)),
        )],
        (None, None, Some(words)) => {
            let standard = LicenseText {
                title: format!("{id} standard text, without a copyright line: upstream names no holder"),
                body: standard_text_without_holder(id),
                kind: TextKind::Own,
                source: None,
            };
            vec![
                own(format!("upstream's own words on the {id} licence"), words.clone()),
                standard,
            ]
        }
        _ => unreachable!("`Config::parse` requires exactly one of `text`, `notice` and `upstream_words`"),
    }
}

/// The standard text of `id` for printing beside a holder line or upstream's words: without the line its template
/// leaves for a holder.
fn standard_text_without_holder(id: &str) -> String {
    debug_assert!(
        HOLDER_LINE_LICENCES.contains(&id),
        "`Config::parse` accepts a holder line only for {HOLDER_LINE_LICENCES:?}"
    );
    without_copyright_line(standard_body(id))
}

/// A standard text without the line its template leaves for a holder (`Copyright (c) <year> <copyright holders>`),
/// and the blank line after it.
fn without_copyright_line(text: &str) -> String {
    let is_template_line = |line: &str| {
        let line = line.trim_start().to_ascii_lowercase();
        line.starts_with("copyright") && line.contains('<')
    };
    let mut out = String::with_capacity(text.len());
    let mut dropped = false;
    for line in text.split_inclusive('\n') {
        if is_template_line(line) {
            dropped = true;
            continue;
        }
        if dropped && line.trim().is_empty() {
            dropped = false;
            continue;
        }
        dropped = false;
        out.push_str(line);
    }
    out
}

const LICENCE_NAMES: &[&str] = &["license", "licence", "copying", "unlicense"];

const NOTICE_NAMES: &[&str] = &["notice"];

/// The extensions of files that are code or data of a package. A name that ends in one (`license.go`,
/// `copying_test.go`) is a source file that happens to start like a licence's. A closed list of what is NOT a licence
/// file fails open: an extension missing from it prints one extra file, where a list of what is one could drop the
/// notice of a component (`LICENSE.httprouter`, `LICENSE.MIT`).
const SOURCE_EXTENSIONS: &[&str] = &[
    "go", "rs", "c", "h", "cc", "cpp", "hpp", "s", "py", "js", "ts", "sh", "json", "toml", "yaml", "yml", "mod", "sum",
];

/// Whether `lowercase_name` starts with one of `names` and does not end in a [`SOURCE_EXTENSIONS`] extension
/// (`LICENSE.MIT`, `COPYING3` match; `license.go` does not).
fn is_named(lowercase_name: &str, names: &[&str]) -> bool {
    if lowercase_name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SOURCE_EXTENSIONS.contains(&extension))
    {
        return false;
    }
    names.iter().any(|name| lowercase_name.starts_with(name))
}

fn is_licence_file(lowercase_name: &str) -> bool {
    is_named(lowercase_name, LICENCE_NAMES)
}

/// The directories already examined for a licence file, and what each held.
#[derive(Default)]
pub(super) struct LicenceDirs {
    held: HashMap<PathBuf, bool>,
}

impl LicenceDirs {
    /// Whether `dir` holds a licence file at its top, decided by the names in it: nothing is read. A directory is
    /// listed the first time it is asked about and never again, so the answer for a directory is the one it first had.
    pub(super) fn has_licence_file(&mut self, dir: &Path) -> Result<bool, NoticesError> {
        if let Some(held) = self.held.get(dir) {
            return Ok(*held);
        }
        let held = !licence_files_in(dir, is_licence_file)?.is_empty();
        self.held.insert(dir.to_owned(), held);
        Ok(held)
    }
}

fn is_notice_file(lowercase_name: &str) -> bool {
    is_named(lowercase_name, NOTICE_NAMES)
}

/// Read, as they are, the files at the top of `dir` whose lowercase name `wanted` accepts.
fn read_files(dir: Option<&Path>, wanted: fn(&str) -> bool) -> Result<Vec<LicenseText>, NoticesError> {
    let Some(dir) = dir else { return Ok(Vec::new()) };
    licence_files_in(dir, wanted)?
        .into_iter()
        .map(|(name, path)| {
            let bytes = std::fs::read(&path).map_err(|source| NoticesError::Io {
                path: path.clone(),
                source,
            })?;
            let body = String::from_utf8(bytes).map_err(|_| NoticesError::NotUtf8 { path })?;
            Ok(LicenseText {
                title: name,
                body,
                kind: TextKind::Own,
                source: None,
            })
        })
        .collect()
}

/// The names and paths of those files, sorted. Nothing is read.
fn licence_files_in(dir: &Path, wanted: fn(&str) -> bool) -> Result<Vec<(String, PathBuf)>, NoticesError> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| NoticesError::Io { path, source }
    };

    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io(dir))? {
        let entry = entry.map_err(io(dir))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if wanted(&name.to_ascii_lowercase()) && entry.path().is_file() {
            found.push((name, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}
