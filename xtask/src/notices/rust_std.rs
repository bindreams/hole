//! The Rust standard library's notices: the toolchain's own copyright file for it.
//!
//! The standard library carries third-party crates and the Unicode tables. The Rust project ships a copyright file for
//! it with the `rustc` component of every toolchain, and the licence texts that file names by identifier.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use spdx::Expression;

use super::take::{LicenseText, Taken, TextKind, EXPRESSION_MODE};
use super::NoticesError;

const COPYRIGHT_FILE: &str = "COPYRIGHT-library.html";

/// Where the licence texts the copyright file names by identifier are, in [`doc_dir`].
const LICENSES_DIR: &str = "licenses";

const NOTE: &str =
    "The copyright file below lists the standard library's build and test tools as well, so it names more than \
                    is linked into Hole.";

/// The toolchain of one `rustc`: where it is installed and which release it is.
#[derive(Clone, Debug)]
pub struct Toolchain {
    pub sysroot: PathBuf,
    /// The `release` of `rustc -vV`, as `1.98.0`.
    pub version: String,
}

/// The toolchain of the `rustc` that runs at `repo_root`: the one `rust-toolchain.toml` selects there, unless the
/// environment overrides it (`RUSTUP_TOOLCHAIN`, `cargo +nightly`, another `rustc` first on `PATH`). The version is
/// read from the `rustc` in that sysroot, so the two always belong together.
pub fn toolchain(repo_root: &Path) -> Result<Toolchain, NoticesError> {
    let mut command = Command::new("rustc");
    command.args(["--print", "sysroot"]).current_dir(repo_root);
    let sysroot = PathBuf::from(printed(&mut command)?.trim());

    let mut command = Command::new(
        sysroot
            .join("bin")
            .join(format!("rustc{}", std::env::consts::EXE_SUFFIX)),
    );
    command.arg("-vV").current_dir(repo_root);
    let version = release_of(&printed(&mut command)?).map_err(|reason| NoticesError::Tool {
        command: crate::command::describe(&command),
        reason,
    })?;
    Ok(Toolchain { sysroot, version })
}

impl Toolchain {
    /// Fails unless this is the release `pinned` names (the `channel` of `rust-toolchain.toml`): the copyright file read
    /// from the sysroot is the toolchain's own, and the notices print the pinned version beside it.
    pub fn require_pinned(&self, pinned: &str) -> Result<(), NoticesError> {
        if self.version == pinned {
            return Ok(());
        }
        Err(NoticesError::Tool {
            command: "compare the toolchain with rust-toolchain.toml".to_owned(),
            reason: format!(
                "the `rustc` that runs here is {} ({}), and rust-toolchain.toml pins {pinned}; the notices must come from the \
                 pinned toolchain (an override such as `cargo +<toolchain>`, RUSTUP_TOOLCHAIN or another `rustc` first on \
                 PATH selects another one)",
                self.version,
                self.sysroot.display()
            ),
        })
    }
}

/// The `release` line of `rustc -vV` output.
pub fn release_of(printed: &str) -> Result<String, String> {
    printed
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .map(|release| release.trim().to_owned())
        .ok_or_else(|| "printed no `release:` line".to_owned())
}

/// What `command` printed to stdout, as UTF-8 text.
fn printed(command: &mut Command) -> Result<String, NoticesError> {
    let line = crate::command::describe(command);
    let tool = |reason: String| NoticesError::Tool {
        command: line.clone(),
        reason,
    };
    let output = crate::command::run_captured(command).map_err(|e| tool(format!("{e:#}")))?;
    String::from_utf8(output.stdout).map_err(|_| tool("printed output that is not UTF-8".to_owned()))
}

/// The folder of a sysroot that holds the toolchain's copyright files and licence texts.
pub fn doc_dir(sysroot: &Path) -> PathBuf {
    sysroot.join("share/doc/rust")
}

/// What is printed for the standard library, under `license`: the body of the copyright file of `doc_dir` converted to text,
/// then the text of every licence that file names for its own source files by identifier alone, from the toolchain's
/// `licenses/`. A missing file fails, naming its path.
pub fn taken(doc_dir: &Path, license: String) -> Result<Taken, NoticesError> {
    let path = doc_dir.join(COPYRIGHT_FILE);
    let doc = dom_query::Document::from(read(&path)?.as_str());

    // The body only: the head's `<title>` repeats the body's `<h1>`. The blank lines the markup leaves around it are not text.
    let mut texts = vec![LicenseText {
        title: COPYRIGHT_FILE.to_owned(),
        body: doc.select("body").formatted_text().trim().to_owned(),
        kind: TextKind::Own,
        source: None,
    }];

    for id in named_by_identifier(&doc)? {
        let file = format!("{LICENSES_DIR}/{id}.txt");
        texts.push(LicenseText {
            body: read(&doc_dir.join(&file))?,
            title: file,
            kind: TextKind::Own,
            source: None,
        });
    }

    Ok(Taken {
        license,
        texts,
        note: Some(NOTE.to_owned()),
    })
}

fn read(path: &Path) -> Result<String, NoticesError> {
    std::fs::read_to_string(path).map_err(|source| match source.kind() {
        std::io::ErrorKind::InvalidData => NoticesError::NotUtf8 { path: path.to_owned() },
        _ => NoticesError::Io {
            path: path.to_owned(),
            source,
        },
    })
}

/// The licences, and licence exceptions, that the in-tree files of the copyright file are under. The file lists them by
/// identifier and carries no text for them; the packages that follow are listed with their texts. Fails when there are
/// none.
fn named_by_identifier(doc: &dom_query::Document) -> Result<BTreeSet<String>, NoticesError> {
    let mut ids = BTreeSet::new();
    for paragraph in doc.select("body > div p").iter() {
        let text = paragraph.text();
        let Some(expression) = text.trim().strip_prefix("License:") else {
            continue;
        };
        let parsed = Expression::parse_mode(expression.trim(), EXPRESSION_MODE).map_err(|e| NoticesError::Tool {
            command: format!("read {COPYRIGHT_FILE}"),
            reason: format!("the licence `{}` does not parse: {e}", expression.trim()),
        })?;
        for requirement in parsed.requirements() {
            ids.insert(requirement.req.license.to_string());
            if let Some(exception) = &requirement.req.addition {
                ids.insert(exception.to_string());
            }
        }
    }
    // The file's own source files are always under some licence, so an empty set means the structure read here changed.
    if ids.is_empty() {
        return Err(NoticesError::Tool {
            command: format!("read {COPYRIGHT_FILE}"),
            reason: "found no `License:` paragraph under a top-level `div`: the file's structure is not the one this \
                     generator reads, and the texts of the licences it names would be dropped"
                .to_owned(),
        });
    }
    Ok(ids)
}
