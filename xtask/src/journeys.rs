//! `cargo xtask verify-journeys`: the table of what a person does with the installed product
//! (`tests/installed/journeys.yaml`) against the cases the installed lanes' result files show as run.
//!
//! A row is a journey a `hole` release must have a test for, with one cell per platform the release ships for.
//! [`Journeys::load`] validates the file once; [`gaps`] lists what a platform's run did not prove; [`RunKind::fails`]
//! decides which gaps stop the step.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use xtask_lib::version::{display_version, parse_release_tag, Group};

use crate::global_net_state_conformance::{absolutize, read_executed};
use crate::manifest::Platform;
use crate::stage_release::shipped;

/// The table, relative to the repo root.
const TABLE: &str = "tests/installed/journeys.yaml";

// Loaded table ========================================================================================================

/// The loaded table. Every journey has a cell for exactly the platforms a `hole` release ships for.
#[derive(Debug)]
pub(crate) struct Journeys {
    journeys: Vec<Journey>,
}

#[derive(Debug)]
struct Journey {
    id: String,
    cells: IndexMap<Platform, Cell>,
}

#[derive(Debug)]
enum Cell {
    /// No test runs the journey on this platform.
    None,
    /// The tests that run the journey on this platform. Never empty.
    Cases(Vec<Case>),
}

/// A test as a pytest JUnit file names it.
#[derive(Debug)]
struct Case {
    classname: String,
    name: String,
}

/// A cell this platform's run did not prove.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gap {
    /// The cell names a case that the lanes did not run, or skipped.
    NotRun { journey: String, case: String },
    /// No test runs the journey on this platform.
    Empty { journey: String },
}

/// What `ran` holds: each JUnit `classname` with the `name`s that ran (`junit_executed_tests`).
pub(crate) fn gaps(table: &Journeys, platform: Platform, ran: &BTreeMap<String, BTreeSet<String>>) -> Vec<Gap> {
    let mut out = Vec::new();
    for journey in &table.journeys {
        let cell = journey
            .cells
            .get(&platform)
            .expect("`Journeys::load` gave every journey a cell for every shipped platform, and `verify` checks the platform is one");
        match cell {
            Cell::None => out.push(Gap::Empty {
                journey: journey.id.clone(),
            }),
            Cell::Cases(cases) => {
                for case in cases {
                    if !ran.get(&case.classname).is_some_and(|names| names.contains(&case.name)) {
                        out.push(Gap::NotRun {
                            journey: journey.id.clone(),
                            case: case.to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

impl std::fmt::Display for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.classname, self.name)
    }
}

// Loading =============================================================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    installs: IndexMap<String, String>,
    journeys: Vec<RawJourney>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJourney {
    id: String,
    does: String,
    cells: IndexMap<String, noyalib::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCases {
    cases: Vec<String>,
    differs: Option<String>,
}

/// The reader's policy: a key written twice anywhere in the file is an error, and so are the YAML features the table
/// has no use for (a tag, a merge key), which would take the reader down paths that resolve keys before it checks them.
fn reader_config() -> noyalib::ParserConfig {
    noyalib::ParserConfig::new()
        .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
        .merge_key_policy(noyalib::MergeKeyPolicy::Error)
        .with_policy(noyalib::policy::DenyTags)
}

impl Journeys {
    /// Parse and validate `text` against `shipped`, the platforms a `hole` release ships for. An error names the row.
    pub(crate) fn load(text: &str, shipped: &[Platform]) -> Result<Self> {
        let raw: RawTable = noyalib::from_str_with_config(text, &reader_config()).context("parsing the table")?;
        check_platforms("`installs`", raw.installs.keys(), shipped)?;

        let mut ids = BTreeSet::new();
        let mut journeys = Vec::new();
        for row in raw.journeys {
            let id = row.id;
            ensure!(ids.insert(id.clone()), "journey `{id}`: the id is used twice");
            ensure!(!row.does.trim().is_empty(), "journey `{id}`: `does` is empty");
            check_platforms(&format!("journey `{id}`"), row.cells.keys(), shipped)?;

            let mut cells = IndexMap::new();
            for (platform, value) in row.cells {
                let context = format!("journey `{id}`, platform {platform}");
                let cell = parse_cell(value).with_context(|| context)?;
                cells.insert(
                    platform.parse::<Platform>().expect("checked by `check_platforms`"),
                    cell,
                );
            }
            journeys.push(Journey { id, cells });
        }
        Ok(Self { journeys })
    }
}

/// `keys`, which the reader has made distinct, are exactly the `shipped` platforms: no missing one, no extra.
fn check_platforms<'a>(what: &str, keys: impl Iterator<Item = &'a String>, shipped: &[Platform]) -> Result<()> {
    let mut seen = Vec::new();
    for key in keys {
        let platform: Platform = key
            .parse()
            .with_context(|| format!("{what}: platform {key:?} is not <os>/<arch>"))?;
        ensure!(
            shipped.contains(&platform),
            "{what}: {platform} is not a platform a `hole` release ships for ({})",
            join(shipped)
        );
        seen.push(platform);
    }
    for platform in shipped {
        ensure!(seen.contains(platform), "{what}: no entry for {platform}");
    }
    Ok(())
}

fn parse_cell(value: noyalib::Value) -> Result<Cell> {
    if value.as_str() == Some("none") {
        return Ok(Cell::None);
    }
    let raw: RawCases =
        noyalib::from_value(&value).context("the cell is neither `none` nor a mapping of `cases` and `differs`")?;
    ensure!(
        !raw.cases.is_empty(),
        "`cases` is empty: write `none` for a journey no test runs"
    );
    ensure!(
        raw.differs.is_some(),
        "no `differs`: write how the test differs from the person's journey, or an empty string when nothing does"
    );
    let cases = raw
        .cases
        .iter()
        .map(|text| {
            let (classname, name) = text
                .split_once("::")
                .with_context(|| format!("case {text:?} is not `classname::name`"))?;
            ensure!(
                !classname.is_empty() && !name.is_empty(),
                "case {text:?} is not `classname::name`"
            );
            Ok(Case {
                classname: classname.to_owned(),
                name: name.to_owned(),
            })
        })
        .collect::<Result<_>>()?;
    Ok(Cell::Cases(cases))
}

fn join(platforms: &[Platform]) -> String {
    platforms.iter().map(Platform::to_string).collect::<Vec<_>>().join(", ")
}

// The kind of run =====================================================================================================

/// What the step is checking for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RunKind {
    /// A pull request, a push to `main`, a release of another track.
    Ordinary,
    /// A release of `hole`.
    HoleRelease,
}

impl RunKind {
    fn of(tag: Option<&str>) -> Result<Self> {
        let Some(tag) = tag else { return Ok(Self::Ordinary) };
        let (group, _) = parse_release_tag(tag)?;
        Ok(match group {
            Group::Hole => Self::HoleRelease,
            Group::Garter => Self::Ordinary,
            Group::Galoshes => Self::Ordinary,
            Group::ExRay => Self::Ordinary,
        })
    }

    /// What this kind of run does with a gap, for the first line of the command's output.
    fn describe(self) -> &'static str {
        match self {
            Self::Ordinary => "a case that did not run fails the step, an empty cell is printed",
            Self::HoleRelease => "a case that did not run and an empty cell both fail the step",
        }
    }

    /// Which gaps stop the step in this kind of run.
    fn fails(self, gap: &Gap) -> bool {
        match (self, gap) {
            (Self::Ordinary, Gap::NotRun { .. }) => true,
            (Self::Ordinary, Gap::Empty { .. }) => false,
            (Self::HoleRelease, Gap::NotRun { .. }) => true,
            (Self::HoleRelease, Gap::Empty { .. }) => true,
        }
    }
}

// The command =========================================================================================================

/// Run `cargo xtask verify-journeys`. `results` is the folder of the lanes' JUnit files, relative to `repo_root`
/// unless absolute; `tag` is the release being cut, if any.
pub fn verify(repo_root: &Path, results: &Path, tag: Option<&str>) -> Result<()> {
    let kind = RunKind::of(tag)?;
    println!(
        "xtask: verify-journeys: {}; {}",
        tag.map_or_else(|| "no release tag".to_owned(), |tag| format!("release tag {tag}")),
        kind.describe()
    );

    let platform = Platform::host().context("unknown host platform")?;
    let manifest = crate::load_manifest_at(repo_root)?;
    let platforms = shipped(Group::Hole, &display_version(repo_root, Group::Hole), &manifest)?
        .into_iter()
        .map(|p| format!("{}/{}", p.os, p.arch).parse::<Platform>())
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        platforms.contains(&platform),
        "this run is on {platform}, which no `hole` release ships for ({}): run the step on one of them",
        join(&platforms)
    );

    let table_path = repo_root.join(TABLE);
    let text = std::fs::read_to_string(&table_path).with_context(|| format!("reading {}", table_path.display()))?;
    let table = Journeys::load(&text, &platforms).with_context(|| format!("loading {TABLE}"))?;

    let ran = read_results(&absolutize(repo_root, results))?;
    let all = gaps(&table, platform, &ran);

    for gap in &all {
        match gap {
            Gap::Empty { journey } => println!("  empty:   {journey}: no test runs it on {platform}"),
            Gap::NotRun { journey, case } => {
                println!("  not run: {journey}: {case}");
                let (classname, _) = case.split_once("::").expect("a case is `classname::name`");
                match ran.get(classname) {
                    Some(names) => println!(
                        "           the result files hold, for {classname}: {}",
                        names.iter().map(String::as_str).collect::<Vec<_>>().join(", ")
                    ),
                    None => println!("           the result files hold no case of {classname}"),
                }
            }
        }
    }

    let failing: Vec<&Gap> = all.iter().filter(|gap| kind.fails(gap)).collect();
    if failing.is_empty() {
        let empty = all.iter().filter(|gap| matches!(gap, Gap::Empty { .. })).count();
        println!(
            "xtask: verify-journeys: every case the table names for {platform} ran; {empty} of {} journeys have no test here",
            table.journeys.len()
        );
        return Ok(());
    }

    let mut message = format!(
        "{} gap(s) on {platform} stop this run; the table is {TABLE}:\n",
        failing.len()
    );
    for gap in failing {
        match gap {
            Gap::Empty { journey } => message.push_str(&format!("  journey `{journey}` has no test on {platform}\n")),
            Gap::NotRun { journey, case } => {
                message.push_str(&format!("  journey `{journey}` on {platform}: {case} did not run\n"))
            }
        }
    }
    bail!("{message}")
}

/// What every JUnit file in `folder` shows as run. A folder with no such file proves nothing, so it is an error.
fn read_results(folder: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut files = Vec::new();
    for entry in
        std::fs::read_dir(folder).with_context(|| format!("reading the results folder {}", folder.display()))?
    {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "xml") {
            files.push(path);
        }
    }
    files.sort();
    ensure!(
        !files.is_empty(),
        "no JUnit file (*.xml) in {}: the installed lanes write theirs there",
        folder.display()
    );
    read_executed(&files)
}
