//! The macOS plugin folder: what the bridge makes it hold, and how it converges there.
//!
//! `hole` carries the two plugin binaries ([`EmbeddedPlugin`]). At every service start, before the bridge serves,
//! it makes the plugin folder hold exactly those files plus a layout stamp. [`decide_repair`] is pure: it reads a
//! [`Survey`] of the folder and says what to do as data ([`RepairPlan`]); `apply` (unix) does it.
//!
//! Every step converges: each file lands by temp and rename and the stamp is stored last, so a crash mid-repair
//! leaves a folder the next start finishes.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use util::versioned_file::WhyUnreadable;

use layout_stamp::StampState;

pub mod layout_stamp;

#[cfg(unix)]
pub mod apply;

// Types ===============================================================================================================

/// Where the plugin folder is and who owns it. A parameter so a test runs in a temp dir as the test user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDirLayout {
    pub dir: PathBuf,
    /// The `(uid, gid)` the folder and its files belong to: root's in production.
    pub owner: (u32, u32),
}

impl PluginDirLayout {
    /// A layout at `dir`, a folder the test made, owned by whoever owns it.
    #[cfg(all(test, unix))]
    pub(crate) fn owned_by_this_process(dir: &std::path::Path) -> Self {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(dir).expect("the test's folder exists");
        Self {
            dir: dir.to_path_buf(),
            owner: (meta.uid(), meta.gid()),
        }
    }
}

/// A plugin binary compiled into `hole`.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedPlugin {
    /// The file name the plugin takes in the folder.
    pub name: &'static str,
    pub bytes: &'static [u8],
    /// SHA-256 of `bytes`, computed when `hole` was built.
    pub sha256: [u8; 32],
}

impl EmbeddedPlugin {
    /// What the pure core needs of this plugin. Empty bytes mean this build carries no payload (a dev or test build
    /// with stub sidecars).
    pub fn carried(&self) -> Carried<'_> {
        Carried {
            name: self.name,
            sha256: (!self.bytes.is_empty()).then_some(self.sha256),
        }
    }
}

/// A plugin as [`decide_repair`] sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carried<'a> {
    pub name: &'a str,
    /// `None`: this build carries no payload for it.
    pub sha256: Option<[u8; 32]>,
}

/// What the folder is, read once. An enum so that a stamp read from a folder that is not sound cannot be expressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Survey {
    /// Nothing at the folder's name.
    NoDir,
    /// Something is there that is not a folder of the owner's that no one else can write: a link or file, another
    /// owner or group, or a mode that group or others can write. Nothing in it is trusted, so no stamp was read.
    UnsoundDir,
    SoundDir {
        record: StampState,
        /// Whether the folder's mode is the one it must have; a sound folder with another mode is only secured.
        mode_right: bool,
        /// Each carried plugin, once, then every other name in the folder as [`Found::Unexpected`].
        entries: Vec<(String, Found)>,
    },
}

/// One name in the folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// A carried plugin that is not there.
    Missing,
    /// A carried plugin that is there with the carried bytes, the layout's owner and group, mode 0755 and one name.
    Matches,
    /// A carried plugin that is there as a regular file and is not what it must be (other bytes, owner, mode or a second
    /// name, or this build has no bytes to compare with).
    Differs,
    /// A carried plugin's name that holds something that is not a regular file.
    Blocked,
    /// A name that is not a carried plugin or the stamp.
    Unexpected,
}

/// One thing repair does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Make the folder, root-owned, mode 0755.
    CreateDir,
    /// Hand a sound folder to its owner and set its mode: nothing in it changes.
    SecureDir,
    /// Take over what is at the folder's name: unlink a link or file there, or empty a folder and hand it to its
    /// owner; then make it as [`Step::CreateDir`] does.
    RebuildDir,
    /// Write the carried plugin of this name, atomically.
    Write(String),
    Remove(String),
    StoreRecord,
}

impl Step {
    /// Whether the step says the folder is converged, so it runs only when every step before it succeeded.
    pub fn claims_convergence(&self) -> bool {
        match self {
            Step::StoreRecord => true,
            Step::CreateDir => false,
            Step::SecureDir => false,
            Step::RebuildDir => false,
            Step::Write(_) => false,
            Step::Remove(_) => false,
        }
    }
}

/// What repair says about what it did not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// This build carries no bytes for the plugin, so nothing was written for it.
    NoPayload(String),
    /// The folder is not sound and was not rebuilt, because that would remove a plugin this build cannot replace.
    DirLeftAlone,
    /// The stamp is one this release cannot read: nothing in the folder was changed.
    RecordRefused(WhyUnreadable),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairPlan {
    pub steps: Vec<Step>,
    pub notes: Vec<Note>,
}

// Decision ============================================================================================================

/// What to do about a folder, given what it holds and what `hole` carries. One match on [`Survey`]; each cell is its
/// own arm and equal consequences are written out, never grouped.
pub fn decide_repair(survey: &Survey, carried: &[Carried<'_>]) -> RepairPlan {
    match survey {
        Survey::NoDir => {
            let mut plan = RepairPlan {
                steps: vec![Step::CreateDir],
                notes: Vec::new(),
            };
            write_all(&mut plan, carried);
            plan.steps.push(Step::StoreRecord);
            plan
        }
        Survey::UnsoundDir => {
            let mut plan = RepairPlan::default();
            let payloadless: Vec<&Carried<'_>> = carried.iter().filter(|c| c.sha256.is_none()).collect();
            if payloadless.is_empty() {
                plan.steps.push(Step::RebuildDir);
                write_all(&mut plan, carried);
                plan.steps.push(Step::StoreRecord);
            } else {
                plan.notes.push(Note::DirLeftAlone);
                plan.notes
                    .extend(payloadless.iter().map(|c| Note::NoPayload(c.name.to_owned())));
            }
            plan
        }
        Survey::SoundDir {
            record,
            mode_right,
            entries,
        } => decide_sound(*record, *mode_right, entries, carried),
    }
}

/// A `Write` for every carried plugin that has a payload, a note for each that has not.
fn write_all(plan: &mut RepairPlan, carried: &[Carried<'_>]) {
    for plugin in carried {
        match plugin.sha256 {
            Some(_) => plan.steps.push(Step::Write(plugin.name.to_owned())),
            None => plan.notes.push(Note::NoPayload(plugin.name.to_owned())),
        }
    }
}

fn decide_sound(
    record: StampState,
    mode_right: bool,
    entries: &[(String, Found)],
    carried: &[Carried<'_>],
) -> RepairPlan {
    // A stamp this release cannot read: whatever else is wrong, nothing is changed.
    if let StampState::Unreadable(why) = record {
        return RepairPlan {
            steps: Vec::new(),
            notes: vec![Note::RecordRefused(why)],
        };
    }
    let mut plan = RepairPlan::default();
    if !mode_right {
        plan.steps.push(Step::SecureDir);
    }
    let mut removals = Vec::new();
    for (name, found) in entries {
        let has_payload = carried.iter().any(|c| c.name == name && c.sha256.is_some());
        match (found, has_payload) {
            (Found::Missing, true) => plan.steps.push(Step::Write(name.clone())),
            (Found::Missing, false) => plan.notes.push(Note::NoPayload(name.clone())),
            (Found::Matches, true) => {}
            (Found::Matches, false) => unreachable!("a plugin with no payload has no hash to match"),
            (Found::Differs, true) => plan.steps.push(Step::Write(name.clone())),
            // The file stays: removing a plugin this build cannot replace would leave none.
            (Found::Differs, false) => plan.notes.push(Note::NoPayload(name.clone())),
            (Found::Blocked, true) => {
                plan.steps.push(Step::Remove(name.clone()));
                plan.steps.push(Step::Write(name.clone()));
            }
            (Found::Blocked, false) => plan.notes.push(Note::NoPayload(name.clone())),
            (Found::Unexpected, _) => removals.push(Step::Remove(name.clone())),
        }
    }
    plan.steps.extend(removals);
    match record {
        StampState::Nothing => plan.steps.push(Step::StoreRecord),
        StampState::Current => {}
        StampState::Unreadable(_) => unreachable!("an unreadable stamp returned above"),
    }
    plan
}

// Outcome =============================================================================================================

/// How a repair went. Owns the log level of each kind in one match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairOutcome {
    /// The folder already held what `hole` carries.
    Converged,
    Repaired {
        steps: usize,
    },
    /// A step failed, or a plugin has no payload in this build: the folder may not hold what `hole` carries.
    Degraded {
        notes: Vec<Note>,
        failures: Vec<String>,
    },
    /// The stamp is one this release cannot read: the folder was left as it was.
    Refused(WhyUnreadable),
}

impl RepairOutcome {
    /// The outcome of running `plan`, whose steps failed as `failures` says.
    pub fn of(plan: &RepairPlan, failures: Vec<String>) -> Self {
        let refused = plan.notes.iter().find_map(|note| match note {
            Note::RecordRefused(why) => Some(*why),
            Note::NoPayload(_) | Note::DirLeftAlone => None,
        });
        if let Some(why) = refused {
            return RepairOutcome::Refused(why);
        }
        if !failures.is_empty() || !plan.notes.is_empty() {
            return RepairOutcome::Degraded {
                notes: plan.notes.clone(),
                failures,
            };
        }
        match plan.steps.len() {
            0 => RepairOutcome::Converged,
            steps => RepairOutcome::Repaired { steps },
        }
    }

    pub fn level(&self) -> tracing::Level {
        match self {
            RepairOutcome::Converged => tracing::Level::DEBUG,
            RepairOutcome::Repaired { .. } => tracing::Level::INFO,
            RepairOutcome::Degraded { .. } => tracing::Level::ERROR,
            RepairOutcome::Refused(_) => tracing::Level::ERROR,
        }
    }

    /// Logs the outcome at its level. Names no path: the plugin folder is a fixed system path and every other layout
    /// is a test's.
    pub fn log(&self) {
        match self {
            RepairOutcome::Converged => tracing::debug!("plugin folder already holds the bundled plugins"),
            RepairOutcome::Repaired { steps } => tracing::info!(steps, "plugin folder repaired"),
            RepairOutcome::Degraded { notes, failures } => {
                tracing::error!(?notes, ?failures, "plugin folder may not hold the bundled plugins")
            }
            RepairOutcome::Refused(why) => tracing::error!(
                %why,
                "the plugin folder's layout file cannot be read: the folder was left as it is, and connects are refused"
            ),
        }
    }
}

// Verdict =============================================================================================================

/// How this start prepared what plugins run from: the plugin folder's repair and the runtime folder's making, which run
/// beside each other. Plugins run with the runtime folder as their scratch space, so a start that could not make it is
/// as untrusted as one whose repair failed.
#[derive(Debug)]
pub struct Prepared {
    folder: RepairOutcome,
    /// Why the runtime folder could not be made; `None` once it was.
    runtime_failure: Option<std::io::Error>,
}

impl Prepared {
    pub fn new(folder: RepairOutcome, runtime: std::io::Result<()>) -> Self {
        Self {
            folder,
            runtime_failure: runtime.err(),
        }
    }

    /// Logs the folder's outcome and, apart from it, the runtime folder's failure: neither hides the other.
    pub fn log(&self) {
        self.folder.log();
        if let Some(failure) = &self.runtime_failure {
            tracing::error!(
                error = failure as &dyn std::error::Error,
                "the plugin runtime folder could not be made: plugins are not run"
            );
        }
    }

    /// What this preparation lets plugins do. One match over every cell; when both failed, the folder is the cause named
    /// (an unreadable stamp is the one the user can act on) and the runtime folder's is in the log.
    pub fn standing(&self) -> Standing {
        match (&self.folder, &self.runtime_failure) {
            (RepairOutcome::Converged, None) => Standing::Vouched,
            (RepairOutcome::Repaired { .. }, None) => Standing::Vouched,
            (RepairOutcome::Converged, Some(_)) => Standing::RuntimeDirNotMade,
            (RepairOutcome::Repaired { .. }, Some(_)) => Standing::RuntimeDirNotMade,
            (RepairOutcome::Degraded { .. }, None) => Standing::FolderNotRepaired,
            (RepairOutcome::Degraded { .. }, Some(_)) => Standing::FolderNotRepaired,
            (RepairOutcome::Refused(why), None) => Standing::StampUnreadable(*why),
            (RepairOutcome::Refused(why), Some(_)) => Standing::StampUnreadable(*why),
        }
    }
}

/// Whether this start's preparation vouches for the folders plugins run from, and the cause when it does not. The
/// plugin source turns each cause into the error its caller shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The folder holds what `hole` carries and the runtime folder exists.
    Vouched,
    /// No preparation has run yet.
    NotPrepared,
    /// The repair could not make the folder hold what `hole` carries.
    FolderNotRepaired,
    /// The runtime folder could not be made.
    RuntimeDirNotMade,
    /// The stamp is one this release cannot read, so the folder was left as it was.
    StampUnreadable(WhyUnreadable),
}

/// The preparation of this start, shared between whoever prepares and whoever resolves plugins from the folders.
/// Cloned handles see the same one.
#[derive(Debug, Clone, Default)]
pub struct RepairVerdict(Arc<OnceLock<Prepared>>);

impl RepairVerdict {
    /// Records how the preparation went. A start prepares once.
    pub fn record(&self, prepared: Prepared) {
        let first = self.0.set(prepared).is_ok();
        debug_assert!(first, "a start prepares the plugin folder once");
    }

    /// The [`Prepared::standing`] of the recorded preparation; before any has run, none may.
    pub fn standing(&self) -> Standing {
        match self.0.get() {
            Some(prepared) => prepared.standing(),
            None => Standing::NotPrepared,
        }
    }
}

#[cfg(test)]
#[path = "plugin_repair_tests.rs"]
mod plugin_repair_tests;
