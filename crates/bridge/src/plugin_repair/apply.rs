//! The I/O half of plugin-folder repair: [`survey`] reads the folder, [`apply`] runs a plan. Unix only: the folder's
//! soundness is its owner and mode.
//!
//! Every file operation goes through [`util::dir::Dir`], one handle per step, so no name is acted on by path.

use std::ffi::OsStr;
use std::fs::{Metadata, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use util::dir::{Dir, EntryKind, OpenFile, Refusal};

use super::layout_stamp::{self, STAMP_FILE_NAME};
use super::{decide_repair, Carried, EmbeddedPlugin, Found, PluginDirLayout, RepairOutcome, RepairPlan, Step, Survey};

/// The mode a plugin has in the folder, and the folder itself.
const MODE: u32 = 0o755;

/// Makes the folder hold what `plugins` carry, as far as it can, and says how that went.
pub fn repair(layout: &PluginDirLayout, plugins: &[EmbeddedPlugin]) -> RepairOutcome {
    let carried: Vec<Carried<'_>> = plugins.iter().map(EmbeddedPlugin::carried).collect();
    let survey = match survey(layout, &carried) {
        Ok(survey) => survey,
        Err(e) => {
            return RepairOutcome::Degraded {
                notes: Vec::new(),
                failures: vec![format!("could not read the plugin folder: {e}")],
            }
        }
    };
    let plan = decide_repair(&survey, &carried);
    let mut failures = apply(&plan, layout, plugins);
    if failures.is_empty() && !plan.steps.is_empty() {
        failures = left_to_do(layout, &carried);
    }
    RepairOutcome::of(&plan, failures)
}

/// What the folder still needs after steps that all succeeded, read from the folder again: a step's success says it
/// ran, not what the volume made of it.
fn left_to_do(layout: &PluginDirLayout, carried: &[Carried<'_>]) -> Vec<String> {
    match survey(layout, carried) {
        Ok(after) => decide_repair(&after, carried)
            .steps
            .iter()
            .map(|step| format!("{}: still needed after the repair", describe(step)))
            .collect(),
        Err(e) => vec![format!("could not read the plugin folder after the repair: {e}")],
    }
}

// Survey ==============================================================================================================

/// What the folder is, judged through handles. A sound folder comes with its open handle and metadata.
enum Judged {
    NoDir,
    Unsound,
    Sound { dir: Dir, meta: Metadata },
}

/// Whether the folder is there and is one of the owner's that no one else can write. Reads nothing in it.
fn judge(layout: &PluginDirLayout) -> io::Result<Judged> {
    let (parent, leaf) = split(&layout.dir)?;
    let parent = match Dir::open(parent, false, Some(layout.owner)) {
        Ok(parent) => parent,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Judged::NoDir),
        Err(e) => return Err(e),
    };
    // Judged by the parent's handle: the walk to the folder itself would follow a link the system owns.
    match parent.kind_of(leaf)? {
        None => return Ok(Judged::NoDir),
        Some(EntryKind::Directory) => {}
        Some(EntryKind::Symlink | EntryKind::File | EntryKind::Other) => return Ok(Judged::Unsound),
    }
    let dir = match Dir::open(&layout.dir, false, Some(layout.owner)) {
        Ok(dir) => dir,
        // A link into another owner's folder (the walk's rule), or a folder owned by neither the owner nor this process:
        // not the folder repair made.
        Err(e) if Refusal::from_error(&e).is_some() => return Ok(Judged::Unsound),
        // A link followed to nothing.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Judged::NoDir),
        Err(e) => return Err(e),
    };
    let meta = dir.file().metadata()?;
    if (meta.uid(), meta.gid()) != layout.owner || meta.mode() & 0o022 != 0 {
        return Ok(Judged::Unsound);
    }
    Ok(Judged::Sound { dir, meta })
}

/// Reads the folder: whether it is there, whether it is one of the owner's that no one else can write, what the stamp
/// says and what each name holds. The stamp is read only from a folder that is sound.
fn survey(layout: &PluginDirLayout, carried: &[Carried<'_>]) -> io::Result<Survey> {
    let (dir, meta) = match judge(layout)? {
        Judged::NoDir => return Ok(Survey::NoDir),
        Judged::Unsound => return Ok(Survey::UnsoundDir),
        Judged::Sound { dir, meta } => (dir, meta),
    };
    let record = layout_stamp::state(&layout.dir);
    let mut entries = Vec::with_capacity(carried.len());
    for plugin in carried {
        entries.push((plugin.name.to_owned(), found(&dir, plugin, layout.owner)?));
    }
    let mut others = Vec::new();
    for name in dir.reader()?.names()? {
        let name = name.to_string_lossy().into_owned();
        if !is_carried_name(&dir, &name, carried)? {
            others.push(name);
        }
    }
    others.sort();
    entries.extend(others.into_iter().map(|name| (name, Found::Unexpected)));
    Ok(Survey::SoundDir {
        record,
        mode_right: meta.mode() & 0o7777 == MODE,
        entries,
    })
}

/// Whether `name` is a carried plugin's or the stamp's, as the volume reads names: a case-insensitive volume lists
/// `Ex-Ray` for what is opened as `ex-ray`, and removing it would remove the plugin. A name that differs only in case
/// is the same entry when it is the same file, and a stray when it is not (a case-sensitive volume).
fn is_carried_name(dir: &Dir, name: &str, carried: &[Carried<'_>]) -> io::Result<bool> {
    for exact in carried.iter().map(|c| c.name).chain([STAMP_FILE_NAME]) {
        if name == exact {
            return Ok(true);
        }
        if !name.eq_ignore_ascii_case(exact) {
            continue;
        }
        let (listed, opened) = (dir.id_of(OsStr::new(name))?, dir.id_of(OsStr::new(exact))?);
        if listed.is_some() && listed == opened {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the carried plugin's name holds, opened without following a link and judged through the open handle.
fn found(dir: &Dir, plugin: &Carried<'_>, owner: (u32, u32)) -> io::Result<Found> {
    let mut file = match dir.open_file(OsStr::new(plugin.name), OpenFile::Read) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Found::Missing),
        Err(e) if Refusal::from_error(&e).is_some() => return Ok(Found::Blocked),
        // What the open cannot read at all (a socket) is not a plugin either; only a regular file that fails to read is
        // an error.
        Err(e) => {
            return match dir.kind_of(OsStr::new(plugin.name))? {
                None => Ok(Found::Missing),
                Some(EntryKind::File) => Err(e),
                Some(EntryKind::Symlink | EntryKind::Directory | EntryKind::Other) => Ok(Found::Blocked),
            }
        }
    };
    let meta = file.metadata()?;
    let as_it_must_be = (meta.uid(), meta.gid()) == owner && meta.mode() & 0o7777 == MODE && meta.nlink() == 1;
    if !as_it_must_be {
        return Ok(Found::Differs);
    }
    match plugin.sha256 {
        Some(want) if hash_of(&mut file)? == want => Ok(Found::Matches),
        Some(_) => Ok(Found::Differs),
        None => Ok(Found::Differs),
    }
}

fn hash_of(file: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn split(dir: &Path) -> io::Result<(&Path, &OsStr)> {
    match (dir.parent(), dir.file_name()) {
        (Some(parent), Some(leaf)) => Ok((parent, leaf)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the plugin folder has no parent",
        )),
    }
}

// Uninstall and runtime folder ========================================================================================

/// Removes `dir` and everything below it, whatever it holds and whatever a stamp in it says: uninstall removes
/// everything Hole installed and does not read the stamp. A link or file at `dir` is removed, never what a link points
/// at. `dir`'s parent must be `owner`'s.
pub fn remove_folder(dir: &Path, owner: (u32, u32)) -> io::Result<()> {
    let (parent, leaf) = split(dir)?;
    let parent = match Dir::open(parent, false, Some(owner)) {
        Ok(parent) => parent,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    match parent.remove_tree(leaf) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// The folder where a plugin that extracts itself puts what it extracts: `owner`'s, mode 0700, made if missing.
pub fn make_runtime_dir(dir: &Path, owner: (u32, u32)) -> io::Result<()> {
    let dir = Dir::open(dir, true, Some(owner))?;
    dir.secure(Some(owner), Some(0o700))
}

// Apply ===============================================================================================================

/// Runs the plan's steps in order and returns a line for each that failed: one failing step does not stop the next,
/// so a folder with one stubborn entry still gets its other plugin. The step that claims convergence is the exception.
pub fn apply(plan: &RepairPlan, layout: &PluginDirLayout, plugins: &[EmbeddedPlugin]) -> Vec<String> {
    let mut run = Run {
        layout,
        plugins,
        dir: None,
    };
    let mut failures = Vec::new();
    for step in &plan.steps {
        if step.claims_convergence() && !failures.is_empty() {
            failures.push(format!("{}: not done, an earlier step failed", describe(step)));
            continue;
        }
        if let Err(e) = run.step(step) {
            failures.push(format!("{}: {e}", describe(step)));
        }
    }
    if let Some(dir) = &run.dir {
        // Makes the renames and removals durable; a volume with no directory flush answers an error that is no
        // reason to fail the repair.
        if let Err(e) = dir.sync() {
            tracing::debug!(error = &e as &dyn std::error::Error, "plugin folder not flushed");
        }
    }
    failures
}

fn describe(step: &Step) -> String {
    match step {
        Step::CreateDir => "create the folder".to_owned(),
        Step::SecureDir => "set the folder's owner and mode".to_owned(),
        Step::RebuildDir => "rebuild the folder".to_owned(),
        Step::Write(name) => format!("write {name}"),
        Step::Remove(name) => format!("remove {name}"),
        Step::StoreRecord => "store the layout file".to_owned(),
    }
}

struct Run<'a> {
    layout: &'a PluginDirLayout,
    plugins: &'a [EmbeddedPlugin],
    /// The folder, opened by the step that made it or by the first step that needs it.
    dir: Option<Dir>,
}

impl Run<'_> {
    fn step(&mut self, step: &Step) -> io::Result<()> {
        match step {
            Step::CreateDir => self.create_dir(),
            Step::SecureDir => self.secure_dir(),
            Step::RebuildDir => self.rebuild_dir(),
            Step::Write(name) => self.write(name),
            Step::Remove(name) => self.dir()?.remove_tree(OsStr::new(name)),
            Step::StoreRecord => layout_stamp::store(self.layout).map_err(io::Error::other),
        }
    }

    fn dir(&mut self) -> io::Result<&Dir> {
        if self.dir.is_none() {
            self.dir = Some(Dir::open(&self.layout.dir, false, Some(self.layout.owner))?);
        }
        Ok(self.dir.as_ref().expect("just set"))
    }

    /// The folder, made if missing, handed to its owner with the mode it must have.
    fn create_dir(&mut self) -> io::Result<()> {
        let dir = Dir::open(&self.layout.dir, true, Some(self.layout.owner))?;
        dir.secure(Some(self.layout.owner), Some(MODE))?;
        self.dir = Some(dir);
        Ok(())
    }

    /// The folder as it is, handed to its owner with the mode it must have.
    fn secure_dir(&mut self) -> io::Result<()> {
        let owner = self.layout.owner;
        self.dir()?.secure(Some(owner), Some(MODE))
    }

    fn rebuild_dir(&mut self) -> io::Result<()> {
        self.dir = None;
        let (parent, leaf) = split(&self.layout.dir)?;
        let parent = Dir::open(parent, true, Some(self.layout.owner))?;
        match parent.kind_of(leaf)? {
            None => {}
            Some(EntryKind::Symlink | EntryKind::File | EntryKind::Other) => parent.unlink(leaf)?,
            Some(EntryKind::Directory) => {
                // Whoever owns it: it is handed to the owner first, then emptied, so nothing is added behind the
                // emptying and what the old owner held open no longer names anything here.
                let dir = Dir::open(&self.layout.dir, false, None)?;
                dir.secure(Some(self.layout.owner), Some(MODE))?;
                let mut first_failure = None;
                for name in dir.reader()?.names()? {
                    if let Err(e) = dir.remove_tree(&name) {
                        first_failure.get_or_insert(e);
                    }
                }
                if let Some(e) = first_failure {
                    return Err(e);
                }
            }
        }
        self.create_dir()
    }

    fn write(&mut self, name: &str) -> io::Result<()> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| io::Error::other("a plan writes a plugin `hole` does not carry"))?;
        let owner = self.layout.owner;
        self.dir()?
            .stage(OsStr::new(name), plugin.bytes, Some(owner), |temp| {
                temp.set_permissions(Permissions::from_mode(MODE))
            })?
            .publish()
    }
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod apply_tests;
