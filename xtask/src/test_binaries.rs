//! Stage workspace test binaries at stable paths under `<out_dir>`.
//!
//! Cargo names compiled test binaries `target/<profile>/deps/<crate>-<hash>.exe`.
//! The hash churns on every rebuild, so Windows Firewall re-prompts every time
//! a test binary binds a non-loopback socket (bindreams/hole#210).
//!
//! `stage_test_binaries` runs `cargo test --no-run --workspace --message-format=json`,
//! parses the artifact stream, and copies each test executable into
//! `<out_dir>/<target-name>.test<.exe>` — a stable path that Firewall can cache.
//! On Windows we also stage the companion `.pdb` so staged-crash symbolication keeps working.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use cargo_metadata::Message;

use crate::bindir::BindirFile;
use crate::{stage, Profile};

pub(crate) fn exe_suffix() -> &'static str {
    if cfg!(windows) {
        ".exe"
    } else {
        ""
    }
}

/// Extracted metadata for one compiled test binary. Decoupled from
/// `cargo_metadata::Artifact` so the collision / dest-name logic can be
/// exercised with hand-rolled fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestArtifact {
    pub target_name: String,
    pub target_kind: String,
    pub executable: PathBuf,
}

/// Filter a cargo JSON message stream down to test-binary artifacts only.
pub(crate) fn extract_test_artifacts<R: BufRead>(stream: R) -> Result<Vec<TestArtifact>> {
    let mut out = Vec::new();
    for msg in Message::parse_stream(stream) {
        let msg = msg.context("read cargo message")?;
        let Message::CompilerArtifact(a) = msg else {
            continue;
        };
        if !a.profile.test {
            continue;
        }
        let Some(exe) = a.executable.as_ref() else {
            continue;
        };
        debug_assert!(
            !a.target.kind.is_empty(),
            "cargo emitted test artifact with empty target.kind: {}",
            a.target.name
        );
        let kind = a.target.kind.first().map(|k| k.to_string()).unwrap_or_default();
        out.push(TestArtifact {
            target_name: a.target.name.clone(),
            target_kind: kind,
            executable: PathBuf::from(exe.as_str()),
        });
    }
    Ok(out)
}

/// Assign a stable, collision-free `dest_name` to each artifact.
///
/// Default is `{target_name}.test{ext}`. Artifacts that collide at the default
/// name all fall back to `{target_name}-{kind}.test{ext}`. Any remaining
/// collision after disambiguation is a hard error — we never silently overwrite.
pub(crate) fn assign_dest_names(artifacts: Vec<TestArtifact>) -> Result<Vec<(String, TestArtifact)>> {
    let ext = exe_suffix();
    let default = |a: &TestArtifact| format!("{}.test{ext}", a.target_name);
    let disambiguated = |a: &TestArtifact| format!("{}-{}.test{ext}", a.target_name, a.target_kind);

    // HashMap is fine — final output is sorted below for determinism.
    let mut groups: HashMap<String, Vec<TestArtifact>> = HashMap::new();
    for a in artifacts {
        groups.entry(default(&a)).or_default().push(a);
    }

    let mut named: Vec<(String, TestArtifact)> = Vec::new();
    let mut used: HashMap<String, PathBuf> = HashMap::new();
    for (name, group) in groups {
        if group.len() == 1 {
            let a = group.into_iter().next().unwrap();
            if let Some(prev) = used.insert(name.clone(), a.executable.clone()) {
                bail!(
                    "dest_name collision at {name}: {} vs {}",
                    prev.display(),
                    a.executable.display()
                );
            }
            named.push((name, a));
        } else {
            for a in group {
                let dname = disambiguated(&a);
                if let Some(prev) = used.insert(dname.clone(), a.executable.clone()) {
                    bail!(
                        "dest_name collision after disambiguation at {dname}: {} vs {}",
                        prev.display(),
                        a.executable.display()
                    );
                }
                named.push((dname, a));
            }
        }
    }

    named.sort_by(|(n1, _), (n2, _)| n1.cmp(n2));
    Ok(named)
}

/// Expand a named test artifact into the concrete files to stage: the exe, and
/// — on Windows if present — the companion `.pdb`.
pub(crate) fn bindir_files_for_artifact(dest_name: &str, artifact: &TestArtifact) -> Vec<BindirFile> {
    let mut files = Vec::with_capacity(2);
    files.push(BindirFile::new(artifact.executable.clone(), dest_name.to_string()));

    if cfg!(windows) {
        if let (Some(stem), Some(dir)) = (
            artifact.executable.file_stem().and_then(|s| s.to_str()),
            artifact.executable.parent(),
        ) {
            let pdb = dir.join(format!("{stem}.pdb"));
            if pdb.is_file() {
                // `dest_name` is produced by `assign_dest_names`, which always
                // appends `exe_suffix()` (".exe" on Windows). This block runs
                // only on Windows, so the suffix is guaranteed present.
                let dest_stem = dest_name.strip_suffix(".exe").unwrap_or(dest_name);
                files.push(BindirFile::new(pdb, format!("{dest_stem}.pdb")));
            }
        }
    }

    files
}

/// List files in `dir` that look like staged test artifacts (on Windows:
/// `*.test.exe`, `*.test.pdb`; elsewhere: `*.test`) and are not in `keep`.
pub(crate) fn stale_files_to_remove(dir: &Path, keep: &HashSet<String>) -> Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    if !dir.exists() {
        return Ok(stale);
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let looks_staged = if cfg!(windows) {
            name.ends_with(".test.exe") || name.ends_with(".test.pdb")
        } else {
            name.ends_with(".test")
        };
        if looks_staged && !keep.contains(&name) {
            stale.push(entry.path());
        }
    }
    Ok(stale)
}

fn run_cargo_test_no_run(profile: Profile) -> Result<Vec<TestArtifact>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.arg("test")
        .arg("--no-run")
        .arg("--workspace")
        .arg("--message-format=json");
    if profile == Profile::Release {
        cmd.arg("--release");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    // xtask can't use `hole_bridge::diagnostics::spawn::spawn_with_diagnostics`:
    // no dep on the bridge crate, and `cargo test --no-run` is a build-host
    // binary that isn't subject to AV-scan contention on its own executable.
    #[allow(clippy::disallowed_methods)]
    let mut child = cmd.spawn().context("spawn `cargo test --no-run`")?;
    let stdout = child.stdout.take().expect("stdout piped");
    let reader = std::io::BufReader::new(stdout);
    let artifacts = extract_test_artifacts(reader)?;
    let status = child.wait().context("wait on cargo")?;
    if !status.success() {
        bail!("`cargo test --no-run` exited with {status}");
    }
    Ok(artifacts)
}

/// Build workspace test binaries and stage them at stable paths under `out_dir`.
pub fn stage_test_binaries(profile: Profile, out_dir: &Path) -> Result<()> {
    let artifacts = run_cargo_test_no_run(profile)?;
    let named = assign_dest_names(artifacts)?;

    let mut files: Vec<BindirFile> = Vec::new();
    for (name, a) in &named {
        files.extend(bindir_files_for_artifact(name, a));
    }

    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    // Stage first, sweep stale second: new binaries are guaranteed present
    // before the sweep runs, so a watcher that sees `out_dir` change never
    // observes a moment with zero staged binaries.
    stage::stage(out_dir, &files)?;

    let keep: HashSet<String> = files.iter().map(|f| f.dest_name.clone()).collect();
    let stale = stale_files_to_remove(out_dir, &keep)?;
    for path in &stale {
        std::fs::remove_file(path).with_context(|| format!("remove stale {}", path.display()))?;
    }

    println!("xtask: staged {} test binaries into {}", named.len(), out_dir.display());
    Ok(())
}
