//! DAG orchestration for the build-target manifest.
//!
//! Given a parsed [`Manifest`] and a target selection, this module:
//! 1. Validates the dependency graph (no cycles).
//! 2. Computes a topologically-sorted subgraph of targets reachable from the
//!    selection that apply to the host platform.
//! 3. Executes each target's `build:` steps in order, fail-fast.
//! 4. For `cargo xtask run <name>`, follows up with the target's `run:` steps
//!    after the build cascade (a "run" performs the work the target is named
//!    after; runs do not depend on other runs).
//!
//! Pure orchestration only — no incremental / up-to-date checks. The leaf
//! commands (`cargo build`, `cargo xtask v2ray-plugin`, etc.) own that.

use std::collections::HashMap;
use std::ffi::OsString;
#[cfg(windows)]
use std::io;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use petgraph::algo::{tarjan_scc, toposort};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::manifest::{Manifest, Platform, Step};

// ===== Plan ==========================================================================================================

/// Wraps a [`Manifest`] with a directed graph (`dep → dependent`) ready for
/// topological queries.
#[derive(Debug)]
pub struct Plan<'m> {
    manifest: &'m Manifest,
    graph: DiGraph<String, ()>,
    by_name: HashMap<String, NodeIndex>,
}

impl<'m> Plan<'m> {
    /// Build a plan from a manifest. Errors on dependency cycles.
    pub fn new(manifest: &'m Manifest) -> Result<Self> {
        let mut graph = DiGraph::<String, ()>::new();
        let mut by_name = HashMap::new();
        for t in manifest.iter() {
            let idx = graph.add_node(t.name.clone());
            by_name.insert(t.name.clone(), idx);
        }
        for t in manifest.iter() {
            let to = by_name[&t.name];
            for dep in &t.depends {
                // `Manifest::parse` already verified every dep name resolves.
                let from = by_name[dep];
                graph.add_edge(from, to, ());
            }
        }

        let plan = Self {
            manifest,
            graph,
            by_name,
        };
        plan.detect_cycles()?;
        Ok(plan)
    }

    fn detect_cycles(&self) -> Result<()> {
        match toposort(&self.graph, None) {
            Ok(_) => Ok(()),
            Err(cycle) => {
                let bad = cycle.node_id();
                // `toposort` only names one node on the cycle, not the full
                // ring. Use Tarjan SCC to recover every node in the strongly
                // connected component containing `bad` — that's the full
                // cycle (or the cycle's super-cycle, in the case of two
                // overlapping cycles sharing a node).
                let scc = self
                    .scc_containing(bad)
                    .unwrap_or_else(|| vec![self.graph[bad].clone()]);
                Err(anyhow!(
                    "dependency cycle detected through target {:?}: {}",
                    self.graph[bad],
                    scc.join(" -> ")
                ))
            }
        }
    }

    /// Return the names of all nodes in the strongly-connected component that
    /// contains `node`, or `None` if no SCC of size > 1 contains it (which
    /// would only happen for a self-loop with no other members — we still
    /// report that as the offender).
    fn scc_containing(&self, node: NodeIndex) -> Option<Vec<String>> {
        for component in tarjan_scc(&self.graph) {
            if !component.contains(&node) {
                continue;
            }
            // SCC of size 1 is a real cycle only if it has a self-loop.
            let is_cycle = component.len() > 1
                || self
                    .graph
                    .edges_directed(node, Direction::Outgoing)
                    .any(|e| e.target() == node);
            if is_cycle {
                return Some(component.into_iter().map(|n| self.graph[n].clone()).collect());
            }
        }
        None
    }

    fn node(&self, name: &str) -> Result<NodeIndex> {
        self.by_name
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("unknown target: {name:?}"))
    }

    /// Return all target names declared in the manifest, in declaration order.
    /// Used by `cargo xtask build --all`.
    pub fn target_names(&self) -> Vec<&str> {
        self.manifest.iter().map(|t| t.name.as_str()).collect()
    }

    /// Compute the topologically-sorted set of targets reachable from `roots`
    /// (each root + all transitive deps), filtered to those that apply to
    /// `platform`.
    pub fn order_for(&self, roots: &[&str], platform: Platform) -> Result<Vec<&'m str>> {
        // 1. Validate every root exists and applies to `platform`.
        let mut root_indices = Vec::with_capacity(roots.len());
        for r in roots {
            let idx = self.node(r)?;
            let target = &self.manifest.targets[*r];
            if !target.applies_to(platform) {
                bail!(
                    "target {r:?} does not apply to host platform {platform} \
                     (declared platforms: {})",
                    join_platforms(&target.platforms)
                );
            }
            root_indices.push(idx);
        }

        // 2. Collect reachable nodes (deps + self) via reverse-DFS from roots.
        let mut reachable = std::collections::HashSet::new();
        let mut stack = root_indices.clone();
        while let Some(n) = stack.pop() {
            if !reachable.insert(n) {
                continue;
            }
            for e in self.graph.edges_directed(n, Direction::Incoming) {
                stack.push(e.source());
            }
        }

        // 3. Toposort the full graph; filter to reachable ∩ applicable.
        let order = toposort(&self.graph, None).map_err(|c| {
            anyhow!(
                "internal: toposort failed after cycle check passed (node {:?})",
                self.graph[c.node_id()]
            )
        })?;

        let mut out = Vec::new();
        for n in order {
            if !reachable.contains(&n) {
                continue;
            }
            let name = &self.graph[n];
            let target = &self.manifest.targets[name];
            if target.applies_to(platform) {
                out.push(target.name.as_str());
            }
            // Targets in reachable but not applicable to the host are silently
            // skipped — e.g. building `hole` on darwin transitively reaches
            // `wintun`, which is windows-only and a no-op there.
        }
        Ok(out)
    }
}

fn join_platforms(plats: &[Platform]) -> String {
    plats.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
}

// ===== Self-relocate (Windows) =======================================================================================

/// Stash directory (relative to the cargo `target/<profile>/` dir) where
/// relocated copies of the running xtask binary live. Sibling of the running
/// exe so the path is local to whatever target tree we were launched from,
/// and so `cargo clean` wipes us along with everything else. Naming follows
/// the project's `.tmp/<role>/` convention (`/var/run/`-style).
#[cfg(windows)]
const STASH_SUBDIR: &[&str] = &[".tmp", "run"];

/// On Windows, rename the running xtask binary out of the way so that
/// recursive `cargo xtask <X>` invocations triggered by manifest steps don't
/// fail with ERROR_ACCESS_DENIED when cargo tries to overwrite the running
/// `target/<profile>/xtask.exe`.
///
/// **The mechanism:** Windows allows renaming a running `.exe` (modern loader
/// opens images with `FILE_SHARE_DELETE`). The running process keeps mapping
/// the file content (FCB) via its existing handle; only the directory entry
/// moves. Once the old dirent is gone, cargo's "delete-then-create" rebuild
/// path succeeds — it sees no file to delete and freshly hardlinks
/// `deps/xtask-<hash>.exe` into place.
///
/// On non-Windows platforms this is a no-op: POSIX permits replacing running
/// binaries through ordinary unlink+create, so the lock issue doesn't exist.
///
/// Best-effort: failures here propagate as errors so the caller can decide,
/// but we tolerate "another xtask process beat me to it" (NotFound on rename).
pub fn relocate_self_if_windows() -> Result<()> {
    #[cfg(not(windows))]
    {
        Ok(())
    }
    #[cfg(windows)]
    {
        relocate_self_windows()
    }
}

#[cfg(windows)]
fn relocate_self_windows() -> Result<()> {
    let current = std::env::current_exe().context("locating current xtask binary")?;
    let parent = current
        .parent()
        .ok_or_else(|| anyhow!("running xtask {current:?} has no parent directory"))?;
    let mut stash = parent.to_path_buf();
    for c in STASH_SUBDIR {
        stash.push(c);
    }
    std::fs::create_dir_all(&stash).with_context(|| format!("creating stash dir {}", stash.display()))?;

    // Prune older relocated copies whose owning process has exited (so the
    // file is no longer mapped). On Windows, `remove_file` on a still-mapped
    // image fails with ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION; success
    // means the file was unlocked and is now gone. Best-effort: log + ignore
    // anything we can't classify.
    if let Ok(read) = std::fs::read_dir(&stash) {
        for entry in read.flatten() {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::PermissionDenied) => {
                    // Locked: another xtask is still running with this binary mapped.
                }
                Err(e) => {
                    eprintln!("xtask: warning: could not prune {}: {e}", entry.path().display());
                }
            }
        }
    }

    // Pick a unique stash name. PID + nanos is collision-free in practice
    // and easy to read in a directory listing.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stem = current.file_stem().and_then(|s| s.to_str()).unwrap_or("xtask");
    let ext = current.extension().and_then(|s| s.to_str()).unwrap_or("exe");
    let new_path = stash.join(format!("{stem}-{pid}-{nanos}.{ext}"));

    match std::fs::rename(&current, &new_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Another xtask process renamed it before us. Our process keeps
            // mapping the file content via its open handle; only the dirent
            // we expected to find is missing. Continue.
            Ok(())
        }
        Err(e) => Err(e).with_context(|| {
            format!(
                "relocating running xtask {} -> {}",
                current.display(),
                new_path.display()
            )
        }),
    }
}

// ===== Step execution ================================================================================================

/// Execute one [`Step`] from the given working directory.
///
/// CWD is always `repo_root`. The step inherits stdio. On non-zero exit this
/// returns `Err` with a message naming the step and exit code; the caller
/// (the build driver) propagates that via fail-fast.
pub fn run_step(step: &Step, repo_root: &Path) -> Result<()> {
    match step {
        Step::Bash { command, environment } => {
            let mut cmd = Command::new(resolve_bash()?);
            // `-e` so multi-line bash heredocs fail fast on the first error,
            // matching the driver's overall fail-fast contract.
            cmd.arg("-e").arg("-c").arg(command).current_dir(repo_root);
            for (k, v) in environment {
                cmd.env(k, v);
            }
            run(cmd, &format!("bash step: {command}"))
        }
        Step::Process { args, environment } => {
            let (program, rest) = args
                .split_first()
                .ok_or_else(|| anyhow!("process step has empty args list"))?;
            let mut cmd = Command::new(program);
            cmd.args(rest).current_dir(repo_root);
            for (k, v) in environment {
                cmd.env(k, v);
            }
            run(cmd, &format!("process step: {}", args.join(" ")))
        }
    }
}

/// Pick the bash interpreter to invoke for `bash:` steps.
///
/// On Unix, this is just `bash` from PATH.
///
/// On Windows, two installations commonly resolve `bash` from a Windows-side
/// `CreateProcess` lookup: **Git Bash** (MSYS2-based, ships with Git for
/// Windows) and **WSL bash** (`C:\Windows\System32\bash.exe`, the WSL
/// launcher). Build orchestration must use Git Bash — WSL bash runs commands
/// inside a Linux distribution where `cargo.exe` is invisible and Windows-form
/// paths in `build.yaml` are interpreted as Linux paths. The two are not
/// interchangeable.
///
/// Resolution order on Windows:
/// 1. `$HOLE_BUILD_BASH` env var — explicit override.
/// 2. Common Git Bash install paths.
/// 3. Error out with a clear message — never fall through to bare `bash`,
///    because that would silently pick up `C:\Windows\System32\bash.exe`
///    (the WSL launcher) on systems without Git Bash.
fn resolve_bash() -> Result<OsString> {
    if let Some(p) = std::env::var_os("HOLE_BUILD_BASH") {
        return Ok(p);
    }
    #[cfg(windows)]
    {
        // Walk standard Git Bash install locations. `Path::is_file` is cheap;
        // we only do this once per bash step.
        const CANDIDATES: &[&str] = &[
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ];
        for c in CANDIDATES {
            if PathBuf::from(c).is_file() {
                return Ok(OsString::from(c));
            }
        }
        bail!(
            "could not locate Git Bash on Windows. Tried: {}. \
             Set HOLE_BUILD_BASH=<path-to-bash.exe> or install Git for Windows.",
            CANDIDATES.join(", ")
        );
    }
    #[cfg(not(windows))]
    {
        Ok(OsString::from("bash"))
    }
}

fn run(mut cmd: Command, label: &str) -> Result<()> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd.status().with_context(|| format!("spawning {label}"))?;
    if !status.success() {
        return Err(anyhow!("{label} failed: exit status {status}"));
    }
    Ok(())
}

// ===== Build driver ==================================================================================================

/// Execute every target in `order` (already toposorted). Each target's
/// `build:` steps run in declaration order; first failure aborts the whole
/// invocation.
pub fn execute(plan: &Plan<'_>, order: &[&str], repo_root: &Path) -> Result<()> {
    for name in order {
        let target = plan
            .manifest
            .get(name)
            .ok_or_else(|| anyhow!("internal: unknown target {name:?} in execute order"))?;

        if target.build.is_empty() {
            println!("xtask: target {name} has no build steps; skipping");
            continue;
        }
        println!("xtask: ==== building target {name} ====");
        for step in &target.build {
            run_step(step, repo_root).with_context(|| format!("while building target {name}"))?;
        }
    }
    Ok(())
}

/// Run a target's `run:` steps after the full build cascade for that target.
///
/// The cascade order matches `cargo xtask build <target>`: every transitive
/// build dep applicable to `host`, in topological order, then the target's
/// own `build:` steps. Once that succeeds, the target's `run:` steps execute.
///
/// Errors:
/// - `unknown target: {name:?}` if `target_name` isn't declared.
/// - `target {name:?} has no run steps defined` if the target's `run:` is
///   empty. Checked before any platform-applicability work — running a
///   target without `run:` is a manifest error, not a host-specific issue.
/// - The platform-applicability message from [`Plan::order_for`] if the
///   target doesn't apply to `host`.
/// - Any step's failure aborts the cascade with `while building target X` or
///   `while running target X` context.
pub fn execute_run(plan: &Plan<'_>, target_name: &str, host: Platform, repo_root: &Path) -> Result<()> {
    let target = plan
        .manifest
        .get(target_name)
        .ok_or_else(|| anyhow!("unknown target: {target_name:?}"))?;
    if target.run.is_empty() {
        bail!("target {target_name:?} has no run steps defined");
    }
    let order = plan.order_for(&[target_name], host)?;
    execute(plan, &order, repo_root)?;

    println!("xtask: ==== running target {target_name} ====");
    for step in &target.run {
        run_step(step, repo_root).with_context(|| format!("while running target {target_name}"))?;
    }
    Ok(())
}

// ===== List output ===================================================================================================

/// Render the table printed by `cargo xtask list`. Returns a string for ease
/// of testing; the caller is responsible for `print!`.
pub fn render_list(manifest: &Manifest, host: Option<Platform>) -> String {
    let mut out = String::new();
    let header = format!("{:<22} {:<46} {:<5} RUN?", "TARGET", "PLATFORMS", "HOST");
    out.push_str(&header);
    out.push('\n');
    for t in manifest.iter() {
        let plats = join_platforms(&t.platforms);
        let host_mark = match host {
            Some(p) if t.applies_to(p) => "yes",
            Some(_) => "no",
            None => "?",
        };
        let run_mark = if t.has_run() { "*" } else { "" };
        out.push_str(&format!("{:<22} {:<46} {:<5} {}\n", t.name, plats, host_mark, run_mark));
    }
    out
}
