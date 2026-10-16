//! Which steps of the unified `ci` job run on which platform, and in what order.
//!
//! Backs the per-platform conformance tests in `ci_platform_coverage_tests.rs`.
//! One matrix job runs every platform, and the matrix flags (`hole`, `dmg`, ...)
//! alone decide which lanes a leg gets, so a flag lost in an edit drops a lane
//! while the job stays green. [`steps_on`] evaluates each step's `if:` for one
//! matrix leg so a test can compare the result against a table written
//! independently of ci.yaml.
//!
//! [`steps_on`] models a HEALTHY run: every step that runs succeeds, nothing is
//! cancelled, so `success()` and `always()` hold, `failure()` and `cancelled()`
//! do not, and `steps.<id>.outcome` is `success` for a step that runs on this
//! leg and `skipped` for one that does not. [`steps_on_after_failure`] models
//! the run in which exactly one named step fails and nothing is cancelled: from
//! then on `success()` is false, `failure()` is true, a step with no status
//! function in its `if:` (or no `if:`) is skipped, as GitHub's implicit
//! `success()` does, and the failed step's outcome is `failure`. It does not
//! model cancellation, `continue-on-error`, or a second failure. The expression
//! subset is deliberately small (`&&`, `||`, `!`, `==`, `!=`, parentheses, the
//! four status functions, `matrix.*` and `steps.<id>.outcome`); anything else
//! is an error, so the grammar cannot silently widen.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::ci_coverage::{join_line_continuations, split_commands, unquote};
use crate::ci_timeouts::xtask_target;
use crate::manifest::Manifest;

// ci.yaml shape (local, minimal) ======================================================================================

#[derive(Deserialize)]
struct CiYaml {
    jobs: IndexMap<String, Job>,
}

#[derive(Deserialize)]
struct Job {
    #[serde(default, rename = "continue-on-error")]
    continue_on_error: Option<serde_yml::Value>,
    #[serde(default)]
    strategy: Option<Strategy>,
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Strategy {
    #[serde(default)]
    matrix: Option<Matrix>,
}

#[derive(Deserialize)]
struct Matrix {
    #[serde(default)]
    include: Vec<IndexMap<String, serde_yml::Value>>,
}

#[derive(Deserialize)]
struct Step {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "if")]
    if_: Option<serde_yml::Value>,
    #[serde(default)]
    run: Option<String>,
    #[serde(default)]
    uses: Option<String>,
    #[serde(default, rename = "continue-on-error")]
    continue_on_error: Option<serde_yml::Value>,
}

fn job<'a>(ci: &'a CiYaml, job_id: &str) -> Result<&'a Job> {
    ci.jobs
        .get(job_id)
        .with_context(|| format!("ci.yaml declares no job {job_id:?}"))
}

fn step_id(step: &Step, index: usize) -> Result<&str> {
    step.id
        .as_deref()
        .with_context(|| format!("steps[{index}] of the unified job has no `id`; every step carries one"))
}

// Legs ================================================================================================================

/// One `matrix.include` entry.
#[derive(Debug, Clone)]
pub struct Leg {
    fields: IndexMap<String, serde_yml::Value>,
    /// Every key any entry of the matrix defines. A key outside it is a typo;
    /// a key inside it that this leg lacks is an unset flag.
    known_keys: Arc<BTreeSet<String>>,
}

impl Leg {
    /// `<os>/<arch>`, the platform spelling used throughout the repo. [`legs`]
    /// guarantees both are strings.
    pub fn name(&self) -> String {
        let part = |key: &str| {
            self.fields
                .get(key)
                .and_then(serde_yml::Value::as_str)
                .unwrap_or_default()
        };
        format!("{}/{}", part("os"), part("arch"))
    }

    /// The leg's job wall (`matrix.timeout`) in minutes, if it is a literal.
    pub fn wall(&self) -> Option<u64> {
        self.fields.get("timeout").and_then(serde_yml::Value::as_u64)
    }

    /// `matrix.<key>`: `Null` for a flag this leg does not set, an error for a
    /// key no leg sets or a value that is not a scalar.
    fn value(&self, key: &str) -> Result<Val> {
        ensure!(
            self.known_keys.contains(key),
            "`matrix.{key}` is defined by no `include` entry of the matrix"
        );
        match self.fields.get(key) {
            None | Some(serde_yml::Value::Null) => Ok(Val::Null),
            Some(serde_yml::Value::Bool(b)) => Ok(Val::Bool(*b)),
            Some(serde_yml::Value::String(s)) => Ok(Val::Str(s.clone())),
            Some(serde_yml::Value::Number(n)) => Ok(Val::Num(n.as_f64())),
            Some(_) => bail!("`matrix.{key}` is a sequence or mapping, which an `if:` expression cannot compare"),
        }
    }
}

/// The matrix legs of `job_id`. Every entry must name its `os` and `arch` as
/// strings, so a leg is never nameless.
pub fn legs(ci_yaml: &str, job_id: &str) -> Result<Vec<Leg>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let include = job(&ci, job_id)?
        .strategy
        .as_ref()
        .and_then(|s| s.matrix.as_ref())
        .map(|m| m.include.clone())
        .with_context(|| format!("job {job_id:?} has no strategy.matrix.include"))?;
    for (i, fields) in include.iter().enumerate() {
        for key in ["os", "arch"] {
            ensure!(
                fields.get(key).is_some_and(serde_yml::Value::is_string),
                "matrix.include[{i}] has no string `{key}`"
            );
        }
    }
    let known_keys: Arc<BTreeSet<String>> = Arc::new(include.iter().flat_map(|f| f.keys().cloned()).collect());
    Ok(include
        .into_iter()
        .map(|fields| Leg {
            fields,
            known_keys: Arc::clone(&known_keys),
        })
        .collect())
}

// Step selection ======================================================================================================

/// The ids of the steps of `job_id` that run on `leg` in a healthy run.
pub fn steps_on(leg: &Leg, ci_yaml: &str, job_id: &str) -> Result<BTreeSet<String>> {
    run_job(leg, ci_yaml, job_id, None)
}

/// The ids of the steps of `job_id` that run on `leg` when the step `failing`
/// fails and nothing else goes wrong. `failing` must itself run on the leg.
pub fn steps_on_after_failure(leg: &Leg, ci_yaml: &str, job_id: &str, failing: &str) -> Result<BTreeSet<String>> {
    run_job(leg, ci_yaml, job_id, Some(failing))
}

fn run_job(leg: &Leg, ci_yaml: &str, job_id: &str, failing: Option<&str>) -> Result<BTreeSet<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;

    let mut ran: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut failed: Option<String> = None;
    for (i, step) in job.steps.iter().enumerate() {
        let id = step_id(step, i)?;
        let runs = match &step.if_ {
            // No `if:` is an implicit `success()`.
            None => failed.is_none(),
            Some(cond) => {
                let text = condition_text(cond).with_context(|| format!("step {id:?}"))?;
                let ctx = Ctx {
                    leg,
                    ran: &ran,
                    seen: &seen,
                    failed: failed.as_deref(),
                };
                let (value, used_status_function) =
                    eval(&text, &ctx).with_context(|| format!("evaluating `if: {text}` of step {id:?}"))?;
                // GitHub adds `success() &&` to an `if:` that names no status function.
                value.truthy() && (used_status_function || failed.is_none())
            }
        };
        seen.insert(id.to_string());
        if runs {
            ran.insert(id.to_string());
            if failing == Some(id) {
                failed = Some(id.to_string());
            }
        }
    }
    if let Some(id) = failing {
        ensure!(
            failed.is_some(),
            "step {id:?} does not run on {}, so it cannot fail there",
            leg.name()
        );
    }
    Ok(ran)
}

/// Ids of the steps of `job_id` after `id` that are in `ran` and are not an
/// artifact upload (`uses: actions/upload-artifact@…`). Whatever runs after a
/// lane that corrupts the machine or leaves root-owned files must not be able
/// to run a toolchain, and a `uses:` step can be one (`setup-build`,
/// `setup-node`), so it is reported like a script step.
pub fn non_upload_steps_after(ci_yaml: &str, job_id: &str, id: &str, ran: &BTreeSet<String>) -> Result<Vec<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;
    let after = steps_after(ci_yaml, job_id, id)?;
    let mut out = Vec::new();
    for (i, step) in job.steps.iter().enumerate() {
        let step_id = step_id(step, i)?;
        let is_upload = step
            .uses
            .as_deref()
            .is_some_and(|u| u.starts_with("actions/upload-artifact@"));
        if after.iter().any(|a| a == step_id) && ran.contains(step_id) && !is_upload {
            out.push(step_id.to_string());
        }
    }
    Ok(out)
}

/// `(step id, budget)` of the steps that run on `leg` in a healthy run and
/// declare a `timeout-minutes` above the leg's job wall. Such a step's own bound
/// can never fire: the wall ends the job first and GitHub drops the log (#989).
/// A step with no literal budget is `ci_steps_declare_a_literal_timeout`'s
/// concern. Steps that run only after a failure are not checked.
pub fn steps_over_wall(leg: &Leg, ci_yaml: &str, job_id: &str) -> Result<Vec<(String, u64)>> {
    let wall = leg
        .wall()
        .with_context(|| format!("leg {} has no literal `timeout` for the job wall", leg.name()))?;
    let budgets = crate::ci_timeouts::step_timeouts(ci_yaml, job_id)?;
    let ran = steps_on(leg, ci_yaml, job_id)?;
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;
    let mut out = Vec::new();
    for (i, step) in job.steps.iter().enumerate() {
        let id = step_id(step, i)?;
        if let Some(&minutes) = budgets.get(id) {
            if ran.contains(id) && minutes > wall {
                out.push((id.to_string(), minutes));
            }
        }
    }
    Ok(out)
}

/// The ids of the steps after `id`, in order.
pub fn steps_after(ci_yaml: &str, job_id: &str, id: &str) -> Result<Vec<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;
    let ids = job
        .steps
        .iter()
        .enumerate()
        .map(|(i, s)| step_id(s, i).map(str::to_string))
        .collect::<Result<Vec<_>>>()?;
    let at = ids
        .iter()
        .position(|x| x == id)
        .with_context(|| format!("job {job_id:?} has no step {id:?}"))?;
    Ok(ids[at + 1..].to_vec())
}

/// Step id → its `run:` script, for the steps that have one.
pub fn step_runs(ci_yaml: &str, job_id: &str) -> Result<BTreeMap<String, String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;
    let mut out = BTreeMap::new();
    for (i, step) in job.steps.iter().enumerate() {
        if let Some(run) = &step.run {
            out.insert(step_id(step, i)?.to_string(), run.clone());
        }
    }
    Ok(out)
}

/// Where `continue-on-error` is declared as anything but a literal `false`: the
/// job (labelled `<job>`) and each step by id. An expression is not evaluated,
/// so it may be true, and a job-level `true` lets every step fail while the job
/// stays green.
pub fn continue_on_error_declarations(ci_yaml: &str, job_id: &str) -> Result<Vec<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = job(&ci, job_id)?;
    let lenient = |v: &Option<serde_yml::Value>| !matches!(v, None | Some(serde_yml::Value::Bool(false)));
    let mut out = Vec::new();
    if lenient(&job.continue_on_error) {
        out.push("<job>".to_string());
    }
    for (i, step) in job.steps.iter().enumerate() {
        if lenient(&step.continue_on_error) {
            out.push(step_id(step, i)?.to_string());
        }
    }
    Ok(out)
}

// Sidecar rewrites ====================================================================================================

/// Targets whose build rewrites `.cache/ex-ray` or `.cache/galoshes`: the two
/// sidecar binaries `hole`'s and `galoshes`' build scripts track.
const SIDECAR_TARGETS: [&str; 2] = ["ex-ray", "galoshes"];

/// Xtask subcommands that rewrite the sidecars without going through a
/// build.yaml target. `deps` provisions both.
const SIDECAR_SUBCOMMANDS: [&str; 3] = ["ex-ray", "galoshes", "deps"];

/// Does running `cmd` rewrite the sidecar binaries — directly, or through the
/// build.yaml target it names, that target's `depends`, or nested `cargo xtask`
/// steps?
pub fn reaches_sidecar_rewrite(cmd: &str, manifest: &Manifest) -> Result<bool> {
    command_rewrites(cmd, manifest, &mut BTreeSet::new())
}

fn command_rewrites(cmd: &str, manifest: &Manifest, visited: &mut BTreeSet<String>) -> Result<bool> {
    let toks: Vec<&str> = cmd.split_whitespace().map(unquote).collect();
    if toks
        .windows(3)
        .any(|w| w[0] == "cargo" && w[1] == "xtask" && SIDECAR_SUBCOMMANDS.contains(&w[2]))
    {
        return Ok(true);
    }
    match xtask_target(cmd)? {
        Some(target) => target_rewrites(target, manifest, visited),
        None => Ok(false),
    }
}

fn target_rewrites(target: &str, manifest: &Manifest, visited: &mut BTreeSet<String>) -> Result<bool> {
    if SIDECAR_TARGETS.contains(&target) {
        return Ok(true);
    }
    if !visited.insert(target.to_string()) {
        return Ok(false);
    }
    let Some(t) = manifest.get(target) else {
        return Ok(false);
    };
    for dep in &t.depends {
        if target_rewrites(dep, manifest, visited)? {
            return Ok(true);
        }
    }
    for step in t.build.iter().chain(t.run.iter()) {
        let text = crate::ci_coverage::step_command(step);
        for cmd in split_commands(&join_line_continuations(&text)) {
            if command_rewrites(&cmd, manifest, visited)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// Expression evaluation ===============================================================================================

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
}

impl Val {
    fn truthy(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Bool(b) => *b,
            Val::Num(n) => *n != 0.0 && !n.is_nan(),
            Val::Str(s) => !s.is_empty(),
        }
    }

    /// GitHub's loose-equality coercion: same types compare directly (strings
    /// ignoring case), otherwise both sides become numbers.
    fn loosely_equals(&self, other: &Val) -> bool {
        match (self, other) {
            (Val::Str(a), Val::Str(b)) => a.eq_ignore_ascii_case(b),
            (Val::Null, Val::Null) => true,
            (Val::Bool(a), Val::Bool(b)) => a == b,
            (Val::Num(a), Val::Num(b)) => a == b,
            (a, b) => a.number() == b.number(),
        }
    }

    fn number(&self) -> f64 {
        match self {
            Val::Null => 0.0,
            Val::Bool(b) => f64::from(u8::from(*b)),
            Val::Num(n) => *n,
            Val::Str(s) if s.is_empty() => 0.0,
            Val::Str(s) => s.parse().unwrap_or(f64::NAN),
        }
    }
}

struct Ctx<'a> {
    leg: &'a Leg,
    /// Steps that ran on this leg so far.
    ran: &'a BTreeSet<String>,
    /// Steps already considered (ran or skipped), so a forward reference is an
    /// error rather than a quiet `skipped`.
    seen: &'a BTreeSet<String>,
    /// The step that failed earlier in the run, if any.
    failed: Option<&'a str>,
}

fn condition_text(cond: &serde_yml::Value) -> Result<String> {
    let raw = match cond {
        serde_yml::Value::Bool(b) => return Ok(b.to_string()),
        serde_yml::Value::String(s) => s.trim(),
        other => bail!("`if:` is {other:?}, expected a string"),
    };
    Ok(raw
        .strip_prefix("${{")
        .and_then(|r| r.strip_suffix("}}"))
        .map_or(raw, str::trim)
        .to_string())
}

/// The value of `text`, and whether it called a status function.
fn eval(text: &str, ctx: &Ctx) -> Result<(Val, bool)> {
    let tokens = tokenize(text)?;
    let mut p = Parser {
        tokens: &tokens,
        at: 0,
        ctx,
        used_status_function: false,
    };
    let v = p.or()?;
    ensure!(
        p.at == tokens.len(),
        "trailing input after the expression: {:?}",
        &tokens[p.at..]
    );
    Ok((v, p.used_status_function))
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Not,
    And,
    Or,
    Eq,
    Ne,
    LParen,
    RParen,
    Str(String),
    Ident(String),
}

fn tokenize(text: &str) -> Result<Vec<Tok>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match (c, next) {
            (c, _) if c.is_whitespace() => i += 1,
            ('&', Some('&')) => {
                out.push(Tok::And);
                i += 2;
            }
            ('|', Some('|')) => {
                out.push(Tok::Or);
                i += 2;
            }
            ('=', Some('=')) => {
                out.push(Tok::Eq);
                i += 2;
            }
            ('!', Some('=')) => {
                out.push(Tok::Ne);
                i += 2;
            }
            ('!', _) => {
                out.push(Tok::Not);
                i += 1;
            }
            ('(', _) => {
                out.push(Tok::LParen);
                i += 1;
            }
            (')', _) => {
                out.push(Tok::RParen);
                i += 1;
            }
            ('\'', _) => {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&c| c == '\'')
                    .with_context(|| format!("unterminated string in {text:?}"))?;
                out.push(Tok::Str(chars[i + 1..i + 1 + end].iter().collect()));
                i += end + 2;
            }
            (c, _) if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '-' | '.')) {
                    i += 1;
                }
                out.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            (c, _) => bail!("unsupported character {c:?} in `if:` expression {text:?}"),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: &'a [Tok],
    at: usize,
    ctx: &'a Ctx<'a>,
    used_status_function: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.at)
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek() == Some(tok) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Val> {
        let mut v = self.and()?;
        while self.eat(&Tok::Or) {
            let rhs = self.and()?;
            v = Val::Bool(v.truthy() || rhs.truthy());
        }
        Ok(v)
    }

    fn and(&mut self) -> Result<Val> {
        let mut v = self.cmp()?;
        while self.eat(&Tok::And) {
            let rhs = self.cmp()?;
            v = Val::Bool(v.truthy() && rhs.truthy());
        }
        Ok(v)
    }

    fn cmp(&mut self) -> Result<Val> {
        let lhs = self.unary()?;
        if self.eat(&Tok::Eq) {
            let rhs = self.unary()?;
            return Ok(Val::Bool(lhs.loosely_equals(&rhs)));
        }
        if self.eat(&Tok::Ne) {
            let rhs = self.unary()?;
            return Ok(Val::Bool(!lhs.loosely_equals(&rhs)));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Val> {
        if self.eat(&Tok::Not) {
            return Ok(Val::Bool(!self.unary()?.truthy()));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Val> {
        let tok = self
            .peek()
            .cloned()
            .ok_or_else(|| anyhow!("unexpected end of expression"))?;
        self.at += 1;
        match tok {
            Tok::LParen => {
                let v = self.or()?;
                ensure!(self.eat(&Tok::RParen), "missing `)`");
                Ok(v)
            }
            Tok::Str(s) => Ok(Val::Str(s)),
            Tok::Ident(name) => {
                if self.eat(&Tok::LParen) {
                    ensure!(
                        self.eat(&Tok::RParen),
                        "function {name:?} takes arguments, which are not supported"
                    );
                    self.used_status_function = true;
                    return call(&name, self.ctx.failed.is_some());
                }
                self.ctx.lookup(&name)
            }
            other => bail!("unexpected token {other:?}"),
        }
    }
}

/// Status functions, for a run in which an earlier step has failed or not.
fn call(name: &str, an_earlier_step_failed: bool) -> Result<Val> {
    match name {
        "success" => Ok(Val::Bool(!an_earlier_step_failed)),
        "always" => Ok(Val::Bool(true)),
        "failure" => Ok(Val::Bool(an_earlier_step_failed)),
        "cancelled" => Ok(Val::Bool(false)),
        other => bail!("function {other:?}() is not supported in an `if:` expression"),
    }
}

impl Ctx<'_> {
    fn lookup(&self, name: &str) -> Result<Val> {
        match name {
            "true" => return Ok(Val::Bool(true)),
            "false" => return Ok(Val::Bool(false)),
            "null" => return Ok(Val::Null),
            _ => {}
        }
        if let Some(key) = name.strip_prefix("matrix.") {
            return self.leg.value(key);
        }
        if let Some(rest) = name.strip_prefix("steps.") {
            let id = rest
                .strip_suffix(".outcome")
                .with_context(|| format!("only `steps.<id>.outcome` is supported, got {name:?}"))?;
            ensure!(
                self.seen.contains(id),
                "`steps.{id}.outcome` refers to a step that is not defined before this one"
            );
            let outcome = if self.failed == Some(id) {
                "failure"
            } else if self.ran.contains(id) {
                "success"
            } else {
                "skipped"
            };
            return Ok(Val::Str(outcome.to_string()));
        }
        bail!("unsupported context reference {name:?} in `if:` expression")
    }
}
