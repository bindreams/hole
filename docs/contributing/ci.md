# Continuous integration

Every pull request runs two workflows. {src}`.github/workflows/semantic-pr.yaml` checks the title ([Commit
messages](commit-messages.md)). {src}`.github/workflows/ci.yaml` has one job, `ci`, on six runners: `windows`, `darwin`
and `linux`, each on `amd64` and `arm64`. A pull request therefore costs six runners, two of them macOS. Each runner builds, lints and tests what its platform ships. A **lane** is one kind of work, such as the Hole
tests, an installer build or the lint, and the matrix flags in `ci.yaml` say which runners run which lanes.

The comments in `ci.yaml` are the detailed description: why each step sits where it does, and the measurements behind the
time budgets. This page is the map.

## Required checks

A pull request needs all of these to merge into `main`: the six `Build, lint, test (<os>/<arch>)` checks, one per
runner, and `Validate PR title` ([Commit messages](commit-messages.md)).

## How a runner works

A runner provisions once, then runs its lanes as steps in a fixed order, on one target directory. Every lane step:

- runs even if an earlier lane failed (`!cancelled()`), so one failure hides nothing;
- has its own literal `timeout-minutes`, so a hang fails that step and the later lanes still report, instead of running
  into the job's wall, which cancels them;
- gates the merge: there is no `continue-on-error`, and re-running repeats the platform's whole job.

**Step ids are API.** The `xtask` audits that read `ci.yaml` address lanes by step id: `hole-*` is the Hole test lane,
`installer-*` and `dmg` assemble an installer. Renaming a step breaks an audit; a prefix that matches no step is an error.

**Order is enforced** by those audits ({src}`xtask/src/ci_platform_coverage.rs`):

- Steps that rebuild the ex-ray and galoshes plugins (plugin tests, the MSI and DMG builds) come before `hole-build`,
  because the plugins are inputs of the `hole` build script. Rewriting them afterwards would make the test lanes recompile
  `hole`.
- On Windows nothing that uses loopback runs after the TUN lane, which leaves loopback in a state that breaks it.
- On macOS the TUN lane runs as root and leaves root-owned files in `target/`, so it is the last step that runs a
  toolchain.

**Lint is split by whether the host matters.** {src}`.github/lint.toml` lists the prek hooks whose result depends on the
platform that runs them (today, the Go linter, which type-checks for the host's OS). `cargo xtask prek platform-dependent`
runs those on every runner; `cargo xtask prek portable` runs every other hook except Clippy once, on linux/amd64. Clippy
is a step of its own on each runner (`clippy-hole`, `clippy-ex-galoshes`), so neither prek run includes it. A new hook is portable
unless it is listed.

**Test lanes compile nothing.** `hole-build` compiles the test binaries once. The lanes after it only run them, and
`hole-verify-no-compile` fails the job if the build state changed in between. A compile in a test lane means a different
fingerprint from the build, such as an environment variable that leaked in, so the lane would pass while running
something other than what was built. `.github/scripts/fail-on-compile.sh` checks the same thing around single steps and
names the units that rebuilt.

## What you can run locally

| CI lane                                | Locally                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------- |
| Hole tests (`hole-test-non-tun`)       | `SKULD_LABELS='!tun' cargo xtask run hole-tests`                          |
| Hole tests, elevated (`hole-test-tun`) | `SKULD_LABELS=tun cargo xtask run hole-tests`, elevated                   |
| Lint, hooks                            | `prek run --all-files`; `cargo xtask run prek` is the same without Clippy |
| Lint, Clippy                           | `cargo xtask run clippy-hole` or `clippy-ex-galoshes`, by platform        |
| Documentation checks                   | `cargo xtask run doc-hole` or `doc-ex-galoshes`, by platform              |
| Front end                              | `cargo xtask run frontend-check`                                          |
| Installers                             | [The installers](installers.md)                                           |

CI's Hole test steps run exactly the command of the `hole-tests` target in {src}`build.yaml` (the audit
`ci_test_hole_steps_match_the_hole_tests_target` holds them equal), with `SKULD_LABELS` and a nextest profile on top.

The table shows POSIX syntax; [Set up and build](setup.md#run-the-tests-once) has the PowerShell form of `SKULD_LABELS`.
On Windows, run the elevated lane from an elevated shell. On macOS, never put `sudo` before `cargo xtask`: it builds
first and leaves root-owned files in `target/`. CI builds as the user, then runs only `cargo nextest` under `sudo` over
the built binaries, with `NEXTEST_PROFILE=tun`; the `hole-test-tun-macos` step in {src}`.github/workflows/ci.yaml` has
the exact command.

## Provisioning retries until it works

A runner can lose its network for a minute. A download, clone or package install that fails in that window would fail its
step with no defect behind it, so provisioning fetches retry with no attempt cap; the step's `timeout-minutes` is the
bound. Each failure prints its cause.

The helpers are `.github/scripts/retry.sh` for shell, `.github/scripts/retry.ps1` for PowerShell, `retry::until_ok` in
{src}`xtask/src/retry.rs` for xtask, and `tenacity` for the MSI project's WiX download. Wrap only the fetch, never a build
or a test: a real failure would retry until the timeout. A failure no retry can fix ends the loop: a program that is not
installed (the shell and xtask helpers), an HTTP 4xx other than 408 and 429 (`retry.ps1`, the WiX download and xtask), or
an error marked `retry::permanent` (xtask).

Where a deterministic check exists, it runs outside the retry, so a retry does not hide a failure the network did not
cause: `uv lock --check --offline` and `npm ci --dry-run --offline` run before their fetches (see `build.yaml`), and
`.github/scripts/cargo-fetch.sh` retries `cargo fetch` and then compares `Cargo.lock` with what it was.

## A test that needs egress

A test that probes real internet access cannot tell a broken cover from a runner that lost its network by looking at the
probe. The oracle is Hole's own state: a failed probe while Hole holds a cover fails at once, as a defect, and with no
cover and the control host down the test waits for the network, with no cap. A probe made inside a cover cannot use a
control host, so the test probes a host the cover permits before and after, and judges the readings after the teardown.
The mechanism and its limits are in the module doc of {src}`crates/test-observability/src/egress.rs`, and the helper
`held_covers` is in {src}`crates/tun-engine/src/routing/failclosed/cover_oracle.rs`.
