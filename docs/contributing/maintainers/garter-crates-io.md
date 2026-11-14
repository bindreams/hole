# Publishing garter

`garter` is released like the other [tracks](releases.md), and its publish workflow also runs `cargo publish`. This page
covers what is different, and what to do when the publish fails.

## How it publishes

- **By trusted publishing: no token is stored.** {src}`.github/workflows/publish-release-garter.yaml` grants
  `id-token: write`, and `rust-lang/crates-io-auth-action` trades that for a short-lived crates.io token. The trusted
  publisher for `garter` is a setting on crates.io, not in this repository. It names the repository `bindreams/hole` and
  the workflow `publish-release-garter.yaml`: the caller, not the reusable workflow, because crates.io matches the
  top-level workflow. A call through `workflow_call` from any other workflow is refused unless that one is registered too.
- **Against crates.io's `cosca`.** The workspace depends on a registry version of `cosca` rather than a path, so `cargo package` accepts the dependency.
- **A dry run first.** The draft workflow ({src}`.github/workflows/draft-release-garter.yaml`) runs `cargo package` and
  `cargo publish --dry-run` before it starts CI, so broken metadata fails at once. The publish workflow takes a `dry_run`
  input that runs the same two commands and stops, touching neither crates.io nor the GitHub release.
- **Idempotent.** Before it publishes, {src}`.github/workflows/reusable-publish-release.yaml` asks the crates.io API whether
  this version exists and skips `cargo publish` if so. It then waits for the version to be indexed and flips the draft to
  published. A missing answer, a rate limit or a server error is asked again until the job's time limit.

## When a publish fails

The dry run happens at draft time and the real publish later. Between the two, a dependency can be yanked, the registry can
change, or `Cargo.lock` can drift.

1. **Check whether the release is already public.** The auth action revokes its token in a post step, and that can fail
   after the release has been flipped. A re-run then stops at "Release ... is not a draft". The token expires on its own,
   and nothing is left to do.
1. **Read the failed `cargo publish` output** for the yanked or unavailable dependency.
1. **Choose by cause.**
   - *Transient* (a registry hiccup): re-run the publish workflow. If the version already reached crates.io, the re-run
     skips `cargo publish` and only flips the release.
   - *Persistent* (a yanked dependency, a breaking registry change): the draft cannot be saved as it stands. Patch
     `Cargo.toml` to pin around the problem, merge it, delete the draft ([Rollback](rollback.md)) and run the draft
     workflow again on the patched commit.

The idempotency check protects against publishing a version twice. It does not protect against a failure that repeats: a
yanked dependency fails every re-run until the upstream problem is fixed.

Once a version is on crates.io it cannot be taken back: see [Yanking garter](rollback.md#yanking-garter).
