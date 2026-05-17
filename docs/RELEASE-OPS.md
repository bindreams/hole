# Release operations runbook

Per-product release procedure: see [CLAUDE.md § Releases](../CLAUDE.md#releases). This file is the runbook for the off-happy-path operations: rollback, minisign key rotation, and the crates.io dry-run TOCTOU gap.

## Rollback procedure

Use when a release is published but later determined to be defective (broken binary, regression, security issue).

### All tracks

1. Delete the GitHub release. This detaches uploaded assets and removes the release object; the tag remains.

   ```bash
   gh release delete releases/<track>/v<X.Y.Z> --yes
   ```

1. Delete the tag locally and on the remote.

   ```bash
   git tag -d releases/<track>/v<X.Y.Z>
   git push --delete origin releases/<track>/v<X.Y.Z>
   ```

### `garter` track only — yank from crates.io

`garter` is the only crate published to crates.io. After the GitHub release/tag are removed, yank the crates.io version:

```bash
cargo yank --version <X.Y.Z> garter
```

Yank does NOT delete the crate from crates.io. It prevents new `Cargo.toml` entries from resolving to the yanked version, but existing `Cargo.lock` files continue to work. To re-allow the version, run `cargo yank --version <X.Y.Z> --undo garter`.

### `hole` track only — auto-updater consideration

`hole` releases are auto-pulled by the upgrade flow (`hole upgrade`). If users have already been updated to a defective release, deleting the GitHub release does NOT roll back their installed version. Procedure:

1. Issue a hotfix release with an incremented patch version.
1. Users on the defective version auto-update to the hotfix on the next upgrade check.
1. Do NOT publish a release with a lower version number than the defective one — the auto-updater treats higher versions as canonical and would not roll back.

## Minisign key rotation (hole only)

Hole's release `SHA256SUMS` is signed with a long-lived minisign key. The public key is committed at [`.github/workflows/publish-release-hole.yaml`](../.github/workflows/publish-release-hole.yaml). The private key is held by the maintainer offline.

Rotation steps (key compromise, lost key, scheduled rotation):

1. Generate a new key pair on the trusted local machine.

   ```bash
   minisign -G -p new-minisign.pub -s new-minisign.key
   ```

1. Update `publish-release-hole.yaml`'s `minisign -Vm SHA256SUMS -P '<NEW-PUBKEY>' ...` line with the new public key.

1. Update [`scripts/sign-release.py`](../scripts/sign-release.py) if it embeds the key path (currently it does not — it uses minisign's default key search).

1. Commit and merge the workflow change.

1. Verify the new key works end-to-end. Cut a test release on a private branch using the new key, run the publish workflow against it, confirm minisign verification passes.

1. **Do NOT delete the old key.** Archive it so historical releases continue to verify against their original signature. The release artifacts on GitHub are immutable; their signature remains tied to the old key.

## Crates.io dry-run TOCTOU

The `garter` draft workflow runs `cargo publish --dry-run -p garter` at validate time to fail-fast on broken metadata (missing fields, license issues, unresolvable deps). The actual `cargo publish` runs later in the publish workflow.

Gap: between draft creation and publish, a transitive dependency could be yanked, an upstream registry change could land, or `Cargo.lock` could drift. Probability is low but non-zero.

On publish failure:

1. Check the failed `cargo publish` output for the yanked or unavailable dep.

1. Two paths:

   - Pin around the issue in `Cargo.toml` (e.g. `dep = "=X.Y.Z-1"` if the latest was yanked), bump garter's version per the group rules, cut a new draft.
   - Wait for upstream resolution and re-run `publish-release-garter.yaml`.

1. The publish workflow is idempotent: it queries crates.io's API and skips `cargo publish` if the version is already there. A re-run after a partial failure resumes cleanly without double-publishing.

The draft GitHub release remains for re-attempt; no rollback is needed unless the draft itself is invalid.
