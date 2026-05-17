# Release operations runbook

Per-product release procedure: see [CLAUDE.md § Releases](../CLAUDE.md#releases). This file is the runbook for the off-happy-path operations: rollback, minisign key rotation, and the crates.io dry-run staleness gap.

## Rollback procedure

Rollback is a **forward-only mitigation**, not undo. A yanked crates.io version cannot be republished; a deleted-and-recreated GitHub release with the same tag has a different commit history. Plan accordingly.

Use when a release is published but later determined defective (broken binary, regression, security issue).

### All tracks (prerequisite for the per-track sections below)

1. Delete the GitHub release. This removes the release object and all uploaded assets. The underlying git tag is preserved by default; use `--cleanup-tag` to drop both in one shot.

   ```bash
   gh release delete releases/<track>/v<X.Y.Z> --yes --cleanup-tag
   ```

1. If `--cleanup-tag` wasn't used (or the tag still exists locally), delete the tag explicitly.

   ```bash
   git tag -d releases/<track>/v<X.Y.Z>
   git push --delete origin releases/<track>/v<X.Y.Z>
   ```

For a **draft** release (e.g. a failed `garter` publish), `gh release delete` destroys the release AND the tag together (drafts hold tags in release metadata, not as real git refs). The `git tag -d` step will fail with "tag not found" — expected.

### `garter` track only — yank from crates.io

`garter` is the only crate published to crates.io. After completing the all-tracks steps above, yank the crates.io version:

```bash
cargo yank --version <X.Y.Z> garter
```

What yank does and doesn't do:

- Prevents new `Cargo.toml` entries from resolving to the yanked version.
- Does NOT delete the version. Existing `Cargo.lock` files still resolve it via sparse registry / `cargo fetch`.
- **Permanently consumes the version number.** A subsequent `cargo publish` of the same `X.Y.Z` is rejected by crates.io; the hotfix MUST use a strictly greater version.
- `cargo yank --version <X.Y.Z> --undo garter` un-yanks. Avoid using this after a hotfix is published — it leaves two versions installable and confuses downstream resolution.

### `hole` track only — auto-updater consideration

`hole` releases are auto-pulled by the upgrade flow (`hole upgrade`, periodic check via `start_update_checker`). The auto-updater is **forward-only**: [`candidate_tags`](../crates/hole/src/update/check.rs) keeps only tags with `ver > current` (strict greater-than for non-snapshot installs).

What this means for rollback:

1. Deleting the defective GitHub release causes `fetch_release_for_tag` to return None for that tag, so new `hole upgrade` invocations skip it and find the previous-good release. New users are immediately safe.
1. Users already on the defective version are stuck. The client never downgrades. The only fix is a **hotfix release with a strictly greater version**.
1. Time-to-rollback equals time-to-cut-hotfix. There is no kill switch. For severe bugs, notify users out-of-band (GitHub release announcement, README banner) while the hotfix is in flight.
1. Do not publish a hotfix with a lower version number than the defective one. The version-comparison check would skip it.

## Minisign key rotation (hole only)

Hole's release `SHA256SUMS` is signed with a long-lived minisign key. **Two embedded copies of the public key must stay in sync**:

- Server-side (release verification): embedded in the `Verify signature` step of [`.github/workflows/publish-release-hole.yaml`](../.github/workflows/publish-release-hole.yaml) as the `-P '...'` argument to `minisign -Vm`.
- Client-side (auto-update verification): `MINISIGN_PUBLIC_KEY` constant in [`crates/hole/src/update/verify.rs`](../crates/hole/src/update/verify.rs).

The private key lives on the maintainer's machine at minisign's default location (`~/.minisign/minisign.key`). [`scripts/sign-release.py`](../scripts/sign-release.py) calls `minisign -Sm` without `-s`, so the default path is what gets used unless `--secret-key` is passed.

Rotation steps (key compromise, lost key, scheduled rotation):

1. Generate a new key pair on the trusted local machine.

   ```bash
   minisign -G -p new-minisign.pub -s new-minisign.key
   ```

1. **Archive** the current `~/.minisign/minisign.key` (do NOT delete — see step 7) and replace it with `new-minisign.key`.

1. Update the public key in `.github/workflows/publish-release-hole.yaml` (the `-P '<NEW-PUBKEY>'` argument to `minisign -Vm`).

1. Update the public key in `crates/hole/src/update/verify.rs` (`MINISIGN_PUBLIC_KEY` constant). **Missing this step silently breaks `hole upgrade` for all already-installed clients** — they verify against the old key and reject the new-key-signed release.

1. Commit and merge the workflow + client changes together.

1. Verify end-to-end. Cut a release on a temporary branch using the new key against a **personal fork** (not the production repo — a production publish workflow flips `/releases/latest`, which would clobber the live release). Run the fork's publish workflow, confirm minisign verification passes, confirm `hole upgrade` against the fork accepts the new signature.

1. **Do NOT delete the old key.** Archive it so historical releases continue to verify against their original signature. The release artifacts on GitHub are immutable; their signature remains tied to the old key. If a user runs `hole upgrade` from a very old version and the auto-updater walks intermediate releases, those intermediate signatures still need the old public key on the client — which is why the client-side key in `verify.rs` MUST be updated for new releases but old clients MUST retain the old key (handled today by clients only verifying the release they're upgrading to, never historical ones).

**Compromised key vs. lost key.** A compromised key requires a public revocation (announce in repo README + GitHub release notes) in addition to rotation. A lost key requires the same rotation procedure but is recoverable only because the maintainer can sign a new client release with the new key — the next `hole upgrade` cycle propagates the trust transition.

## Crates.io dry-run staleness

(Originally framed as "TOCTOU" — strictly it's stale validation, not a check-then-act race.)

The `garter` draft workflow runs `cargo publish --dry-run -p garter` at validate time to fail-fast on broken metadata (missing fields, license issues, unresolvable deps). The actual `cargo publish` runs later in the publish workflow. Between those two moments, a transitive dep could be yanked, an upstream registry change could land, or `Cargo.lock` could drift.

On publish failure:

1. Read the failed `cargo publish` output to identify the yanked or unavailable dep.

1. Pick a recovery path based on the failure mode:

   - **Transient upstream issue** (e.g. registry hiccup): wait, then re-run the publish workflow. Idempotent — if the version already reached crates.io, `cargo publish` is skipped and the GitHub release is just flipped from draft to published.
   - **Persistent issue** (yanked dep, breaking registry change): the draft is salvageable only after the underlying `Cargo.toml` is patched. Pin around the issue (e.g. `tokio = "=1.41.0"` to lock to the previous-good version), bump garter's version per the group rules, abandon the existing draft (`gh release delete` per the rollback procedure above), and cut a new draft against the patched commit.

The publish workflow's idempotency check (`already_published` query) protects against **double-publishing** the same version, NOT against repeated-failure publishes — a yanked-dep failure will reproduce on every re-run until the upstream resolution lands.

## Track interactions

### Bundled-galoshes consideration

CLAUDE.md notes galoshes is "shipped alongside hole.exe AND released standalone." A defective galoshes shipped inside a hole release requires:

1. Roll back the **standalone** galoshes release using the procedure above (so server operators don't deploy it fresh).
1. Roll back the **bundled** copy by cutting a new hole release with a fixed galoshes. The bundled bytes are baked into the MSI/DMG — patching galoshes alone does not retroactively fix already-installed hole.

### v2ray-plugin lineage rollback

The v2ray-plugin track uses `X.Y.Z-hole.N` lineage versioning (per CLAUDE.md). The "no-gaps" sequence validator in [`xtask-lib/src/v2ray_plugin_version.rs`](../xtask-lib/src/v2ray_plugin_version.rs) rejects skipped N values. After rolling back `1.3.3-hole.1`, the next attempt must be `1.3.3-hole.2` (the rollback removed the tag; the validator looks at tag history not release history, so the gap is invisible to it).
