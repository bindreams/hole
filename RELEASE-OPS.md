# Release operations runbook

Per-product release procedure: see [CONTRIBUTING.md § Releases](CONTRIBUTING.md#releases). This file is the runbook for the off-happy-path operations — rollback, minisign key rotation, and the crates.io dry-run staleness gap.

## Ship blockers

Conditions under which a `hole` release must not go out, recorded here because the code that states them is not where a release operator looks.

- **The first `hole` release without `NOTICES.md` in its Windows update archive**: its release notes must tell Windows
  users on 0.5.0 to 0.7.0 that the in-app update fails (on 0.5.0 and 0.6.0 a retry is then refused until the computer
  restarts), and that they update by running the new MSI over the existing install, not by uninstalling first: on
  0.5.0 and 0.6.0 an uninstall after the failed update leaves the kill switch's block in place. Their installed update
  code requires that file.

## Stated limits

Shortfalls that ship on purpose, each with the condition that triggers it and the way out.

- **A stranded Windows boot-time kill-switch twin.** [#998](https://github.com/bindreams/hole/issues/998) adds `FWPM_FILTER_FLAG_BOOTTIME` twins to the standing lockdown cover's block-all pair. A stranded `PERSISTENT` filter self-heals (BFE re-adds it every boot, so a later GUID-aware build can delete it by key); a stranded boot-time one does not, and a build that never learned its GUID cannot delete it by key. [#1008](https://github.com/bindreams/hole/issues/1008)'s version-independent sweep (`release_all` and `disengage_lockdown`, so every release and unlock, read the boot-time view of every layer and delete every boot-time filter under `PROVIDER_GUID` that no key list names; a persistent one is left on purpose, [#1242](https://github.com/bindreams/hole/issues/1242)) removes one whatever its key, so a downgrade through a normal uninstall cannot strand a twin. A twin is stranded only by:

  1. an uninstall with `LEAVE_NETWORK_BLOCKED=1`, which skips the release (every cover stays, see "Windows uninstall refuses to complete"); or
  1. an upgrade that rolls back after the new bridge engaged the kill switch, when the release rolled back to does not list the new release's boot-time keys (0.6.0 to 0.7.0 is the first such pair), followed by a reboot before the rolled-back build's next unlock. The sweep reaches a stranger only within the boot it was installed in (a boot-time filter is not live after BFE starts, so neither a by-key delete nor the enumeration finds it on a later boot; whether it does is [#1043](https://github.com/bindreams/hole/issues/1043)'s unmeasured question), so the reboot strands it.

  **Effect:** egress is blocked from kernel start until BFE start on every boot (a soft block: the machine boots and works after that). **Way out:** reinstall the release that installed the twin, or later (the uninstall gate's report names the running build's release), turn the kill switch on, then off. After a reboot the stranded twin is not live, so `hole bridge unlock` or `release-covers` alone delete nothing they can prove: a by-key delete answers not-found, and the boot-time enumeration goes through BFE. Turning the kill switch on is an engage, which deletes and re-adds the twins' fixed keys (only those that build lists, which is why an older build cannot clear a newer release's twin), so the twin is live on this boot; turning it off then deletes a live twin, a removal the sweep watched. That an engage's re-add replaces a stranded boot-time record, and that a by-key delete purges the record so the block is gone on the next boot, are both [#1043](https://github.com/bindreams/hole/issues/1043)'s unmeasured assumption; nothing in CI reboots.

  **Forward rule:** a boot-time key a release ships stays in the sweep list of every later build, so a downgrade from any later release can still delete it by key. The enumeration is the backstop for a key an older build never learned, not a replacement for the list. Adding a boot-time key needs no edit to the uninstall gate's remedy: it names the running build's release, whose list names the key.

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

### crates.io tracks (`garter`) — yank

After completing the all-tracks steps above, yank the crates.io version:

```bash
cargo yank --version <X.Y.Z> <crate>
```

What yank does and doesn't do:

- Prevents new `Cargo.toml` entries from resolving to the yanked version.
- Does NOT delete the version. Existing `Cargo.lock` files still resolve it via sparse registry / `cargo fetch`.
- **Permanently consumes the version number.** A subsequent `cargo publish` of the same `X.Y.Z` is rejected by crates.io; the hotfix MUST use a strictly greater version.
- `cargo yank --version <X.Y.Z> --undo <crate>` un-yanks. Avoid using this after a hotfix is published — it leaves two versions installable and confuses downstream resolution.

### `hole` track only — auto-updater consideration

`hole` releases are auto-pulled by the upgrade flow (`hole upgrade`, periodic check via `start_update_checker`). The auto-updater is **forward-only**: [`candidate_tags`](crates/hole/src/update/check.rs) keeps only tags with `ver > current` (strict greater-than for non-snapshot installs).

What this means for rollback:

1. Deleting the defective GitHub release causes `fetch_release_for_tag` to return None for that tag, so new `hole upgrade` invocations skip it and find the previous-good release. New users are immediately safe.
1. Users already on the defective version are stuck. The client never downgrades. The only fix is a **hotfix release with a strictly greater version**.
1. Time-to-rollback equals time-to-cut-hotfix. There is no kill switch. For severe bugs, notify users out-of-band (GitHub release announcement, README banner) while the hotfix is in flight.
1. Do not publish a hotfix with a lower version number than the defective one. The version-comparison check would skip it.

## Windows uninstall refuses to complete

The MSI's `BridgeRelease` custom action releases every fail-closed cover and disarms the kill switch before `RemoveFiles` deletes `hole.exe`. It is the one uninstall action with `Return="check"`, because the WFP filters are `FWPM_FILTER_FLAG_PERSISTENT`: leaving them behind is a host that is blocked on every boot with no binary left to remove them ([#1003](https://github.com/bindreams/hole/issues/1003)).

So an uninstall that aborts at `BridgeRelease` is the gate working. Fix the cause first — it is almost always one of:

1. The Base Filtering Engine service is not running (`sc query BFE`). Start it and retry.
1. `hole.exe` was quarantined by AV, so the custom action could not launch at all. Restore it and retry.

If the release can never succeed, force the uninstall past the gate:

```
msiexec /x hole.msi LEAVE_NETWORK_BLOCKED=1
```

**This can leave the host blocked.** `LEAVE_NETWORK_BLOCKED=1` skips the uninstall's release step entirely: every fail-closed cover in place stays (the kill switch's firewall rules and, if one was engaged, the transient startup cover) and the target is not recorded off. If a cover was engaged, the network stays blocked. Reinstalling alone does not clear it, because the new bridge adopts a live cover: reinstall, then turn the kill switch off or run `hole bridge release-covers` elevated. Boot-time twins need the release that installed them (see "Stated limits"). Nothing shipped with Windows can undo it: `netsh wfp` is diagnostics-only (`capture`, `dump`, `help`, `set`, `show` — [no delete verb](https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wfp)), so `netsh wfp show filters` can show Hole's persistent provider but not remove it. Use `netsh wfp show boottimepolicy` for the kill switch's boot-time twins: `show filters` lists what is active *now*, which by definition excludes a boot-time filter once BFE has started — i.e. at every moment you can run the command. Removing a WFP filter takes an FWPM call, and `hole.exe` is the only caller of one on that host. So use this only after the release named in "Stated limits" above has been reinstalled (an older build cannot delete a boot-time key it was never taught) and `hole bridge release-covers` (elevated) has been tried and cannot succeed — and expect to reinstall that release again, then turn the kill switch off or run `hole bridge release-covers`, to clear the block.

## Minisign key rotation (hole only)

Hole's release `SHA256SUMS` is signed with a long-lived minisign key. **Two embedded copies of the public key must stay in sync**:

- Server-side (release verification): embedded in the `Verify signature` step of [`.github/workflows/publish-release-hole.yaml`](.github/workflows/publish-release-hole.yaml) as the `-P '...'` argument to `minisign -Vm`.
- Client-side (auto-update verification): `MINISIGN_PUBLIC_KEY` constant in [`crates/hole/src/update/verify.rs`](crates/hole/src/update/verify.rs).

The private key lives on the maintainer's machine at minisign's default location (`~/.minisign/minisign.key`). [`scripts/sign-release.py`](scripts/sign-release.py) calls `minisign -Sm` without `-s`, so the default path is what gets used unless `--secret-key` is passed.

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

The `garter` draft workflow runs `cargo publish --dry-run -p garter` at validate time to fail-fast on broken metadata (missing fields, license issues, unresolvable deps). The actual `cargo publish` runs later in the publish workflow. Between those two moments, a transitive dep could be yanked, an upstream registry change could land, or `Cargo.lock` could drift.

On publish failure:

1. First check whether the release is already published: the auth action's post-step token revoke can fail after the release flip. A re-run then fails at "Release ... is not a draft"; the token expires on its own.

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

### ex-ray rollback

The `ex-ray` track uses plain `X.Y.Z` semver (first-party; no upstream-lineage tracking). Its version lives in [`crates/ex-ray/version.toml`](crates/ex-ray/version.toml) and is validated by [`xtask-lib/src/ex_ray_version.rs`](xtask-lib/src/ex_ray_version.rs). Rollback follows the standard non-crates.io track procedure (delete the tag + release; re-cut against a patched commit). Because galoshes embeds ex-ray and hole bundles galoshes, a defective ex-ray that has already shipped inside a hole release also requires the bundled-galoshes rollback above (re-cut hole with a fixed galoshes that embeds the fixed ex-ray).
