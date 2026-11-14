# Rollback

A release is published and turns out to be defective: a broken binary, a regression, a security problem. Rolling back is
a **forward-only mitigation, not an undo**. A yanked crates.io version cannot be published again, and a GitHub release
deleted and re-created under the same tag has a different commit history behind it. Plan for a fixed release, not for
putting the old state back.

## Every track

1. Delete the GitHub release. That removes the release and its files. The git tag survives unless you also pass
   `--cleanup-tag`, which drops both:

   ```sh
   gh release delete -R bindreams/hole releases/<product>/v<X.Y.Z> --yes --cleanup-tag
   ```

1. If the tag is still there (you left `--cleanup-tag` off), delete it:

   ```sh
   git tag -d releases/<product>/v<X.Y.Z>
   git push --delete origin releases/<product>/v<X.Y.Z>
   ```

A **draft** release holds its tag in the release's metadata, not as a git ref, so deleting it removes both together, and
`git tag -d` then fails with "tag not found". That is expected.

## Yanking garter

After the steps above, yank the version from crates.io:

```sh
cargo yank --version <X.Y.Z> garter
```

- A yanked version no longer resolves for a new `Cargo.toml` entry. It is not deleted: an existing `Cargo.lock` still
  resolves it.
- **The version number is used up.** crates.io rejects a second `cargo publish` of the same `X.Y.Z`, so the fix needs a
  strictly greater version.
- `cargo yank --version <X.Y.Z> --undo garter` reverses it. Avoid that once a fix is out: two installable versions
  confuse resolution downstream.

## Rolling back hole

Installed copies of `hole` update themselves, and the update is **forward-only**. {src}`crates/hole/src/update/check.rs`
(`candidate_tags`) keeps only tags whose version is greater than the running one, then offers the highest release that
qualifies.

- Deleting the defective release makes the lookup for its tag come back empty, so the updater skips it and offers the
  previous good release to anyone who has not installed the defective one.
- A copy that already runs the defective version never goes back: the previous release is older than it. Only a **hotfix
  with a strictly greater version** reaches it. Publishing a hotfix with a lower number than the defective release would
  be skipped.
- Nothing withdraws a release from a machine that has it installed, so the time to roll back is the time to ship the
  hotfix. For a severe bug, tell users out of band (a release announcement, a README banner) while the hotfix is in
  flight.

## Plugins that ship inside hole

`hole` ships both plugins, ex-ray and galoshes ([Plugin binaries](../architecture/plugin-binaries.md)), and galoshes
embeds its own copy of ex-ray ([The workspace](../workspace.md#how-galoshes-carries-ex-ray)). A defective plugin that has
already shipped inside a `hole` release therefore needs two rollbacks:

1. Roll back the **standalone** release of the plugin with the steps above, so nobody deploys it fresh.
1. Roll back the **bundled** copy by cutting a new `hole` release that carries the fixed plugin. The plugin's bytes are
   baked into the installer, so fixing the standalone release does nothing for a `hole` already installed.

A defective ex-ray is in three places, so the fix goes out in this order: a fixed ex-ray, a galoshes built after it (so
it embeds the fixed copy), then a `hole` that carries both.

The `ex-ray` track needs no crates.io step. It follows the plain procedure under [Every track](#every-track): delete the
tag and release, and re-cut from a patched commit. Its version is in {src}`crates/ex-ray/version.toml`, checked by
{src}`xtask-lib/src/ex_ray_version.rs`.
