# Withdrawing a release

A release is published and turns out to be defective: a broken binary, a regression, a security problem. It is
**withdrawn**, by the steps below.

## Withdrawing hole

1. **Put a caution banner at the top of the release's notes.** It says the defect, the platforms affected, the issue, what
   to install instead, and what a person already running the release should do. The banner names a version and never
   links `/releases/latest`, which moves. It has this form:

   ```markdown
   > [!CAUTION]
   > **DO NOT USE: <the defect>, on <platforms>.** Tracked in [#<issue>](https://github.com/bindreams/hole/issues/<issue>).
   > To install, use <version>. If you already run it: <wait for the fix in the next release, or the workaround>.
   ```

   A person already on the release has no way back on Windows: the installer refuses a downgrade
   ({src}`msi-installer/src/msi_installer/hole.wxs`, `MajorUpgrade` with `DowngradeErrorMessage`, no `AllowDowngrades`). They
   wait for the fix or use a workaround.

   Change the notes by editing a copy of them. Do not run the edit if `notes.md` is empty: it would replace the notes with
   the banner alone.

   ```sh
   gh release view -R bindreams/hole releases/hole/v<X.Y.Z> --json body --jq .body > notes.md
   test -s notes.md   # must succeed; if not, stop
   # put the banner at the top of notes.md
   gh release edit -R bindreams/hole releases/hole/v<X.Y.Z> --notes-file notes.md
   ```

1. **If the withdrawn release is the one flagged latest, move "latest" to the previous good `hole` release**, so the
   README's download link stops serving it. Do this before the fix is published, which sets "latest" itself. If a `hole`
   release newer than the withdrawn one is already published and not withdrawn, "latest" belongs to that one, not to an
   older release: it is `<GOOD>` below. The latest release is the tag the first command prints; if it is another one,
   skip the step. The last command must print `releases/hole/v<GOOD>`:

   ```sh
   gh api -X GET repos/bindreams/hole/releases/latest --jq .tag_name
   gh release edit -R bindreams/hole releases/hole/v<GOOD> --latest
   gh api -X GET repos/bindreams/hole/releases/latest --jq .tag_name
   ```

   Only the `hole` track claims latest ([`/releases/latest` belongs to hole](releases.md#releaseslatest-belongs-to-hole)).
   The README's link serves every platform, so a release withdrawn on one platform sends the other platforms to the older
   release too. The edit may lock `<GOOD>` ([Immutable releases](#immutable-releases)); nothing in this procedure needs it
   to stay editable.

1. **Add the release to the withdrawal list**, so the updater skips it:
   [Adding an entry](withdrawal-list.md#adding-an-entry).

1. **Publish a fix with a strictly greater version** ([Cutting a release](releases.md#cutting-a-release)).

## What is never done

- **Deleting a published release.** A URL that served a good file would serve nothing, or something else.
- **Flagging it pre-release to hide it.** The flag mislabels the release.
- **Removing one platform's files from an older release that is still mutable.** The route exists and is not used: it is a
  partial delete, and it protects no client, because every client that could be offered such a release is offered a
  higher one first.

## Immutable releases

Immutable releases are on for this repository since 2026-11-15. A release published from then on has its **assets and tag
locked**. Its title, notes, pre-release flag and latest flag stay editable. Immutability cannot be undone for a release
once it is published, and a deleted immutable release uses up its tag name for good.

A release published before that date is mutable until its first edit; the notes edit locks it (measured on
`releases/hole/v0.7.0`). Whether an edit of the latest flag alone locks one is not measured.

## What the updater does

Installed copies of `hole` update themselves, and the update is **forward-only**. {src}`crates/hole/src/update/check.rs`
(`candidate_tags`) keeps only tags whose version is greater than the running one and not withdrawn on its platform, then
offers the highest release that qualifies.

- A copy that already runs the defective version never goes back: the previous release is older than it. Only a **fix
  with a strictly greater version** reaches it. A fix with a lower number than the defective release is skipped.
- A client that reads the withdrawal list skips the release on a fresh check: at launch, in `hole upgrade`, or in the
  re-check before an install. That is within 5 minutes of the entry merging. A running app checks every 24 hours
  ({src}`crates/hole/src/update/periodic.rs`, `UPDATE_CHECK_INTERVAL`) and keeps showing the offer it stored until then;
  a failed check keeps it too (`state_after`). An install of that offer is refused by the re-check
  ([what a client does with it](withdrawal-list.md#what-a-client-does-with-it)).
- A client that predates the list (`0.7.0` and older) checks for updates at launch and is offered the withdrawn release
  at once, until the fix is published. Moving "latest" protects the download, not these installed copies: tell their
  users out of band (a release announcement, a README banner) while the fix is in flight.

## The banner on garter, galoshes and ex-ray

Put the caution banner on the track's GitHub release with the same two commands as for `hole`, and the tag
`releases/<product>/v<X.Y.Z>` (`garter`, `galoshes` or `ex-ray`). Do not run the edit if `notes.md` is empty.

```sh
gh release view -R bindreams/hole releases/<product>/v<X.Y.Z> --json body --jq .body > notes.md
test -s notes.md   # must succeed; if not, stop
# put the banner at the top of notes.md
gh release edit -R bindreams/hole releases/<product>/v<X.Y.Z> --notes-file notes.md
```

Of the `hole` banner's template, `garter` has no platforms to name (omit `on <platforms>`), and none of the three claims
"latest", so there is no step 2 for them.

## Withdrawing garter

Withdraw the version from crates.io, and put the caution banner on its GitHub release. The release is not deleted.
`cargo yank` needs a crates.io token of a `garter` owner (`cargo login`); CI publishes with trusted publishing and holds
none ([Publishing garter](garter-crates-io.md#how-it-publishes)).

```sh
cargo yank --version <X.Y.Z> garter
```

- A yanked version no longer resolves for a new `Cargo.toml` entry. It is not deleted: an existing `Cargo.lock` still
  resolves it.
- **The version number is used up.** crates.io rejects a second `cargo publish` of the same `X.Y.Z`, so the fix needs a
  strictly greater version.
- `cargo yank --version <X.Y.Z> --undo garter` reverses it. Avoid that once a fix is out: it makes the defective version
  resolvable again for any requirement that excludes the fix.

## Withdrawing galoshes and ex-ray

For a standalone release, [the caution banner](#the-banner-on-garter-galoshes-and-ex-ray) is the only marking: neither
track claims latest, and neither has an updater.
Publish a fix with a strictly greater version, as for `hole`.

`hole` ships both plugins, ex-ray and galoshes ([Plugin binaries](../architecture/plugin-binaries.md)), and galoshes
embeds its own copy of ex-ray ([The workspace](../workspace.md#how-galoshes-carries-ex-ray)). A defective plugin that has
already shipped inside a `hole` release makes that `hole` release defective: withdraw it by the
[full `hole` procedure](#withdrawing-hole). The plugin's bytes are baked into the installer, so a fix to the standalone
release does nothing for a `hole` already installed.

A defective ex-ray is in three places, so the fix goes out in this order: a fixed ex-ray, a galoshes built after it (so it
embeds the fixed copy), then a `hole` that carries both. The ex-ray version is in {src}`crates/ex-ray/version.toml`,
checked by {src}`xtask-lib/src/ex_ray_version.rs`.
