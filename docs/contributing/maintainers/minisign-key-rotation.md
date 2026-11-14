# Rotating the signing key

Every `hole` release's `SHA256SUMS` is signed with a minisign key ([Releasing](releases.md)). This page is the order in
which to replace that key, and why the order matters: an installed copy of Hole trusts only the public key it was built
with.

## Who checks what

The signature is checked in two directions, with keys held in separate places:

| Check                               | Whose key                                  | Where the public key is                                                                                           |
| ----------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| An installed Hole checks an update  | The key **of the version already running** | `MINISIGN_PUBLIC_KEY` in {src}`crates/common/src/verify.rs`, used by the app and by the bridge before it extracts |
| The publish workflow checks a draft | The key **in the workflow file**           | The `-P` argument of the `Verify signature` step in {src}`.github/workflows/publish-release-hole.yaml`            |

{src}`.github/workflows/reusable-publish-release.yaml` carries a third copy, for its `verify-signature` input. No track
sets that input today, since `hole` publishes through its own file, but a rotation updates it too, so a later user of the
input does not inherit the old key.

The private key stays on the maintainer's machine. `scripts/sign-release.py` calls `minisign -Sm` and passes `-s` only
when given `--secret-key`, so minisign's default key is used otherwise.

## The order

A client checks a release against its *own* key, so a release signed with a new key is rejected by every client that does
not already contain the new public key. The new key therefore ships one release before it signs anything. Call the release
that introduces the key **N**.

1. **Generate the new pair** on a trusted machine, and keep the old private key until N is signed:

   ```sh
   minisign -G -p new-minisign.pub -s new-minisign.key
   ```

1. **Release N embeds the new public key and is signed with the old key.** Put the new public key in
   `MINISIGN_PUBLIC_KEY`, leave the workflows alone, and release as usual with
   `uv run scripts/sign-release.py <version> --secret-key <old key>`. The clients that update to N verify it with the old
   key they already have; N carries the new one. The publish workflow still holds the old key, so it verifies N.

1. **After N is published, replace the public key in the workflow files** ({src}`.github/workflows/publish-release-hole.yaml`
   and the reusable one) with the new key.

1. **Release N+1 and every later release are signed with the new key.** Pass it to the script as
   `--secret-key <new key>`: without `--secret-key`, minisign's default key signs. Clients that installed N verify them.

```{warning}
Signing N with the new key makes every installed client reject N. Putting the new public key in the workflows before N
is published makes the publish workflow reject N.
```

### What a rotation costs

The updater offers only the newest release that qualifies ({src}`crates/hole/src/update/check.rs`), and it does not step
through the releases in between. A copy older than N is therefore offered N+1, whose signature its old key rejects. Those
users install N+1 by hand from the releases page.

If the old key is **lost**, N cannot be signed with it, and no installed client accepts a release signed with the new
key: every user installs the new release by hand. If the old key is **compromised**, rotate the same way and announce it in
the repository README and the release notes. Until a client has installed N, whoever holds the old key can sign an update
it accepts.

### Checking a rehearsal

Rehearse on a personal fork, never on the production repository: a production publish flips `/releases/latest`.

`scripts/sign-release.py` cannot be used on a fork. It hard-codes `REPO = "bindreams/hole"` in every `gh` call, so on a
rehearsal it would look at the production repository and, if a draft of that version exists there, upload the signature
to it. Sign the fork's draft by hand, naming the fork in each command:

```sh
gh release download <tag> -R <fork> --pattern SHA256SUMS
minisign -Sm SHA256SUMS -s <secret key>
gh release upload <tag> -R <fork> SHA256SUMS.minisig
```

Run the fork's draft workflow, sign by hand, run its publish workflow, and confirm that the `Verify signature` step
passes. That step checks the public key in the fork's own workflow file, so a rehearsal of step 3 edits it there.

A fork cannot exercise the client half, because the updater's repository is the constant `REPO` in `check.rs`. Check the
key in {src}`crates/common/src/verify.rs` against a release signed by the new key with the same tool the workflow uses:

```sh
minisign -Vm SHA256SUMS -P <the public key in crates/common/src/verify.rs> -x SHA256SUMS.minisig
```
