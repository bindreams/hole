# Signing keys

Every `hole` release's `SHA256SUMS` is signed with a [minisign](https://jedisct1.github.io/minisign/) key, and an
installed copy of Hole accepts an update only if it is signed by a key that copy was built with. Replacing the key in
use is a separate procedure with an order that matters: [Rotating the signing key](minisign-key-rotation.md), which also
lists every place the public key appears.

## Making a key pair

Get minisign from [its home page](https://jedisct1.github.io/minisign/) (prebuilt binaries for each platform) or your
package manager. Then, on a machine you trust:

```sh
minisign -G -p hole.pub -s hole.key
```

minisign asks for a password and encrypts the private key with it. Give it a strong one. `-W` skips the password; do not
use it for a release key.

The command writes two files:

| File       | What it is                                                                                    |
| ---------- | --------------------------------------------------------------------------------------------- |
| `hole.key` | The private key, encrypted with the password.                                                 |
| `hole.pub` | A comment line, then the public key: one string starting `RW`. That string is the public key. |

The public key string is what Hole embeds, as `MINISIGN_PUBLIC_KEY` in {src}`crates/common/src/verify.rs`.

## Checking a pair

Before a key signs anything real, sign a scratch file and verify it against the public key string exactly as it is
pasted into the code:

```sh
echo test > scratch.txt
minisign -Sm scratch.txt -s hole.key
minisign -Vm scratch.txt -H -P <the RW... string from verify.rs>
```

The last command prints `Signature and comment signature verified` when the pair matches. `-H` makes minisign accept
only a prehashed signature, the only kind Hole accepts, so an old minisign that signs the legacy way fails here instead
of in every installed copy.

## Keeping the private key

- The key is the private key file **and** its password. Losing either one loses the key.
- Keep the private key on the machine that signs, and a backup offline, for example on an encrypted drive that stays
  disconnected. Store the password separately from both, somewhere that survives losing that machine.
- A release is signed with the key you name with `--secret-key`; see [Releasing](releases.md) and the rotation page.

```{warning}
A lost key cannot sign a release that installed copies accept, so every user has to install the next release by hand.
A key that someone else may hold can sign an update that installed copies accept, until they have updated to a release
that no longer trusts it. [Rotating the signing key](minisign-key-rotation.md) covers both cases.
```
