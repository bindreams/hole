# Signing keys

Every `hole` release's `SHA256SUMS` is signed with a [minisign](https://jedisct1.github.io/minisign/) key, and an
installed copy of Hole accepts an update only if it is signed by a key that copy was built with. This page covers
making a key pair and keeping it. Replacing the key in use is a separate procedure with an order that matters:
[Rotating the signing key](minisign-key-rotation.md).

## Making a key pair

Install minisign ([its installation notes](https://jedisct1.github.io/minisign/#installation) list the packages for
each platform), then, on a machine you trust:

```sh
minisign -G -p hole.pub -s hole.key
```

minisign asks for a password and encrypts the private key with it. Give it a strong one. `-W` skips the password; do not
use it for a release key.

The command writes two files:

| File       | What it is                                                                                    | Where it goes                    |
| ---------- | --------------------------------------------------------------------------------------------- | -------------------------------- |
| `hole.key` | The private key, encrypted with the password.                                                 | Only on the machine that signs.  |
| `hole.pub` | A comment line, then the public key: one string starting `RW`. That string is the public key. | Into the code and the workflows. |

The public key string is what Hole embeds (`MINISIGN_PUBLIC_KEY` in {src}`crates/common/src/verify.rs`) and what the
publish workflows check against. The rotation page lists every place it appears.

## Checking a pair

Before a key signs anything real, sign a scratch file and verify it with the public key:

```sh
echo test > scratch.txt
minisign -Sm scratch.txt -s hole.key
minisign -Vm scratch.txt -p hole.pub
```

The last command prints `Signature and comment signature verified` when the pair matches.

## Keeping the private key

- Keep the private key and its password apart. Either one alone is useless, and losing either loses the key.
- Keep a backup of the private key offline, for example on an encrypted drive that stays disconnected.
- `scripts/sign-release.py` signs with `--secret-key <file>` when given one, and otherwise with minisign's default key,
  `~/.minisign/minisign.key`.

```{warning}
A lost key cannot sign a release that installed copies accept, so every user has to install the next release by hand.
A key that someone else may hold can sign an update that installed copies accept, until they have updated to a release
that no longer trusts it. [Rotating the signing key](minisign-key-rotation.md) covers both cases.
```
