# The withdrawal list

A published `hole` release is not deleted or hidden ([Withdrawing a release](withdrawal.md)). `static/hole.yaml` on
`main` is the list that steers clients around it: the updater skips a listed version, and warns someone already running
one. The bridge does not read the list.

## The file

`static/hole.yaml` is a signed envelope. Its `payload` is YAML text; `signatures` is a list with one entry per signing
key, each the lines `minisign` writes over that text. The envelope and the payload are read by
`hole_common::withdrawals`, which the client and `cargo xtask sign-static` share.

```yaml
payload: |
  withdrawn:
    - version: 0.7.0
      platforms: [windows-amd64]
      reason: Uninstalling from Settings fails and rolls back.
      url: https://github.com/bindreams/hole/issues/1342
signatures:
  - |
    <the lines minisign writes>
```

A client fetches `https://raw.githubusercontent.com/bindreams/hole/main/static/hole.yaml` (at most 1 MiB) and checks each
entry of `signatures` over the exact string the YAML parser returns for `payload`, with the minisign public key embedded
in the binary. **The list is valid when at least one entry verifies**; entries that do not verify belong to another key
and are ignored. Only then does the client parse `payload`. An empty or missing `signatures` is unreadable. Shipped
clients freeze that URL, the envelope's two keys and `withdrawn:` as an inline list at the top of the payload. Moving the
list elsewhere makes them offer nothing.

The list carries one signature per key because a client verifies only with the key it was built with: across a
[signing-key rotation](minisign-key-rotation.md) one frozen file has to serve clients on both sides of it.

| Entry key   | Meaning                                                                                                     |
| ----------- | ----------------------------------------------------------------------------------------------------------- |
| `version`   | `MAJOR.MINOR.PATCH` of the withdrawn release. Required.                                                     |
| `platforms` | Release platform ids: `windows-amd64`, `darwin-arm64`, `darwin-amd64`. Omitted: every platform. `[]`: none. |
| `reason`    | One sentence, shown in dialogs, in `hole upgrade` output and in the log. Required.                          |
| `url`       | An `https` link to the issue or release page. Required.                                                     |

The file always exists: with nothing withdrawn, the payload is `withdrawn: []`.

### What a client tolerates

- Unknown top-level keys of the payload and unknown keys of an entry are ignored (the signing tool refuses them).
- `platforms` are plain strings compared with the running build's id. An id the client does not know matches nothing.
- A missing or malformed `version`, `reason` or `url` makes the whole list unreadable.
- **A future entry key may only narrow an entry.** An older client ignores it, so it over-skips and never under-skips.
- An unreadable list (it cannot be fetched, the envelope does not parse, no signature verifies, the payload does not
  parse) fails the update check: nothing is offered and nothing is warned about. The check runs again on the next
  schedule.
- A `platforms` key with no value reads as every platform and `platforms: []` as none; `cargo xtask sign-static` refuses
  both ([below](#what-the-tool-refuses)).

## What a client does with it

- A version listed for the client's platform is not offered. The updater offers the next lower release that is still
  newer than the running one and qualifies.
- An install, from the tray or from the "Update Available" dialog, starts only for the version the person was shown,
  and only if a check made after their last answer (the dialog's Install, or the Lockdown-off consent) still offers
  that version. Otherwise nothing is installed and a dialog says so.
- A client running a listed version shows a tray item, `Version X.Y.Z Was Withdrawn...`, that opens a dialog with the
  entry's `reason` and a button for its `url`; `hole upgrade` prints a warning with both. A development build
  (version `X.Y.Z-snapshot+...`) is not the release and gets no warning.

## Adding an entry

1. Add an entry to the payload in `static/hole.yaml`.
1. Sign it: `cargo xtask sign-static`. It takes `--secret-key <path>` and `--public-key <base64>`, each zero or more
   times:
   - With no `--secret-key`, it signs once with `minisign`'s default key (`~/.minisign/minisign.key`), as
     `scripts/sign-release.py` does.
   - With several, it signs once per key, in the order given, and needs the public half of every key the tree does not
     ship: `cargo xtask sign-static --secret-key <old key> --secret-key <new key> --public-key <old public key>`
     ([Rotating the signing key](minisign-key-rotation.md)). Without any `--public-key` it refuses to run.
   - Every run replaces the whole `signatures` list: an edit to `payload` invalidates every old signature, so sign again
     with every key after any edit.
1. Merge the change to `main`. The host caches the file for 300 seconds, so clients see it within 5 minutes.
1. Confirm with `hole upgrade` on a client older than the withdrawn version: it prints a log record containing
   `skipping a withdrawn release` for that version, with its `url`, on stderr and in `gui-cli.log` (the command-line
   log; [where logs go](../architecture/logging.md#where-the-logs-go)).

### What the tool refuses

The tool signs exactly the string the YAML parser returns for `payload`, with `minisign -t` and a fixed trusted comment
without a TAB, so each signature renders as a YAML `|` block. It writes nothing, and says why, when:

- the payload is not a list a client can read (the rules above);
- an entry's `platforms` names an id that is not a release platform (`windows-amd64`, `darwin-arm64`, `darwin-amd64`:
  `hole_common::withdrawals::PLATFORM_IDS`, the list the app's own platform id comes from);
- an entry has `platforms: []`, which covers nothing;
- an entry has a `platforms` key with no value (`platforms:`, `~`, `null`), which a client reads as every platform. To
  withdraw on every platform the key is left out;
- the payload or an entry has a key a client does not read (`hole_common::withdrawals::PAYLOAD_KEYS` and `ENTRY_KEYS`).
  A client ignores such a key, so a misspelled `platforms` or `reason` would be read as absent. A key added to the format
  later is added to those lists first.

### What the tool proves

Before it writes, the tool reads the rewritten file the way a client does, with the public key this tree ships, and
proves every signature it made. It writes only when:

- the read gives back the payload that was signed and at least one signature verifies under the tree's key; if none does
  it fails with `none of the signatures verifies under the public key this tree ships`, and the usual cause is a secret
  key other than the release key;
- every signature verifies under the tree's key or one of the `--public-key` values; a failure names the signature by
  position and the secret key it was made with;
- each `--public-key` verifies at least one signature; a failure names the key.

So a wrong old secret key in a rotation is caught before it writes a file older clients reject.

## Limits

- Only clients that ship this read the list ([what the updater does](withdrawal.md#what-the-updater-does)).
- A replayed older list can hide a withdrawal and cannot invent one.
- The bridge does not read the list: a withdrawn release is still installable by hand.
