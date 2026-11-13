# Command line

The app is the main way to use Hole. These commands are for scripting and recovery.

| Command                              | Description                                                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `hole [--no-show-dashboard]`         | Launch the app. It opens the dashboard unless `--no-show-dashboard` starts it in the tray only.                    |
| `hole version`                       | Print version information.                                                                                         |
| `hole upgrade [-y]`                  | Check for updates and install the latest version. `-y` answers yes to the consent prompt, for non-interactive use. |
| `hole path add` / `hole path remove` | Add or remove `hole` from the system `PATH`. Run it as administrator (`sudo` on macOS). See below.                 |
| `hole bridge unlock`                 | Turn the {term}`kill switch` off and clear the block it left behind. Run it as administrator (`sudo` on macOS).    |

On Windows the installer runs `hole path add` for you. On macOS `hole` is not on
`PATH` until you add it, so every command on this page needs the full path to the app's binary there, for example:

```sh
sudo /Applications/Hole.app/Contents/MacOS/hole path add
sudo /Applications/Hole.app/Contents/MacOS/hole bridge unlock
```

```{admonition} On Windows, from a terminal
---
class: note
---
`hole.exe` is a graphical program that attaches to the terminal it was started from to print. A terminal may give you
its prompt back before a command has finished, and these pages describe the exit status and the `hole upgrade` consent
prompt from the code, not from a measurement on Windows.
```

## hole upgrade

```text
hole upgrade [-y | --yes]
```

Checks GitHub for a newer release of Hole, downloads the archive for this platform, verifies it against the release's
signed `SHA256SUMS`, and hands it to the running {term}`bridge`, which swaps the files and restarts the service. The
command returns once the swap has started, not when the restart has finished.

Installing restarts the VPN. With the {term}`kill switch` off, traffic briefly leaves unencrypted during the restart, so
the command asks for consent:

- With the kill switch on, it does not ask.
- With it off and a terminal attached, it prints a prompt and proceeds only on `y` or `yes`. Anything else, including
  Enter, cancels with exit status 0.
- With it off and no terminal attached, it refuses and exits with status 1, unless `-y` is given. `-y` answers yes in
  advance.

Exit status is 0 when Hole is already up to date, when the update has started, and when you declined at the prompt. It is
1 when the check, the download, the verification or the hand-off fails. Sources: {src}`crates/hole/src/cli.rs` and
{src}`crates/hole/src/update/consent.rs`.

## hole path

```text
hole path add
hole path remove
```

`add` puts `hole` on the system `PATH`; `remove` takes it off. Both need administrator rights, and both exit with status 1
on failure. Open a new terminal afterwards: one that was already open does not see the change.

- **Windows:** `add` appends the folder that holds `hole.exe` to the system `Path` (`HKEY_LOCAL_MACHINE`) and `remove`
  deletes that entry. An entry that is already there, or already gone, is reported and is not an error.
- **macOS:** `add` creates the symlink `/usr/local/bin/hole` pointing at the running binary. If anything else is at that
  path, whether a link to another program or an ordinary file, `add` deletes it first. `remove` deletes the link, and
  refuses one that does not point at a file named `hole`. `add` refuses to run from a translocated copy of the app: move
  Hole.app to `/Applications` first. Run it with the full path to the binary, as shown above.

Source: {src}`crates/hole/src/path_management.rs`.

## hole bridge unlock

```text
hole bridge unlock
```

The recovery route for a {term}`kill switch` block that nothing else can lift: it works with no bridge running. Run it as
administrator (`sudo` on macOS, with the full path to the binary, as above). In order, it records that Hole should not be connected, removes the standing block,
clears the server remembered for the **Always connect** startup choice, and records the kill switch as off. It stops with
an error before changing anything if a bridge is running: the message names the app's **Unblock Network** action as the
route to use then. On Windows it may print a warning that it could not prove every boot-time filter gone.

Exit status is 0 on success and 1 on failure. Source: `unlock` in {src}`crates/bridge/src/cutover.rs`.

The remaining `hole bridge` and `hole proxy` subcommands are for development and administration. They are listed in
the {src}`dev/admin CLI section of CONTRIBUTING.md <CONTRIBUTING.md#cli-devadmin-commands>`.
