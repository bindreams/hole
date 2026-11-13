# Install

This page gets Hole onto a computer. It covers which download to pick, the steps for Windows and for macOS, and what the
administrator prompts mean.

## Pick the right download

Installers are on Hole's [latest release](https://github.com/bindreams/hole/releases/latest) page. Under **Assets**, pick
the file that matches the computer:

| The computer                         | The file                           |
| ------------------------------------ | ---------------------------------- |
| Windows, 64-bit Intel or AMD         | `hole-<version>-windows-amd64.msi` |
| Mac with Apple silicon (M1 or later) | `hole-<version>-darwin-arm64.dmg`  |
| Mac with an Intel processor          | `hole-<version>-darwin-amd64.dmg`  |

`<version>` stands for the release's version number. The other files in the list (`.zip`, `.tar.gz`, `SHA256SUMS`) are
for Hole's own updater; you do not need them.

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

Hole supports 64-bit Intel and AMD PCs. To check, open **Settings** → **System** → **About**: the **System type** line
should say "64-bit operating system, x64-based processor". Windows on ARM is not supported. Hole needs Windows 10 version
2004 or later; Windows 11 qualifies.
```

```{tab-item} macOS
:sync: macos

Open the Apple menu, choose **About This Mac** and look at the **Chip** line. If it starts with "Apple" followed by a
name such as M1, the Mac has Apple silicon: pick the `arm64` file. If it says Intel, pick the `amd64` file.
```
````

### If GitHub is hard to reach

Hole's installers are published on that GitHub page and nowhere else, and Hole checks GitHub for updates. If GitHub is
blocked or unreliable where the person lives, download the installer yourself and send them the file: the `.msi` and the
`.dmg` are each a single self-contained file. While Hole is connected, its update check travels through the tunnel like
any other app's traffic.

````{dropdown} Check that the file arrived intact
The release also lists a `SHA256SUMS` file, which holds the expected checksum of every installer. Compare it with the
checksum of the file you have. Take `SHA256SUMS` from the release page, not from whoever sent you the installer, or the
comparison proves nothing.

On Windows, in PowerShell:

```powershell
Get-FileHash .\hole-<version>-windows-amd64.msi -Algorithm SHA256
```

On a Mac, in Terminal:

```sh
shasum -a 256 hole-<version>-darwin-arm64.dmg
```

The two checksums must be identical.
````

## Install it

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

1. Double-click the `.msi` file.
2. Windows asks whether to allow the installer to make changes to the device. Choose **Yes**. This is expected: see
   [Why Hole asks for administrator rights](#why-hole-asks-for-administrator-rights).
3. The installer walks through a welcome page, the license, the folder to install into, and which shortcuts to create. A
   Start menu shortcut is on by default and a desktop shortcut is off.
4. When it finishes, Hole opens its {term}`dashboard`.

If you open a terminal later, `hole` is available there: the installer adds its folder to the system `PATH`. Open a new
terminal window after installing, since one that was already open does not see the change.
```

```{tab-item} macOS
:sync: macos

1. Open the `.dmg` file. A window shows the Hole app and the Applications folder with an arrow between them.
2. Drag **Hole** onto **Applications**.
3. Open **Hole** from the Applications folder. macOS warns that Apple could not verify "Hole" is free of malware. This
   is expected: Hole is not notarized by Apple yet. To open it anyway:
   - **macOS 15 or later:** choose **Done**, open **System Settings** → **Privacy & Security**, scroll down and choose
     **Open Anyway** next to Hole.
   - **Earlier macOS:** Control-click Hole and choose **Open**.

   You do this once per Mac.
4. Hole lives in the menu bar; its Dock icon shows only while the dashboard window is open. The first time you connect,
   it asks to install its background helper: see
   [Why Hole asks for administrator rights](#why-hole-asks-for-administrator-rights).
```
````

## Why Hole asks for administrator rights

Hole is one program that runs in two modes. The app you click runs as you. The {term}`bridge` is a background service
with administrator rights, and it is the only part that changes how the computer's network behaves: it creates the
{term}`TUN` device and points the routes at it. Installing a service needs permission once, and that is the only reason
for the prompt.

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

The installer registers the service, which Windows lists as **Hole Bridge**, and starts it. The permission prompt you
saw at the start of the install covers it. After that, switching Hole on and off asks for nothing.
```

```{tab-item} macOS
:sync: macos

The service is installed the first time you connect. Hole shows a dialog titled **Hole — First-Time Setup** that says the
bridge is not installed and offers **Install** or **Later**. Choose **Install**, then enter your Mac's administrator
password when macOS asks. After that, connecting asks for nothing. **Later** leaves Hole unable to connect.

To remove the helper, choose **Uninstall Helper...** from the **Hole** menu.
```
````

```{dropdown} A "Permission Required" dialog
If Hole shows a dialog titled **Hole — Permission Required** that says it needs administrator permissions to enable the
VPN, your account is not yet allowed to talk to the bridge. This happens when a different account did the install. It is
expected, and it is safe to answer.

- **Yes** asks for administrator permission once and gives your account standing access, by adding it to a local group
  named `hole`. Hole does not ask again.
- **No** asks for administrator permission for this one action, and Hole asks again the next time.
```

## Updating

Hole checks GitHub for a new version when it starts and then once a day. When one is found, the {term}`tray` menu gains
an **Install Update** item, and **Help** → **Check for Updates...** in the dashboard checks on demand. Installing an
update restarts the VPN. With the {term}`kill switch` off, your traffic briefly goes out unencrypted during the restart,
so Hole asks you to confirm first. From a terminal, [`hole upgrade`](../reference/cli.md) does the same.

## Next

[Connect](connect.md): import the config and switch Hole on.
