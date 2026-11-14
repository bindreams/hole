# When an uninstall refuses to complete

On Windows the MSI's `BridgeRelease` custom action releases every fail-closed {term}`cover` and turns the {term}`kill switch` off before the uninstaller deletes `hole.exe`. It is the one uninstall action whose failure aborts the uninstall
(`Return="check"`), because the kill switch's filters are persistent: leaving them behind would be a host blocked on every
boot with no binary left to remove them. [Uninstall and the service](../architecture/kill-switch-uninstall.md) has the
mechanism. This page is for the person whose uninstall stopped there.

An uninstall that aborts at `BridgeRelease` is the gate working. Fix the cause first. The release talks to the Base
Filtering Engine through `hole.exe`, so it fails when either is out of reach:

1. **The Base Filtering Engine service is not running.** Check with `sc query BFE`, start it and retry.
1. **`hole.exe` was quarantined by antivirus**, so the custom action could not launch it. Restore it and retry.

## Forcing the uninstall

If the release can never succeed, force the uninstall past the gate:

```text
msiexec /x hole.msi LEAVE_NETWORK_BLOCKED=1
```

```{danger}
This can leave the host blocked. `LEAVE_NETWORK_BLOCKED=1` skips the release entirely: every cover in place stays (the
kill switch's firewall rules and, if one was engaged, the transient startup cover), and the target is not recorded off.
If a cover was engaged, the network stays blocked.
```

Use it only after the release has been tried and cannot succeed. If a boot-time filter may be involved, reinstall the
release named in [the stated limit](ship-blockers.md#a-stranded-windows-boot-time-kill-switch-twin) first: an older build
cannot delete a boot-time key it was never taught.

## Getting the network back

Reinstalling Hole alone does not clear a cover, because the new bridge adopts a live one. After the reinstall, release it
from the running bridge or from the command line:

- **From the app.** Untick **Lockdown**, or choose **Unblock Network** in the tray. Either releases every cover
  ({term}`Unblock Network`; rows T11 and T12 of the [transitions](../architecture/kill-switch.md#transitions)).
- **From the command line.** `hole bridge release-covers`, run elevated, releases every cover, but it refuses while the
  reinstalled service is running ([#1289](https://github.com/bindreams/hole/issues/1289)). Stop the service first, with
  `Stop-Service -Name HoleBridge -Force` in an elevated PowerShell.
- **Boot-time twins** need the release that installed them: see [the stated
  limit](ship-blockers.md#a-stranded-windows-boot-time-kill-switch-twin).

Nothing shipped with Windows can undo a cover. `netsh wfp` is diagnostics-only: its verbs are `capture`, `dump`, `help`,
`set` and `show`, and none deletes a filter ([Microsoft's
reference](https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wfp)). `netsh wfp show filters`
shows Hole's persistent provider but cannot remove it. For the boot-time twins use `netsh wfp show boottimepolicy`: `show filters` lists what is active now, which by definition excludes a boot-time filter once BFE has started, that is, at every
moment you can run the command. Removing a filter takes an FWPM call, and `hole.exe` is the only caller of one on the host.
