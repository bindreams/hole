# Ship blockers and stated limits

Two lists a release operator needs and the code does not show. **Ship blockers** are conditions under which a `hole`
release must not go out. **Stated limits** are shortfalls that ship on purpose, each with the condition that triggers it
and the way out.

## Ship blockers

### The first `hole` release without `NOTICES.md` in its Windows payload

This covers the MSI and the update archive. Every Windows updater from 0.3.0 to 0.7.0 requires that file: 0.3.0 and 0.4.0
update from the `.msi` asset (`msiexec /a`), 0.5.0 to 0.7.0 from the update archive, and each then plans a swap of every
name in the install directory, `NOTICES.md` included.

The release notes of that release must therefore tell Windows users on 0.3.0 to 0.7.0 two things:

- The in-app update fails.
- They update by **running the new MSI over the existing install**. They must not uninstall first.

Two further effects of the failed update are worth knowing when users report it:

- On 0.3.0 to 0.6.0, a retry after the failure is refused until the bridge service next starts (a restart), because the
  planning returns before it clears the update marker. 0.7.0 clears it.
- An uninstall after the failed update leaves the kill switch's block in place. The marker's presence makes the service's
  stop disarm the cover instead of disengaging it ([Uninstall and the service](../architecture/kill-switch-uninstall.md)).
  The way out is [When an uninstall refuses to complete](uninstall-gate.md#getting-the-network-back).

## Stated limits

### A stranded Windows boot-time kill-switch twin

The standing {term}`lockdown` cover's block-all filter pair has a twin flagged `FWPM_FILTER_FLAG_BOOTTIME`, aimed at the
window between the kernel starting and the Base Filtering Engine (BFE) starting ([Windows: filters and the boot
window](../architecture/kill-switch-windows.md)). A stranded persistent filter heals itself: BFE re-adds it at every boot,
so a later build that knows its key can delete it. A stranded boot-time one does not, and a build that never learned its
key cannot delete it by key.

Every release and every unlock runs a sweep that deletes each boot-time filter under Hole's provider that no key list
names ([The provider
sweep](../architecture/kill-switch-windows.md#the-provider-sweep)), so a downgrade through a normal uninstall cannot strand
one. A twin is stranded only by:

1. an uninstall with `LEAVE_NETWORK_BLOCKED=1`, which skips the release and leaves every cover in place
   ([When an uninstall refuses to complete](uninstall-gate.md)); or
1. an upgrade that rolls back after the new bridge engaged the kill switch, when the release rolled back to does not list
   the new release's boot-time keys (0.6.0 to 0.7.0 is the first such pair), followed by a reboot before the rolled-back
   build's next unlock. The sweep reaches a stranger only within the boot it was installed in: a boot-time filter is not
   live after BFE starts, so neither a delete by key nor the enumeration finds it on a later boot. Whether it does is an
   open measurement ([#1043](https://github.com/bindreams/hole/issues/1043)); the reboot strands it.

**Effect.** Egress is blocked from kernel start until BFE starts, on every boot. It is a soft block: the machine boots and
works after that.

**Way out.** Reinstall the release that installed the twin, or a later one (the uninstall gate's report names the running
build's release), turn the kill switch on, then off. After a reboot the stranded twin is not live, so `hole bridge unlock`
or `release-covers` alone delete nothing they can prove: a delete by key answers not-found, and the boot-time enumeration
goes through BFE. Turning the kill switch on is an engage, which deletes and re-adds the fixed keys of the twins that
build lists (which is why an older build cannot clear a newer release's twin), so the twin is live on this boot. Turning
it off then deletes a live twin, a removal the sweep watched. That an engage's re-add replaces a stranded boot-time record,
and that a delete by key purges the record so the block is gone on the next boot, are both the unmeasured assumption of
#1043; nothing in CI reboots.

**Forward rule.** A boot-time key a release ships stays in the sweep list of every later build, so a downgrade from any
later release can still delete it by key. The enumeration is the backstop for a key an older build never learned, not a
replacement for the list. Adding a boot-time key needs no edit to the uninstall gate's remedy: it names the running
build's release, whose list names the key.
