# File lock and state files

Two things in the {term}`bridge` live in a {term}`state directory` that the interactive user may own: a lock that says a
bridge is running, and the files that hold state across a restart. Both are written by a privileged process into a folder
an unprivileged user can tamper with, so both follow [the rules for privileged code in such
folders](privileged-folders.md). This page covers how the lock and the state-file writers apply them. It is for a developer
who adds a cross-process lock or a new state file.

## Cross-process locks

A lock on a file goes through `file_lock::Exclusive` ({src}`crates/file-lock/src/exclusive.rs`: `flock` on Unix,
`LockFileEx` on Windows), not a second implementation. The bridge's liveness lock, `bridge-liveness.lock` in the state
directory, is built on it ({src}`crates/bridge/src/liveness.rs`). It is held for the bridge's whole run, and `hole bridge unlock` takes it to refuse to run against a live bridge. A state file takes no lock file of its own.

Whatever is at the lock's name is chosen by an attacker, and the name can change between any two calls that take it.
`Exclusive` therefore decides on what an attacker cannot change once the file is open. The protocol, in the module doc:

1. Create the file with `O_CREAT | O_EXCL` (Windows `CREATE_NEW`). A file it creates is its own.
1. If the name exists, reopen it without creating. A symlink (Windows: any reparse point), directory, socket or other
   non-regular file is refused.
1. On Unix with an `owner`, an existing file's uid must be the owner's, exactly. A file owned by *this process* is not used:
   it is locked, its *name* is unlinked and a fresh file is created. That recovers the file a previous run made and died
   before handing over (refusing it would lock the owner out), and it is also what happens to an unrelated file this process
   owns that was hard-linked at the name, because the unlink touches only the name. A file owned by anyone else is refused.
1. `fchmod` and `fchown` are applied only to a file this call created, or one the owner owns that has a single name. A file
   with another name is locked and used as it is.
1. Once locked, the name must still name the open file (device and inode); if the previous holder unlinked it, start over.

So whatever an attacker does to the name, before or after the open, nothing but a file this call created, or a
single-named file the owner owns, is re-permissioned. Windows opens without `FILE_SHARE_DELETE`, so while the lock is held
the name can be neither removed nor renamed.

The directory above the lock is as attacker-writable as the name. `Exclusive` opens it first as a `Dir`, one component at a
time, and every later step on the lock file goes through that handle; see [the walk and the ownership-transition
rule](privileged-folders.md#the-ownership-transition-rule). With an `owner`, the final directory must be owned by it or by
this process. Windows has no unix ids and does not check. Missing directories above the file are created relative to their
parent's handle, never by `create_dir_all` on a path.

### What is refused

A symlink (on Windows, any reparse point), directory, socket or other non-regular file at the name, a file owned by a third
party, or a directory in the path that `Dir` refuses, is **refused**: an `InvalidData` error holding a `file_lock::Refused`.
A second name for the lock file is not refused, because the count can change after it is read.

`Refused` carries no path in its `Display` or `Debug`: the lock sits in a user's profile, and a log line must not hold the
user's name. It has no `source()`, so logging the error as `error = &e as &dyn std::error::Error` renders one link,
`refusing to lock: <reason>`, where the reason is a fixed sentence or a uid. `Refused::path()` is the one way out, for a
caller that chooses a sink that may hold a path (`gui.log`) and never the bridge log or the support bundle.

## State files

Every file the bridge reads back across a restart is a `util::versioned_file::VersionedFile`
({src}`crates/util/src/versioned_file.rs`). Each is one flat JSON object, `{"version": N, ...}`, where every version of the
payload is its own frozen type linked to the one before. The files are `bridge-routes.json`, `bridge-target.json`,
`bridge-startup.json`, `bridge-plugins.json`, `bridge-dns.json`, the plugin folder's `layout.json`, the update marker
`update-in-progress.json`, and the cover's `bridge-failclosed.json`, `bridge-lockdown.json`, `bridge-lockdown-pf.json` and
`bridge-boottime.json`. The module doc is the reference for adding a version.

The type's three calls, `observe`, `update` and `create_new`, open the directory as a `Dir` and do every step inside that
handle:

- the read, through `ReadDir::read_vouched`;
- the staged temp file, sealed through its own handle (owner, mode and ACL set before the rename);
- the backup hard link, the no-clobber rename, the replace and the directory flush.

Nothing touches the final name after the rename, so a name swapped for a hard link or symlink after it changes nothing. A
symlink at the file's own name is never read through: it is a file this release cannot read, and the file's role decides
what happens to it ([crash recovery](crash-recovery.md#records-that-cannot-be-read)).
`the_state_file_writers_never_chown_chmod_or_rename_by_path` keeps the writers on the handle. The log directory
(`hole_common::logging::init_dual` with `DirRotate`) is written through the same `Dir`.

Three more properties follow from the contract:

- **A write that reached the rename is complete.** A failure of the directory flush after it is logged at warn and the call
  is `Ok`, because the caller acts on what is on disk.
- **Readers ignore unknown fields.** No schema declares `deny_unknown_fields`, and the version number is the only
  compatibility signal. A change an older reader would act wrongly on needs a version bump; adding an optional field does
  not.
- **An error names the file, never its directory** (`StoreError::Unreadable`, `ReadFailed`).

Exclusion is in two parts. `observe` and `update` take an in-process lock keyed by the file's path, so two threads never
interleave a read with the write that depends on it. It does not exclude another process; for the bridge's state files that
is the liveness lock above, held by the running bridge and by every command that writes state. `create_new` takes no lock,
since the rename that publishes the file refuses to replace and is atomic across processes. The cover has a separate lock
for its own changes ([the cover lock](kill-switch-recovery.md#the-cover-lock)).
