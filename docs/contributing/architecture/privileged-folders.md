# Privileged code in folders a user may own

The {term}`bridge` runs as root or SYSTEM, yet some of what it reads and writes sits under the interactive user's
profile: the state directory when the bridge is started by hand, the log directory, the update marker. The user owns every
folder on such a path, so the user can replace any component of it between two calls. This page is the rule set for code
that acts in such a folder, and what keeps the rules from being forgotten. It is for a developer who adds a file the bridge
reads or writes. Read it before adding a call to `std::fs`.

## The threat

A path call (`create_dir_all`, `chown`, `rename`, `remove_file`, `File::create`) resolves the whole path again each time. A
user who swaps a folder for a symlink between two calls sends the next call anywhere the bridge can reach: a `chown` of
`/etc`, a write over a system file, a read of a file the user could not open. Every rule below removes one such step.

{src}`util::dir::Dir <crates/util/src/dir.rs>` implements the rules once. Use it and
do not re-derive them. Its module doc is the reference for the mechanics (`openat` with `O_NOFOLLOW` on Unix, `NtCreateFile`
relative to the parent handle on Windows); this page is the why and the policy.

## The rules

1. **Walk through handles.** Open the directory once, one component at a time, each relative to the handle already held.
   Every later step names a file by one name *inside that handle*.
1. **Give the walk the path as it was given.** Never `canonicalize` or `realpath` a state or log directory first: that
   follows every link with no rule, so a user's link to a folder of root's has become the folder's own name by the time the
   walk judges it. `std::path::absolute` makes a path absolute without following anything.
1. **Follow a link only under the ownership-transition rule** (next section).
1. **Never follow the final name.** A file operation opens its name with `O_NOFOLLOW` (Windows
   `FILE_OPEN_REPARSE_POINT`) and creates with `O_EXCL`. A link at that name is renamed, linked or unlinked as itself and
   never read or written through. A FIFO there is not waited for, and reading anything that is not a regular file is
   refused.
1. **Write only to a file you made, or one the expected owner already owns.** A file kept at a name across runs, the log,
   is opened with `Dir::append_own_file`: created with `O_EXCL`, or an existing file taken only if it is the owner's with no
   other name. Anything else at the name is unlinked and replaced, never written through, and an existing file's owner and
   mode are left alone.
1. **Read through the handle too.** A privileged read of a fixed name is `ReadDir::read_vouched` after the same walk
   (`VersionedFile::observe` does this for a state file). `std::fs::read` opens by path without `O_NONBLOCK`: a FIFO the
   user plants at the name would hang the bridge before it serves, a link to `/dev/zero` is read without end, and a link is
   read as any path the user names. A read by path stays only where the reader is the unprivileged app. Code that only
   reads holds a `ReadDir`, which has no method that writes, renames or removes.
1. **Remove and move aside through the handle.** A state file is removed by `VersionedFile::update` with
   `Change::Remove` and moved aside by `Change::MoveAside` or `Dir::rename_noreplace`, never by `std::fs::remove_file` or
   `rename` on a path. The same holds for the stale socket (`socket::remove`, `util::dir::make_dir_and_free_name`) and the
   installer's SID file in the `hole` folder of `%ProgramData%`, to which a standard user can add names. A socket's bind,
   and the mode or ACL set on it afterwards, still name it by path, because no platform binds relative to a directory
   handle.
1. **Set mode and owner through the open file.** `fchown`, `fchmod` and the Windows ACL go to the handle of a temp file,
   before it is renamed into place (`Dir::write_atomic`, `Dir::stage`).
1. **Never touch a path after a rename.** Once the temp file has its final name the writer does nothing to that name, so a
   name swapped for a hard link or symlink afterwards changes nothing.

## The ownership-transition rule

A link is followed only if the walk never moves from a folder an unprivileged user owns into one somebody else owns. The
rule is systemd's `chase()` with `CHASE_SAFE`, tightened in two places, and it lives in one place,
{src}`crates/util/src/dir/trail.rs` (`Owner::may_enter` and `Trail`), decided on each link and never at a call site.

- **A link is judged by its own owner** as well as by the folder it sits in. A link the system owns (root; on Windows
  SYSTEM, Administrators, TrustedInstaller) is followed in a folder the system owns (macOS's `/var`, `/tmp` and `/etc`,
  hence `temp_dir()`; Windows's `C:\Documents and Settings`), and refused in a user's folder, where it can only be a hard
  link the user planted.
- **A link a user owns binds the walk to that user.** The walk may pass through anyone's folders, since an absolute target
  restarts at the root, but it creates only in folders that user owns and ends only in one. A user's link to their own
  relocated profile is followed. Their link to `/etc` is refused, and so is a link whose target is another user's.

Without the second tightening, a link a user plants in a folder the system owns (`/tmp`) leads anywhere: systemd's own check
lets any step away from a system-owned folder pass and never sees who owns the link.

```{dropdown} Two more properties of the walk
**A bound.** The walk follows at most as many links as the OS follows in one path (`MAX_LINKS`: 40 on Linux, 32 on macOS, 63
reparse points on Windows), which also ends a loop. A user plants the links and each can name the next several times, so
without a bound a chain of forty costs exponential time in a process that runs as root.

**Hand-over.** A folder the walk makes below a user's link is given to that user at once, because a folder the bridge
made is the bridge's on disk and the next walk through the link would refuse it. The user owns the parent, so the name can
be swapped between making the folder and giving it. The hand-over therefore opens the name once (Unix `O_DIRECTORY |
O_NOFOLLOW`), requires the handle to be a directory the bridge itself owns, and gives that handle (`fchown`). On Windows
the owner is set through a handle re-opened for the purpose and compared with the made one, which takes the restore
privilege an elevated token holds.

A folder made on a path with no user's link is left as its maker's, on Windows too. A folder SYSTEM made there is
Administrators-owned, and if a user later puts a link they own above it, the walk refuses it on every start after. Unix
hands the final folder over in `Dir::secure`; Windows has no counterpart (`secure_dir` there does nothing).
```

## Reading a file the user might have planted

`ReadDir::read_vouched` is what a state-file read uses. It refuses (`Refusal::ForeignFile`) a file the folder's owner cannot
vouch for: the file must be owned by the folder's own user, or by the system with at most one link (none, when a rename has
just replaced the open file, since it then has no name left for a user to have planted). A user can hard-link any file the
system can read at a state name, and macOS has no `protected_hardlinks`, so the planted name has two links. The check
stops that and nothing else about ownership: a system-owned file the user *moved* into the folder keeps its owner and its one
link, and is read. What the user could learn from it is limited by the readers, which parse a file as that state's schema
and never echo it: each turns its `serde_json::Error` into a `util::parse_error::ParseFailure` (a category and a position)
where the parse happens, because the error's own text quotes the file.

The rule is for files published by rename, which therefore have one name. `ReadDir::read` skips it and is for a file that has a
second name by design. One exception: a write that fails to publish makes a backup link first, and if taking the backup back
also fails the original has two names, so it reads as `ForeignFile` until the backup is removed
(`take_back_backup` in {src}`crates/util/src/versioned_file/store.rs`). A filesystem with no rename that refuses to
replace fails a claim, and the move-aside of an unreadable record, with an `Unsupported` error naming the file; neither falls
back to a hard link, which would leave the file under two names.

## What keeps the rules in force

Tests plant a hostile layout and check the writer. {src}`crates/bridge/src/dir_writers_tests.rs` holds every writer into a
state directory to two properties. A hard link, symlink or FIFO planted at a name it acts on changes nothing it leads to, and
the writer either takes the name over (or removes it) or refuses it with a typed refusal. A second run in the same layout,
with or without a user's link on the path, succeeds. A source file that opens a `Dir`, calls `make_dir_and_free_name` or
`append_own_file`, or writes a `VersionedFile`, and has no row in the table fails `every_file_that_opens_a_dir_has_a_row`,
so a new writer cannot skip them.

The readers have the same kind of table (`no_reader_reads_through_a_symlink_planted_at_its_name`,
`no_reader_waits_on_a_fifo_planted_at_its_name`, and `state_symlink_tests.rs` in `tun-engine`). A hard link is the file's own
inode, so only `read_vouched`'s ownership and link-count rule tells it from the file: `no_reader_reads_a_hard_link_the_system_would_not_have_made`.
A test cannot make a file the system owns without being the system, so the planted name is refused when the runner is root or an
elevated token and read when it is a user. Logging has its own two: `no_state_reader_logs_a_fragment_of_a_file_it_cannot_parse`
and, for the installer's SID file, `text_that_is_not_a_sid_is_refused_and_never_logged`.

Five source scans close the class. Each reads every use of a function through the file's own `use` and `type` declarations
(`dir_writers_tests/scan.rs`), so a name imported, aliased, globbed or reached through a `type` alias is seen as the function it
stands for, whether it is called or only named as a value.

| Scan                                                 | Forbids                                                                                                                                                                                                                                      |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `no_privileged_code_acts_on_a_file_by_name`          | A by-name change (`chown`, `chmod`, `remove_file`, `rename`, `create_dir`, `File::create`, `OpenOptions::new`, and their Win32 counterparts, from the list `BY_NAME`), except the sites in `BY_NAME_ALLOWED`, each with a count and a reason |
| `no_privileged_state_code_reads_a_file_by_path`      | Opening a file by path in a privileged crate, except `BY_PATH_ALLOWED`                                                                                                                                                                       |
| `no_privileged_code_resolves_a_link_before_the_walk` | `canonicalize` and `realpath`, except `RESOLVING_ALLOWED`                                                                                                                                                                                    |
| `no_state_module_logs_a_path`                        | A state module logging a path: no `.display()` or `.to_string_lossy()`, and no formatting or tracing macro that takes a binding declared as a path                                                                                           |
| `no_privileged_json_parse_keeps_the_raw_error`       | A non-test `serde_json` parse in `bridge`, `tun-engine`, `util` or `common` that does not convert its error before the next parse, except `JSON_PARSE_ALLOWED`                                                                               |

The scans are lexical tripwires over explicit lists, not a proof about every spelling. They do not see a function bound by
anything but `use` and `type` (a macro that expands to a path, a `let` that renames a function), a path through a module of
the same file that re-exports it, or a call with a qualified self. A call the lists do not name is not seen either, so a new
spelling of a by-path call needs a new row. Some rows in `BY_NAME_ALLOWED` are marked "open owner question": they wait for a
decision and are not settled.

A test of a walk plants links with `util::dir::testing` (`plant_link`, `user_dir`, `SystemScratch`), which hand what they make
to an unprivileged owner whoever runs the test. A link to a folder the system owns must be refused, a link to a folder its
own owner owns must be followed, and the same holds through each writer.
