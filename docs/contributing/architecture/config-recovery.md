# Config corruption recovery

The app keeps the user's servers, passwords and settings in `config.json`. This page covers what the app does when that
file cannot be read, and the one rule that keeps a bad read from becoming data loss. It is for a developer who changes how
the config is loaded or saved. The config belongs to the unprivileged app; the bridge's records are a different matter
([crash recovery](crash-recovery.md)).

## One door

`ConfigStore` ({src}`crates/common/src/config_store.rs`) is the only way to load or save `config.json`. `AppConfig::save` is
a disallowed method in {src}`clippy.toml`, so a call outside the store's own `save` does not pass the lint, and there is no
other loader.

## Load

`ConfigStore::load` returns the store, the config and an optional `ConfigRecovery`:

- A missing file is a first launch: defaults, no recovery.
- A file that parses is loaded.
- A file that does not parse, or cannot be read, is *quarantined*: moved to a sibling named
  `config.json.<timestamp>.bak`, where the timestamp is UTC with dashes in place of colons, which Windows file names do not
  allow. A backup that would collide gets `-2`, `-3` and so on before `.bak`. The app then runs on defaults and shows a
  native dialog that names the backup ({src}`crates/hole/src/config_recovery.rs`). A parse error is reduced to its kind,
  line and column, because serde's text can echo the file's content. That reduced error is what `gui.log` and the recovery
  record carry. An I/O error's text is kept as it is.

The quarantine prefers a rename, which keeps the original's permissions (the file holds plaintext passwords). If the rename
fails and the contents were readable, it writes the backup as a new file and removes the original on a best-effort basis; on
Windows a file another process holds open refuses the rename but still allows a new sibling. On Unix the backup is created
with mode `0600`. The probe for a free backup name is not atomic, which is safe only because nothing else creates
`config.json.*.bak` and the single-instance lock makes Hole itself sequential.

## Save

If quarantine failed, for example because the directory is not writable, the corrupt file is still at the config path, and
saving would overwrite it. `ConfigStore` sets `save_blocked` for the whole session, and every `save` returns
`ConfigError::SaveBlocked`. The dialog says that saving is disabled until Hole restarts and tells the user to move or
delete the file. A save that is blocked is the intended failure: a save over a file that failed to parse destroys the
user's servers and passwords.

`AppConfig::save` itself writes atomically: a temp file in the same directory (so the rename stays within one filesystem),
fully written and synced, renamed over the target, then the directory is flushed where the platform allows. A crash in the
middle of a save cannot leave a truncated config. The file is `0600` on Unix.
