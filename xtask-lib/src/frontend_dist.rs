//! Whether a Tauri build can embed the frontend it is configured to.

use std::path::{Path, PathBuf};

/// The `frontendDist` directory a build must embed but cannot find, if any.
///
/// Tauri embeds the frontend unless the build is a dev build (`dev`) with a
/// `devUrl` (`dev_url`), in which case the webview loads that URL instead; an
/// embedding build panics in `tauri-codegen` when the directory is absent. This
/// is the same decision, asked before that panic so the caller can report it.
/// `frontend_dist` is the config's `build.frontendDist` when it is a string: a
/// URL embeds nothing, and anything else is a directory under `config_dir`.
pub fn missing_frontend_dist(
    dev: bool,
    dev_url: bool,
    frontend_dist: Option<&str>,
    config_dir: &Path,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if dev && dev_url {
        return None;
    }
    let value = frontend_dist?;
    if is_url(value) {
        return None;
    }
    let dir = config_dir.join(value);
    (!exists(&dir)).then_some(dir)
}

/// `scheme://...`, the shape of a URL as opposed to a path (`C:/x` has no `//`).
fn is_url(value: &str) -> bool {
    value.split_once("://").is_some_and(|(scheme, _)| {
        let mut chars = scheme.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}
