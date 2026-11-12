//! Install directories (a fake bridge exe with plugin binaries beside it) for
//! tests that resolve through `PluginLookup`.
//!
//! Shared into integration targets by `#[path]` (`test_support` is a private
//! module).

use std::env::consts::EXE_SUFFIX;
use std::path::{Path, PathBuf};

/// The file `binary` takes beside `exe` (platform extension added).
pub(crate) fn sibling_path(exe: &Path, binary: &str) -> PathBuf {
    exe.with_file_name(format!("{binary}{EXE_SUFFIX}"))
}

/// A fresh install directory inside `parent` holding only a fake bridge
/// executable; returns that executable. `parent` must outlive every start, since
/// each one resolves again.
pub(crate) fn empty_install(parent: &Path) -> PathBuf {
    let install = parent.join("install");
    std::fs::create_dir(&install).unwrap();
    let exe = install.join(format!("hole{EXE_SUFFIX}"));
    std::fs::write(&exe, b"fake").unwrap();
    exe
}

/// An install whose `ex-ray` is whatever `write_ex_ray` puts at the path it is
/// given; returns its bridge exe.
pub(crate) fn install_with_ex_ray(parent: &Path, write_ex_ray: impl FnOnce(&Path)) -> PathBuf {
    let exe = empty_install(parent);
    write_ex_ray(&sibling_path(&exe, "ex-ray"));
    exe
}

/// An install whose `ex-ray` resolves but cannot run.
pub(crate) fn fake_install_with_unspawnable_ex_ray(parent: &Path) -> PathBuf {
    install_with_ex_ray(parent, |dest| std::fs::write(dest, b"not a program").unwrap())
}

/// An install whose `ex-ray` is a copy of the built one at `built`.
pub(crate) fn install_with_built_ex_ray(parent: &Path, built: &Path) -> PathBuf {
    install_with_ex_ray(parent, |dest| {
        std::fs::copy(built, dest).unwrap();
    })
}
