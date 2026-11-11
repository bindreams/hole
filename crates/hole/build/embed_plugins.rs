//! Embeds the plugin binaries macOS carries inside `hole` instead of beside it (`xtask_lib::bindir::embedded_plugin_names`).
//!
//! The service writes them to a root-owned folder at every start (`hole_bridge::plugin_repair`), so the app bundle
//! does not ship them. This script reads each from `.cache/<name>/<name>-<triple>` (what `cargo xtask deps` builds),
//! hashes it, copies the same bytes to `$OUT_DIR/<name>`, and writes `$OUT_DIR/embedded_plugins.rs`, which
//! `src/embedded_plugins.rs` includes. The hash and the embedded bytes both come from that one read.
//!
//! A missing input is stubbed empty, as `tauri-build`'s sidecars are, so a dev or test build compiles without
//! `cargo xtask deps`; an empty payload means "this build carries none" and repair never converges toward it.
//! A release build refuses an empty payload: it would ship a bridge that can never vouch for its plugin folder.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{create_dated, mtime};

/// Writes the generated file for a macOS target; does nothing for another.
pub fn embed(repo_root: &Path) {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let out = out_dir.join("embedded_plugins.rs");
    let names = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        xtask_lib::bindir::embedded_plugin_names(xtask_lib::bindir::Os::Darwin)
    } else {
        &[]
    };
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    let mut generated = String::from("pub static PLUGINS: &[EmbeddedPlugin] = &[\n");
    for name in names {
        let path = xtask_lib::bindir::cache_sidecar_path(repo_root, name, &target, false);
        std::fs::create_dir_all(path.parent().expect("a sidecar path has a parent"))
            .expect("failed to create sidecar cache dir");
        if create_dated(&path, &[], mtime(Path::new("tauri.conf.json"))) {
            println!("cargo:warning=created empty {name} stub — run `cargo xtask deps` for a real build");
        }
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert!(
            !(bytes.is_empty() && std::env::var("PROFILE").as_deref() == Ok("release")),
            "{} is empty: a release build must carry the {name} plugin; run `cargo xtask deps`",
            path.display()
        );
        let copy = out_dir.join(name);
        std::fs::write(&copy, &bytes).unwrap_or_else(|e| panic!("failed to write {}: {e}", copy.display()));
        let hash = Sha256::digest(&bytes);
        let mut hash_bytes = String::new();
        for byte in hash {
            write!(hash_bytes, "{byte}, ").expect("writing to a String cannot fail");
        }
        writeln!(
            generated,
            "    EmbeddedPlugin {{ name: {name:?}, bytes: include_bytes!({copy:?}), sha256: [{hash_bytes}] }},",
            copy = copy.to_string_lossy(),
        )
        .expect("writing to a String cannot fail");
    }
    generated.push_str("];\n");
    std::fs::write(&out, generated).unwrap_or_else(|e| panic!("failed to write {}: {e}", out.display()));
}
