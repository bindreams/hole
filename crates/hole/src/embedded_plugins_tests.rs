use super::*;
use sha2::{Digest, Sha256};

#[skuld::test]
fn the_embedded_names_are_the_plugins_macos_embeds() {
    let names: Vec<&str> = PLUGINS.iter().map(|p| p.name).collect();

    assert_eq!(
        names,
        xtask_lib::bindir::embedded_plugin_names(xtask_lib::bindir::Os::Darwin)
    );
}

#[skuld::test]
fn every_embedded_hash_is_the_hash_of_its_bytes() {
    for plugin in PLUGINS {
        let digest: [u8; 32] = Sha256::digest(plugin.bytes).into();

        assert_eq!(plugin.sha256, digest, "{}", plugin.name);
    }
}

/// `cargo xtask deps` has run, so the build carries real payloads. Fails on a stub build: a release must never
/// embed empty plugins, and the DMG tests compare the bytes with `.cache` too. Set `HOLE_ALLOW_STUB_PLUGINS=1` to
/// run the other tests against stubs.
#[skuld::test]
fn the_embedded_plugins_are_not_stubs() {
    if std::env::var_os("HOLE_ALLOW_STUB_PLUGINS").is_some() {
        return;
    }
    for plugin in PLUGINS {
        assert!(
            !plugin.bytes.is_empty(),
            "{} is an empty stub: run `cargo xtask deps` (or set HOLE_ALLOW_STUB_PLUGINS=1)",
            plugin.name
        );
    }
}
