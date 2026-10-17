use std::path::{Path, PathBuf};

use crate::frontend_dist::missing_frontend_dist;

const CONFIG_DIR: &str = "/repo/crates/hole";

fn missing(dev: bool, dev_url: bool, frontend_dist: Option<&str>, present: &[&str]) -> Option<PathBuf> {
    missing_frontend_dist(dev, dev_url, frontend_dist, Path::new(CONFIG_DIR), |dir| {
        present.iter().any(|p| Path::new(p) == dir)
    })
}

#[skuld::test]
fn a_production_build_names_the_directory_it_cannot_find() {
    for dev_url in [false, true] {
        assert_eq!(
            missing(false, dev_url, Some("../../ui/dist"), &[]),
            Some(PathBuf::from("/repo/crates/hole/../../ui/dist")),
            "dev_url={dev_url}"
        );
    }
}

#[skuld::test]
fn a_production_build_with_the_directory_present_is_fine() {
    assert_eq!(
        missing(false, true, Some("../../ui/dist"), &["/repo/crates/hole/../../ui/dist"]),
        None
    );
}

#[skuld::test]
fn a_dev_build_with_a_dev_url_does_not_embed_the_directory() {
    assert_eq!(missing(true, true, Some("../../ui/dist"), &[]), None);
}

#[skuld::test]
fn a_dev_build_without_a_dev_url_still_embeds_the_directory() {
    assert_eq!(
        missing(true, false, Some("../../ui/dist"), &[]),
        Some(PathBuf::from("/repo/crates/hole/../../ui/dist"))
    );
}

#[skuld::test]
fn no_frontend_dist_embeds_nothing() {
    assert_eq!(missing(false, false, None, &[]), None);
}

#[skuld::test]
fn a_url_frontend_dist_embeds_nothing() {
    for url in [
        "https://app.test/index.html",
        "http://localhost:1420",
        "custom+scheme://x",
    ] {
        assert_eq!(missing(false, false, Some(url), &[]), None, "{url}");
    }
}

#[skuld::test]
fn a_path_that_only_looks_like_a_url_is_a_directory() {
    for path in ["C:/ui/dist", "../ui://dist", "1x://dist", "://dist"] {
        assert!(missing(false, false, Some(path), &[]).is_some(), "{path}");
    }
}
