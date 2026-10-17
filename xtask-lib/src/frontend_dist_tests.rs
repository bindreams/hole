use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::frontend_dist::missing_frontend_dist;

const CONFIG_DIR: &str = "/repo/crates/hole";

/// The config file's `build` section, as `tauri.conf.json` would carry it.
fn conf(build: Value) -> Value {
    json!({ "identifier": "test.app", "build": build })
}

fn check(dev: bool, base: Value, tauri_config: Option<&str>, present: &[&str]) -> anyhow::Result<Option<PathBuf>> {
    missing_frontend_dist(dev, base, tauri_config, Path::new(CONFIG_DIR), |dir| {
        present.iter().any(|p| Path::new(p) == dir)
    })
}

fn missing(dev: bool, build: Value, present: &[&str]) -> Option<PathBuf> {
    check(dev, conf(build), None, present).expect("config is valid")
}

#[skuld::test]
fn a_production_build_names_the_directory_it_cannot_find() {
    for dev_url in [None, Some("http://localhost:1420")] {
        assert_eq!(
            missing(
                false,
                json!({ "frontendDist": "../../ui/dist", "devUrl": dev_url }),
                &[]
            ),
            Some(PathBuf::from("/repo/ui/dist")),
            "dev_url={dev_url:?}"
        );
    }
}

#[skuld::test]
fn a_production_build_with_the_directory_present_is_fine() {
    assert_eq!(
        missing(
            false,
            json!({ "frontendDist": "../../ui/dist", "devUrl": "http://localhost:1420" }),
            &["/repo/crates/hole/../../ui/dist"]
        ),
        None
    );
}

#[skuld::test]
fn a_dev_build_with_a_dev_url_does_not_embed_the_directory() {
    assert_eq!(
        missing(
            true,
            json!({ "frontendDist": "../../ui/dist", "devUrl": "http://localhost:1420" }),
            &[]
        ),
        None
    );
}

#[skuld::test]
fn a_dev_build_without_a_dev_url_still_embeds_the_directory() {
    assert_eq!(
        missing(true, json!({ "frontendDist": "../../ui/dist" }), &[]),
        Some(PathBuf::from("/repo/ui/dist"))
    );
}

#[skuld::test]
fn no_frontend_dist_embeds_nothing() {
    assert_eq!(missing(false, json!({}), &[]), None);
}

#[skuld::test]
fn a_file_list_is_left_to_tauri() {
    assert_eq!(missing(false, json!({ "frontendDist": ["a.html", "b.js"] }), &[]), None);
}

/// Every string `url::Url::parse` accepts is a `FrontendDist::Url` to tauri,
/// which embeds nothing for it. `C:/ui/dist` is one: its scheme is `c`.
#[skuld::test]
fn what_tauri_parses_as_a_url_embeds_nothing() {
    for url in [
        "https://app.test/index.html",
        "http://localhost:1420",
        "custom+scheme://x",
        "C:/ui/dist",
        "C:\\ui\\dist",
        "c:dist",
        "dist:x",
    ] {
        assert_eq!(missing(false, json!({ "frontendDist": url }), &[]), None, "{url}");
    }
}

#[skuld::test]
fn what_tauri_does_not_parse_as_a_url_is_a_directory() {
    for path in [
        "../ui://dist",
        "1x://dist",
        "://dist",
        "dist",
        "/abs/dist",
        "../../ui/dist",
    ] {
        assert!(missing(false, json!({ "frontendDist": path }), &[]).is_some(), "{path}");
    }
}

#[skuld::test]
fn tauri_config_can_point_frontend_dist_at_an_existing_directory() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    let alt = r#"{"build":{"frontendDist":"../../.tmp/dist-alt"}}"#;
    assert_eq!(
        check(false, base, Some(alt), &["/repo/crates/hole/../../.tmp/dist-alt"]).unwrap(),
        None
    );
}

#[skuld::test]
fn tauri_config_can_point_frontend_dist_at_a_missing_directory() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    let alt = r#"{"build":{"frontendDist":"../../.tmp/dist-alt"}}"#;
    assert_eq!(
        check(false, base, Some(alt), &["/repo/crates/hole/../../ui/dist"]).unwrap(),
        Some(PathBuf::from("/repo/.tmp/dist-alt"))
    );
}

#[skuld::test]
fn tauri_config_can_point_frontend_dist_at_a_url() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    let alt = r#"{"build":{"frontendDist":"https://app.test"}}"#;
    assert_eq!(check(false, base, Some(alt), &[]).unwrap(), None);
}

#[skuld::test]
fn tauri_config_null_removes_frontend_dist() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    assert_eq!(
        check(false, base, Some(r#"{"build":{"frontendDist":null}}"#), &[]).unwrap(),
        None
    );
}

#[skuld::test]
fn tauri_config_can_supply_the_dev_url_a_dev_build_loads() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    let patch = r#"{"build":{"devUrl":"http://localhost:1420"}}"#;
    assert_eq!(check(true, base.clone(), Some(patch), &[]).unwrap(), None);
    assert!(check(false, base, Some(patch), &[]).unwrap().is_some());
}

#[skuld::test]
fn a_malformed_tauri_config_is_an_error() {
    let base = conf(json!({ "frontendDist": "../../ui/dist" }));
    assert!(check(false, base, Some("{not json"), &[]).is_err());
}

#[skuld::test]
fn a_config_tauri_would_reject_is_an_error() {
    assert!(check(false, json!({ "identifier": 7 }), None, &[]).is_err());
}

#[skuld::test]
fn existence_is_asked_of_the_path_tauri_checks() {
    let asked = std::cell::RefCell::new(Vec::new());
    let found = missing_frontend_dist(
        false,
        conf(json!({ "frontendDist": "../../ui/dist" })),
        None,
        Path::new(CONFIG_DIR),
        |dir| {
            asked.borrow_mut().push(dir.to_path_buf());
            true
        },
    )
    .unwrap();
    assert_eq!(found, None);
    assert_eq!(
        asked.into_inner(),
        vec![PathBuf::from("/repo/crates/hole/../../ui/dist")]
    );
}
