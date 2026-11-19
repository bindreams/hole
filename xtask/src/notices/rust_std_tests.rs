use std::path::Path;

use super::rust_std::{doc_dir, release_of, taken, toolchain, Toolchain};
use super::{render, Component, NoticesError, Origin};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// The text of the notices file with the standard library's section alone in it.
fn section_of(doc_dir: &Path) -> Result<String, NoticesError> {
    let component = Component {
        name: "Rust standard library".to_owned(),
        version: "1.98.0".to_owned(),
        origin: Origin::Declared,
        license: Some("MIT OR Apache-2.0".to_owned()),
        source_dir: None,
        url: Some("https://github.com/rust-lang/rust".to_owned()),
        modified_copy: false,
        replaces: None,
        text_dir: Some(doc_dir.to_owned()),
    };
    Ok(render::render(
        "0.0.0",
        &[(component, taken(doc_dir, "Apache-2.0".to_owned())?)],
    ))
}

#[skuld::test]
fn the_standard_librarys_section_carries_every_package_and_every_text_of_the_toolchains_file() {
    let dir = doc_dir(&toolchain(repo_root()).unwrap().sysroot);
    let html = std::fs::read_to_string(dir.join("COPYRIGHT-library.html")).unwrap();
    let output = section_of(&dir).unwrap();

    // What the file holds, read by a parser of its own: every package heading and every preformatted licence text.
    let doc = dom_query::Document::from(html.as_str());
    let packages: Vec<String> = doc.select("h3").iter().map(|h| h.text().trim().to_owned()).collect();
    let texts: Vec<String> = doc.select("pre").iter().map(|p| p.text().trim().to_owned()).collect();
    assert_eq!(
        packages.len(),
        html.matches("<h3").count(),
        "the parser lost a package heading"
    );
    assert_eq!(texts.len(), html.matches("<pre").count(), "the parser lost a text");
    assert!(!packages.is_empty() && !texts.is_empty());

    let missing_packages: Vec<&String> = packages.iter().filter(|name| !output.contains(name.as_str())).collect();
    let missing_texts = texts.iter().filter(|text| !output.contains(text.as_str())).count();
    let note = output
        .find("names more than is linked")
        .expect("the section says it names more than is linked");
    assert!(
        note < output.find(&packages[0]).unwrap(),
        "the sentence is not at the head of the section"
    );
    assert!(
        missing_packages.is_empty(),
        "packages missing from the output: {missing_packages:?}"
    );
    assert_eq!(
        missing_texts,
        0,
        "of {} texts, {missing_texts} are missing from the output",
        texts.len()
    );
}

#[skuld::test]
fn a_toolchain_without_its_copyright_file_fails_naming_the_path() {
    let sysroot = tempfile::tempdir().unwrap();
    let dir = doc_dir(sysroot.path());
    std::fs::create_dir_all(&dir).unwrap();

    let err = section_of(&dir).unwrap_err();

    assert!(matches!(err, NoticesError::Io { .. }), "{err:?}");
    let expected = dir.join("COPYRIGHT-library.html");
    assert!(err.to_string().contains(&*expected.to_string_lossy()), "{err}");
}

/// A toolchain folder whose copyright file names `Unicode-3.0` for one in-tree file and carries one package text, and
/// whose `licenses/` holds that licence and one the file does not name.
fn toolchain_naming_unicode() -> tempfile::TempDir {
    let sysroot = tempfile::tempdir().unwrap();
    let dir = doc_dir(sysroot.path());
    std::fs::create_dir_all(dir.join("licenses")).unwrap();
    std::fs::write(
        dir.join("COPYRIGHT-library.html"),
        "<html><body>\n<h2>In-tree files</h2>\n<div><p><b>License:</b> Unicode-3.0</p></div>\n\
         <h2>Out-of-tree</h2>\n<h3>pkg-1.0.0</h3>\n<pre>\nCopyright &#60;a&#62; &amp; &#34;b&#34;\n</pre>\n</body></html>\n",
    )
    .unwrap();
    std::fs::write(dir.join("licenses/Unicode-3.0.txt"), "UNICODE TEXT\n").unwrap();
    std::fs::write(dir.join("licenses/GPL-2.0-only.txt"), "GPL TEXT\n").unwrap();
    sysroot
}

#[skuld::test]
fn a_licence_the_file_names_only_by_identifier_takes_its_text_from_the_toolchain() {
    let sysroot = toolchain_naming_unicode();
    let output = section_of(&doc_dir(sysroot.path())).unwrap();

    assert!(output.contains("UNICODE TEXT"), "{output}");
    assert!(
        !output.contains("GPL TEXT"),
        "a licence the file does not name is printed:\n{output}"
    );
}

#[skuld::test]
fn the_entities_of_a_text_decode_exactly() {
    let sysroot = toolchain_naming_unicode();
    let output = section_of(&doc_dir(sysroot.path())).unwrap();

    assert!(output.contains("Copyright <a> & \"b\""), "{output}");
}

#[skuld::test]
fn a_licence_the_file_names_without_a_text_in_the_toolchain_fails_naming_the_path() {
    let sysroot = toolchain_naming_unicode();
    let dir = doc_dir(sysroot.path());
    std::fs::remove_file(dir.join("licenses/Unicode-3.0.txt")).unwrap();

    let err = section_of(&dir).unwrap_err();

    assert!(err.to_string().contains("Unicode-3.0.txt"), "{err}");
}

#[skuld::test]
fn a_copyright_file_whose_in_tree_licences_cannot_be_found_fails_naming_the_file() {
    let sysroot = tempfile::tempdir().unwrap();
    let dir = doc_dir(sysroot.path());
    std::fs::create_dir_all(dir.join("licenses")).unwrap();
    // The structure the generator reads (a `License:` paragraph in a top-level `div`) is not there.
    std::fs::write(
        dir.join("COPYRIGHT-library.html"),
        "<html><body><section><span>License: Unicode-3.0</span></section>\n<h3>pkg-1.0.0</h3>\n<pre>\ntext\n</pre></body></html>\n",
    )
    .unwrap();

    let err = section_of(&dir).unwrap_err();

    assert!(matches!(err, NoticesError::Tool { .. }), "{err:?}");
    assert!(err.to_string().contains("COPYRIGHT-library.html"), "{err}");
}

#[skuld::test]
fn the_toolchain_read_is_the_one_rust_toolchain_pins() {
    let pinned: toml::Table = std::fs::read_to_string(repo_root().join("rust-toolchain.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let channel = pinned["toolchain"]["channel"].as_str().unwrap();

    let found = toolchain(repo_root()).unwrap();

    assert_eq!(found.version, channel);
    found.require_pinned(channel).unwrap();
}

#[skuld::test]
fn a_toolchain_that_is_not_the_pinned_one_fails_naming_both_versions_and_its_folder() {
    let found = Toolchain {
        sysroot: "/somewhere/nightly".into(),
        version: "1.99.0-nightly".to_owned(),
    };

    let err = found.require_pinned("1.98.0").unwrap_err();

    assert!(matches!(err, NoticesError::Tool { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains("1.99.0-nightly") && message.contains("1.98.0") && message.contains("nightly"),
        "{message}"
    );
}

#[skuld::test]
fn the_version_is_the_release_line_of_rustc_vv() {
    let printed = "rustc 1.98.0 (88d9e12ae 2026-08-18)\nbinary: rustc\nhost: x86_64-pc-windows-msvc\nrelease: 1.98.0\nLLVM version: 22.1.8\n";
    assert_eq!(release_of(printed).unwrap(), "1.98.0");
    assert!(release_of("rustc 1.98.0\n").is_err());
}

#[skuld::test]
fn the_files_title_is_printed_once() {
    let sysroot = toolchain_naming_unicode();
    let dir = doc_dir(sysroot.path());
    // The head's `<title>` repeats the body's `<h1>`.
    std::fs::write(
        dir.join("COPYRIGHT-library.html"),
        "<html><head><title>Notices for the library</title></head><body>\n<h1>Notices for the library</h1>\n\
         <div><p><b>License:</b> Unicode-3.0</p></div>\n<h3>pkg-1.0.0</h3>\n<pre>\ntext\n</pre>\n</body></html>\n",
    )
    .unwrap();

    let output = section_of(&dir).unwrap();

    assert_eq!(output.matches("Notices for the library").count(), 1, "{output}");
}

#[skuld::test]
fn the_converted_file_carries_no_blank_lines_around_its_text() {
    let sysroot = toolchain_naming_unicode();
    let dir = doc_dir(sysroot.path());

    let taken = taken(&dir, "Apache-2.0".to_owned()).unwrap();

    let body = &taken.texts[0].body;
    assert!(
        !body.ends_with('\n') && !body.starts_with('\n'),
        "blank lines around the converted file: {body:?}"
    );
}
