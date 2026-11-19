use super::take::{LicenseText, Taken, TextKind};
use super::{Component, Origin};

fn component(name: &str, version: &str, url: Option<&str>) -> Component {
    Component {
        name: name.to_owned(),
        version: version.to_owned(),
        origin: Origin::Crate,
        license: None,
        source_dir: None,
        url: url.map(str::to_owned),
        modified_copy: false,
        replaces: None,
        text_dir: None,
    }
}

fn render(hole_version: &str, taken: &[(Component, Taken)]) -> String {
    super::render::render(hole_version, taken)
}

fn shared(license: &str, body: &str) -> LicenseText {
    LicenseText {
        title: license.to_owned(),
        body: body.to_owned(),
        kind: TextKind::Shared,
        source: None,
    }
}

fn own(title: &str, body: &str) -> LicenseText {
    LicenseText {
        title: title.to_owned(),
        body: body.to_owned(),
        kind: TextKind::Own,
        source: None,
    }
}

fn taken(license: &str, texts: Vec<LicenseText>) -> Taken {
    Taken {
        license: license.to_owned(),
        texts,
        note: None,
    }
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[skuld::test]
fn the_file_opens_with_holes_own_statement_and_source_url() {
    let out = render("0.7.1", &[]);
    assert!(out.starts_with("# "), "{out}");
    let source = "https://github.com/bindreams/hole/tree/releases/hole/v0.7.1";
    let statement = out.find("GPL-3.0-or-later").expect("the statement names the licence");
    let url = out
        .find(source)
        .expect("the statement links the source of this release");
    let gpl = out
        .find(spdx::license_id("GPL-3.0-or-later").unwrap().text())
        .expect("the GPL text is printed");
    let third_party = out.find("## Third-party software").expect("the third-party section");
    assert!(
        statement < url && url < gpl && gpl < third_party,
        "order: {statement} {url} {gpl} {third_party}"
    );
}

#[skuld::test]
fn a_shared_text_is_printed_once_with_its_components_listed() {
    let apache = spdx::license_id("Apache-2.0").unwrap().text();
    let components = [
        (
            component("alpha", "1.0.0", Some("https://crates.io/crates/alpha/1.0.0")),
            taken("Apache-2.0", vec![shared("Apache-2.0", apache)]),
        ),
        (
            component("beta", "2.0.0", None),
            taken("Apache-2.0", vec![shared("Apache-2.0", apache)]),
        ),
    ];
    let out = render("0.7.1", &components);
    assert_eq!(count(&out, apache), 1, "the text once");
    assert!(
        out.contains("- alpha 1.0.0 (https://crates.io/crates/alpha/1.0.0)"),
        "{out}"
    );
    assert!(out.contains("- beta 2.0.0\n"), "{out}");
}

#[skuld::test]
fn identical_holder_texts_are_merged_and_different_ones_are_not() {
    let microsoft = "MIT License\n\nCopyright (c) Microsoft Corporation.\n\nPermission is hereby granted";
    let jane = "MIT License\n\nCopyright (c) 2020 Jane Widget\n\nPermission is hereby granted";
    let components = [
        (
            component("windows-sys", "0.61.2", None),
            taken("MIT", vec![own("LICENSE-MIT", microsoft)]),
        ),
        (
            component("windows-core", "0.62.0", None),
            taken("MIT", vec![own("LICENSE", microsoft)]),
        ),
        (
            component("widget", "1.0.0", None),
            taken("MIT", vec![own("LICENSE", jane)]),
        ),
    ];
    let out = render("0.7.1", &components);
    assert_eq!(count(&out, microsoft), 1, "identical texts are printed once:\n{out}");
    assert_eq!(count(&out, jane), 1);
    assert_eq!(count(&out, "Copyright (c) Microsoft Corporation."), 1);
    // Both components of the merged text are listed in its group, and the other one is not.
    let at = out.find(microsoft).unwrap();
    let group = &out[out[..at].rfind("#### ").unwrap()..at];
    assert!(
        group.contains("- windows-core 0.62.0") && group.contains("- windows-sys 0.61.2"),
        "{group}"
    );
    assert!(
        !group.contains("widget"),
        "the different text is its own entry: {group}"
    );
}

#[skuld::test]
fn a_component_with_several_files_keeps_them_together() {
    let components = [(
        component("ring", "0.17.14", None),
        taken(
            "Apache-2.0 AND ISC",
            vec![
                own("LICENSE", "ring licence"),
                own("LICENSE-BoringSSL", "boringssl licence"),
            ],
        ),
    )];
    let out = render("0.7.1", &components);
    let first = out.find("ring licence").unwrap();
    let second = out.find("boringssl licence").unwrap();
    assert!(
        first < second && out[first..second].contains("LICENSE-BoringSSL"),
        "{out}"
    );
}

#[skuld::test]
fn a_text_with_a_code_fence_in_it_is_still_one_block() {
    let body = "before\n```\nfenced inside\n```\nafter\n";
    let components = [(
        component("odd", "1.0.0", None),
        taken("MIT", vec![own("LICENSE", body)]),
    )];
    let out = render("0.7.1", &components);
    let at = out.find("before").unwrap();
    let opening = out[..at].lines().last().unwrap();
    assert!(
        opening.starts_with("````") && opening.chars().all(|c| c == '`'),
        "opening fence: {opening:?}"
    );
    assert!(
        out[at + body.len()..].starts_with("````"),
        "the block closes with the same fence"
    );
}

#[skuld::test]
fn a_supplied_text_names_where_it_was_read_from() {
    let mut text = own("MIT", "Copyright (c) Jane");
    text.source = Some("https://example.com/widget/LICENSE".to_owned());
    let components = [(component("widget", "1.0.0", None), taken("MIT", vec![text]))];
    assert!(render("0.7.1", &components).contains("https://example.com/widget/LICENSE"));
}

#[skuld::test]
fn the_output_is_the_same_for_the_same_input() {
    let apache = spdx::license_id("Apache-2.0").unwrap().text();
    let build = |order: &[usize]| {
        let all = [
            (
                component("alpha", "1.0.0", None),
                taken("Apache-2.0", vec![shared("Apache-2.0", apache)]),
            ),
            (
                component("beta", "2.0.0", None),
                taken("MIT", vec![own("LICENSE", "Copyright Beta")]),
            ),
            (
                component("gamma", "3.0.0", None),
                taken("MIT", vec![own("LICENSE", "Copyright Gamma")]),
            ),
        ];
        let ordered: Vec<_> = order.iter().map(|&i| all[i].clone()).collect();
        render("0.7.1", &ordered)
    };
    let one = build(&[0, 1, 2]);
    assert_eq!(one, build(&[0, 1, 2]), "twice, the same");
    assert_eq!(one, build(&[2, 0, 1]), "in another order, the same");
}

#[skuld::test]
fn a_merged_text_lists_every_component_it_covers() {
    let words = "MIT, as upstream states it";
    let read = |from: &str| {
        let mut text = own("MIT", words);
        text.source = Some(from.to_owned());
        text
    };
    let components = [
        (
            component("objc2", "0.6.4", Some("https://example.com/objc2")),
            taken("MIT", vec![read("https://example.com/objc2/LICENSE.md")]),
        ),
        (
            component("block2", "0.6.2", Some("https://example.com/block2")),
            taken("MIT", vec![read("https://example.com/block2/LICENSE.md")]),
        ),
        (
            component("objc2-encode", "4.1.0", None),
            taken("MIT", vec![read("https://example.com/block2/LICENSE.md")]),
        ),
    ];
    let out = render("0.7.1", &components);
    assert_eq!(count(&out, words), 1, "the text is printed once:\n{out}");

    // The section's title and the line that says where the text was read from name every component and every source.
    let at = out.find(words).unwrap();
    let section = &out[out[..at].rfind("#### ").unwrap()..at];
    let title = section.lines().next().unwrap();
    for label in ["objc2 0.6.4", "block2 0.6.2", "objc2-encode 4.1.0"] {
        assert!(title.contains(label), "the title names {label}: {title}");
    }
    for url in [
        "https://example.com/objc2",
        "https://example.com/block2",
        "https://example.com/objc2/LICENSE.md",
        "https://example.com/block2/LICENSE.md",
    ] {
        assert!(section.contains(url), "the section gives {url}:\n{section}");
    }
    assert_eq!(
        count(section, "https://example.com/block2/LICENSE.md"),
        1,
        "a source two components share is given once:\n{section}"
    );
}

#[skuld::test]
fn the_third_party_section_says_the_rust_list_may_name_crates_only_the_build_uses() {
    let out = render("0.7.1", &[]);
    let heading = out.find("## Third-party software").unwrap();
    let sentence = out
        .find("may name crates that only the build uses")
        .expect("the section says the Rust list can include build-only crates");
    let next_heading = out[heading + 3..].find("\n#").map_or(out.len(), |at| at + heading + 3);
    assert!(heading < sentence && sentence < next_heading, "{out}");
}

#[skuld::test]
fn a_modified_copy_is_listed_as_one_at_its_address() {
    let mut copy = component(
        "example.com/m",
        "v1.0.0",
        Some("https://example.com/tree/v1/third_party/m"),
    );
    copy.modified_copy = true;
    let out = render("1.0.0", &[(copy, taken("MIT", vec![own("LICENSE", "text")]))]);
    assert!(
        out.contains("- modified copy of example.com/m v1.0.0 (https://example.com/tree/v1/third_party/m)"),
        "{out}"
    );
}
