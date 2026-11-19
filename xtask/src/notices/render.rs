//! The notices file as Markdown.

use std::collections::BTreeMap;
use std::fmt::Write;

use super::take::{standard_body, LicenseText, Taken};
use super::Component;

/// The licence of Hole's own code.
const HOLE_LICENSE: &str = "GPL-3.0-or-later";

/// Where Hole's source is, for the release `hole_version`.
pub fn source_url(hole_version: &str) -> String {
    format!("https://github.com/bindreams/hole/tree/releases/hole/v{hole_version}")
}

/// The notices file for a `hole` artifact of `hole_version` carrying `taken`: Hole's own statement and licence, then
/// the third-party notices. The same input in any order gives the same output.
///
/// A standard text that names no holder is printed once with the components under it. A component's own text is
/// printed whole as it distributes it; components whose texts are byte for byte the same share one block.
pub fn render(hole_version: &str, taken: &[(Component, Taken)]) -> String {
    let gpl = standard_body(HOLE_LICENSE);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Notices\n\n\
         Hole {hole_version} is free software: you can redistribute it and modify it under the terms of the GNU General \
         Public License as published by the Free Software Foundation, either version 3 of the License, or (at your \
         option) any later version (GPL-3.0-or-later).\n\n\
         The source code of this release is at {}\n\n\
         ## GNU General Public License, version 3\n",
        source_url(hole_version)
    );
    fenced(&mut out, gpl);

    out.push_str(
        "\n## Third-party software\n\n\
         Hole includes the software below, under the licences shown. The source code of each component is available at \
         the address listed beside it. The list of Rust crates may name crates that only the build uses.\n",
    );

    // Shared standard texts, by licence.
    let mut shared: BTreeMap<(&str, &str), Vec<&Component>> = BTreeMap::new();
    // A component's own texts, by what they say (the bodies in order): each member with the texts it distributes.
    let mut own: BTreeMap<Vec<&str>, Vec<(&Component, Vec<&LicenseText>)>> = BTreeMap::new();
    let mut notes: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for (component, taken) in taken {
        if let Some(note) = &taken.note {
            notes.insert(key(component), note);
        }
        for text in taken.texts.iter().filter(|text| text.kind.is_printed_once()) {
            shared
                .entry((text.title.as_str(), text.body.as_str()))
                .or_default()
                .push(component);
        }
        let own_texts: Vec<&LicenseText> = taken.texts.iter().filter(|text| !text.kind.is_printed_once()).collect();
        if !own_texts.is_empty() {
            let key = own_texts.iter().map(|text| text.body.as_str()).collect();
            own.entry(key).or_default().push((component, own_texts));
        }
    }

    if !shared.is_empty() {
        out.push_str("\n### Licences whose text names no holder\n");
    }
    for ((id, body), mut components) in shared {
        components.sort_by(|a, b| key(a).cmp(&key(b)));
        let name = spdx::license_id(id).map_or(id, |known| known.full_name);
        let _ = write!(out, "\n#### {name} ({id})\n\nUsed by:\n\n");
        list(&mut out, &components);
        out.push('\n');
        fenced(&mut out, body);
    }

    let mut groups: Vec<_> = own.into_values().collect();
    for members in &mut groups {
        members.sort_by(|a, b| key(a.0).cmp(&key(b.0)));
    }
    groups.sort_by(|a, b| key(a[0].0).cmp(&key(b[0].0)));
    if !groups.is_empty() {
        out.push_str("\n### Licence texts of the components\n");
    }
    for members in groups {
        let components: Vec<&Component> = members.iter().map(|(component, _)| *component).collect();
        let heading = components.iter().map(|c| c.label()).collect::<Vec<_>>().join(", ");
        let _ = write!(out, "\n#### {heading}\n\n");
        list(&mut out, &components);
        for component in &components {
            if let Some(note) = notes.get(&key(component)) {
                let _ = write!(
                    out,
                    "
{note}
"
                );
            }
        }
        // Members share each body; where each read it from can differ.
        for (at, text) in members[0].1.iter().enumerate() {
            let mut sources: Vec<&str> = Vec::new();
            for source in members.iter().filter_map(|(_, texts)| texts[at].source.as_deref()) {
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
            let _ = write!(out, "\n`{}`", text.title);
            if !sources.is_empty() {
                let _ = write!(out, " (read from {})", sources.join(", "));
            }
            out.push_str("\n\n");
            fenced(&mut out, &text.body);
        }
    }
    out
}

fn key(component: &Component) -> (&str, &str) {
    (&component.name, &component.version)
}

fn list(out: &mut String, components: &[&Component]) {
    for component in components {
        match &component.url {
            Some(url) => {
                let _ = writeln!(out, "- {} ({url})", component.label());
            }
            None => {
                let _ = writeln!(out, "- {}", component.label());
            }
        }
    }
}

/// `body` in a code block, exactly as it is. The fence is longer than any run of backticks inside.
fn fenced(out: &mut String, body: &str) {
    let longest = body.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    let _ = writeln!(out, "{fence}");
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    let _ = writeln!(out, "{fence}");
}
