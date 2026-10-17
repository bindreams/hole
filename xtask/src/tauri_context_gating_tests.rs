//! Whether a macro is invoked under a `cfg`/`cfg_attr` that can compile it out,
//! for `tauri_context_conformance_tests`: an invocation that is compiled out
//! does not give the unit its context.

use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit::Visit;

use crate::tauri_context_conformance_tests::{ident_is, mentions_of};

/// How many of `source`'s invocations of the macro `name` sit under an attribute
/// that can remove them: `cfg`, or `cfg_attr` expanding to one, on an enclosing
/// item, statement, expression, match arm or field, or as an inner attribute of
/// the file or a module. A macro's unparsed body counts as gated when it holds
/// such an attribute anywhere. `source` itself is all that is read: a file it
/// pulls in with `#[path]` or `include!` is the caller's to list.
pub(crate) fn gated_mentions(source: &str, name: &str, origin: &Path) -> Result<usize, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse {}: {e}", origin.display()))?;
    let mut gating = Gating {
        name,
        depth: 0,
        gated: 0,
    };
    gating.visit_file(&file);
    Ok(gating.gated)
}

struct Gating<'a> {
    name: &'a str,
    /// How many enclosing nodes carry a gating attribute.
    depth: usize,
    gated: usize,
}

impl Gating<'_> {
    fn within(&mut self, gates: bool, visit: impl FnOnce(&mut Self)) {
        self.depth += usize::from(gates);
        visit(self);
        self.depth -= usize::from(gates);
    }

    /// For a node whose attributes lead its tokens (every item, statement,
    /// expression, arm and field value does).
    fn within_node(&mut self, node: &impl ToTokens, visit: impl FnOnce(&mut Self)) {
        self.within(starts_with_gating_attr(node.to_token_stream()), visit);
    }
}

impl<'ast> Visit<'ast> for Gating<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.within(has_gating_attr(&file.attrs), |s| syn::visit::visit_file(s, file));
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.within_node(item, |s| syn::visit::visit_item(s, item));
    }

    // A module's inner attributes sit inside its braces, after its leading tokens.
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        self.within(has_gating_attr(&module.attrs), |s| {
            syn::visit::visit_item_mod(s, module)
        });
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        self.within_node(item, |s| syn::visit::visit_impl_item(s, item));
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        self.within_node(item, |s| syn::visit::visit_trait_item(s, item));
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        self.within_node(stmt, |s| syn::visit::visit_stmt(s, stmt));
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        self.within_node(expr, |s| syn::visit::visit_expr(s, expr));
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.within_node(arm, |s| syn::visit::visit_arm(s, arm));
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        self.within_node(field, |s| syn::visit::visit_field_value(s, field));
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let own = mac.path.segments.last().is_some_and(|s| ident_is(&s.ident, self.name));
        let body = mentions_of(mac.tokens.clone(), self.name).named;
        if self.depth > 0 || contains_gating_attr(mac.tokens.clone()) {
            self.gated += usize::from(own) + body;
        }
    }
}

fn has_gating_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| attr_gates(a.meta.to_token_stream()))
}

/// Whether the attribute `#[<meta>]` (given as `meta`) can remove what it is on.
fn attr_gates(meta: TokenStream) -> bool {
    let mut tokens = meta.into_iter();
    match tokens.next() {
        Some(TokenTree::Ident(head)) if ident_is(&head, "cfg") => true,
        // `cfg_attr(<condition>, <attr>, ...)`: a condition names no `cfg`, so
        // one anywhere in the arguments is an attribute it expands to.
        Some(TokenTree::Ident(head)) if ident_is(&head, "cfg_attr") => {
            matches!(tokens.next(), Some(TokenTree::Group(args)) if names_cfg(args.stream()))
        }
        _ => false,
    }
}

/// Whether `stream` names `cfg` or `cfg_attr` anywhere.
fn names_cfg(stream: TokenStream) -> bool {
    stream.into_iter().any(|tree| match tree {
        TokenTree::Ident(i) => ident_is(&i, "cfg") || ident_is(&i, "cfg_attr"),
        TokenTree::Group(g) => names_cfg(g.stream()),
        _ => false,
    })
}

/// The `#[...]` / `#![...]` attributes at the start of `stream`, whether any gates.
fn starts_with_gating_attr(stream: TokenStream) -> bool {
    let mut tokens = stream.into_iter().peekable();
    while matches!(tokens.peek(), Some(TokenTree::Punct(p)) if p.as_char() == '#') {
        tokens.next();
        if matches!(tokens.peek(), Some(TokenTree::Punct(p)) if p.as_char() == '!') {
            tokens.next();
        }
        match tokens.next() {
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket => {
                if attr_gates(g.stream()) {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}

/// Whether `stream` holds a gating attribute at any depth.
fn contains_gating_attr(stream: TokenStream) -> bool {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    tokens.iter().enumerate().any(|(i, tree)| match tree {
        TokenTree::Punct(p) if p.as_char() == '#' => starts_with_gating_attr(tokens[i..].iter().cloned().collect()),
        TokenTree::Group(g) => contains_gating_attr(g.stream()),
        _ => false,
    })
}

fn gated(source: &str) -> usize {
    gated_mentions(source, "tauri_build_context", Path::new("fixture.rs")).expect("fixture parses")
}

#[skuld::test]
fn a_cfg_on_any_enclosing_node_gates_the_invocation() {
    for source in [
        "#[cfg(any())] fn a() { tauri::tauri_build_context!(); }",
        "fn a() { #[cfg(any())] tauri::tauri_build_context!(); }",
        "fn a() { #[cfg(any())] let _ = tauri::tauri_build_context!(); }",
        "fn a() { let _ = #[cfg(any())] tauri::tauri_build_context!(); }",
        "fn a() { run(#[cfg(any())] tauri::tauri_build_context!()); }",
        "#[cfg(any())] mod m { fn a() { tauri::tauri_build_context!(); } }",
        "struct S; impl S { #[cfg(any())] fn a() { tauri::tauri_build_context!(); } }",
        "trait T { #[cfg(any())] fn a() { tauri::tauri_build_context!(); } }",
        "fn a() { match 0 { #[cfg(any())] _ => tauri::tauri_build_context!(), } }",
        "fn a() { S { #[cfg(any())] f: tauri::tauri_build_context!() }; }",
    ] {
        assert_eq!(gated(source), 1, "{source}");
    }
}

#[skuld::test]
fn a_cfg_attr_that_expands_to_a_cfg_gates_the_invocation() {
    for source in [
        "#[cfg_attr(unix, cfg(any()))] fn a() { tauri::tauri_build_context!(); }",
        "#[cfg_attr(unix, allow(dead_code), cfg(any()))] fn a() { tauri::tauri_build_context!(); }",
        "#[cfg_attr(unix, cfg_attr(unix, cfg(any())))] fn a() { tauri::tauri_build_context!(); }",
    ] {
        assert_eq!(gated(source), 1, "{source}");
    }
}

#[skuld::test]
fn an_inner_cfg_of_the_file_or_a_module_gates_the_invocation() {
    for source in [
        "#![cfg(any())] fn a() { tauri::tauri_build_context!(); }",
        "mod m { #![cfg(any())] fn a() { tauri::tauri_build_context!(); } }",
    ] {
        assert_eq!(gated(source), 1, "{source}");
    }
}

#[skuld::test]
fn a_cfg_inside_another_macros_body_gates_the_invocation() {
    for source in [
        "cfg_if! { if #[cfg(unix)] { fn a() { tauri::tauri_build_context!(); } } }",
        "m! { #[cfg(any())] fn a() { tauri::tauri_build_context!(); } }",
    ] {
        assert_eq!(gated(source), 1, "{source}");
    }
}

#[skuld::test]
fn attributes_that_do_not_enclose_the_invocation_do_not_gate_it() {
    for source in [
        // The attributes the real `main.rs` carries: crate-level `cfg_attr`
        // that expands to other attributes, and `cfg`-gated siblings.
        "#![cfg_attr(not(debug_assertions), windows_subsystem = \"windows\")] \
         #![cfg_attr(test, allow(dead_code))] \
         #[cfg(test)] fn t() {} #[cfg(not(test))] fn main() {} \
         fn run() { tauri::tauri_build_context!(); }",
        "#[cfg_attr(test, allow(dead_code))] fn a() { tauri::tauri_build_context!(); }",
        "#[derive(Debug)] #[allow(unused)] fn a() { tauri::tauri_build_context!(); }",
        "fn a() { #[cfg(test)] let _ = 1; tauri::tauri_build_context!(); }",
        "fn a() { let _ = #[cfg(unix)] 1; run(tauri::tauri_build_context!()); }",
        "#[cfg(unix)] use a::b; fn a() { tauri::tauri_build_context!(); }",
        "fn a() { match 0 { #[cfg(unix)] 1 => {}, _ => tauri::tauri_build_context!(), } }",
        "cfg_if! { if #[cfg(unix)] { fn a() {} } } fn b() { tauri::tauri_build_context!(); }",
    ] {
        assert_eq!(gated(source), 0, "{source}");
    }
}

#[skuld::test]
fn a_raw_identifier_spelling_is_gated_too() {
    assert_eq!(gated("#[cfg(any())] fn a() { tauri::r#tauri_build_context!(); }"), 1);
}

#[skuld::test]
fn a_source_that_does_not_parse_is_reported_with_its_path() {
    let err = gated_mentions("fn f( {", "tauri_build_context", Path::new("crates/x/src/y.rs")).unwrap_err();
    assert!(err.contains("crates/x/src/y.rs"), "{err}");
}
