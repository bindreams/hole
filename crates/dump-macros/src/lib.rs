//! Proc-macro support for the `dump` crate — provides
//! `#[derive(Dump)]`.
//!
//! v1 attribute vocabulary:
//!
//! - Field: `#[dump(skip)]`, `#[dump(rename = "...")]`,
//!   `#[dump(secret)]`.
//! - Container: `#[dump(rename_all = "kebab-case" | "snake_case")]`.
//!
//! ## `rename_all` scope
//!
//! `rename_all` applies to **struct field names** and **struct-variant
//! field names** only. Enum variant names themselves are never rewritten
//! (use `#[dump(rename = "...")]` on the variant if you need this).
//!
//! The rename is a plain `_` → `-` substitution — there is no
//! camelCase / PascalCase splitting. A field named `fooBar` stays as
//! `fooBar` under `kebab-case`; use `#[dump(rename = "foo-bar")]`
//! explicitly. Raw identifiers (`r#type`) have their `r#` prefix
//! stripped before the substitution runs, matching what the YAML key
//! should look like to a reader.
//!
//! Future commits may add `flatten`, `via`, and `tag`. The derive emits
//! absolute paths (`::dump::...`) so it works from any downstream crate.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Fields, Ident, LitStr};

#[proc_macro_derive(Dump, attributes(dump))]
pub fn derive_dump(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    // Add `T: ::dump::Dump` bound for every type parameter, matching
    // what `#[derive(Debug)]` does for its own bound.
    let mut generics = input.generics.clone();
    for p in generics.type_params_mut() {
        p.bounds.push(syn::parse_quote!(::dump::Dump));
    }
    let (impl_gen, type_gen, where_clause) = generics.split_for_impl();

    let container = parse_container_attrs(&input.attrs)?;
    let body = match &input.data {
        Data::Struct(s) => gen_struct(s, &container)?,
        Data::Enum(e) => gen_enum(e, name, &container)?,
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(name, "Dump cannot be derived for unions"));
        }
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_gen ::dump::Dump for #name #type_gen #where_clause {
            fn dump(&self) -> ::dump::DumpValue {
                #body
            }
        }
    })
}

#[derive(Clone, Copy, Default)]
enum RenameRule {
    #[default]
    None,
    KebabCase,
    SnakeCase,
}

impl RenameRule {
    /// Apply the rename rule to a raw `Ident::to_string()` value. Strips
    /// the `r#` raw-identifier prefix first so the resulting YAML key
    /// reflects the reader's mental model, not Rust's escape syntax.
    fn apply(self, s: String) -> String {
        let s = s.strip_prefix("r#").map(str::to_owned).unwrap_or(s);
        match self {
            RenameRule::None | RenameRule::SnakeCase => s,
            RenameRule::KebabCase => s.replace('_', "-"),
        }
    }
}

#[derive(Default)]
struct ContainerConfig {
    rename_all: RenameRule,
}

fn parse_container_attrs(attrs: &[syn::Attribute]) -> syn::Result<ContainerConfig> {
    let mut c = ContainerConfig::default();
    for attr in attrs {
        if !attr.path().is_ident("dump") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                let s: LitStr = meta.value()?.parse()?;
                c.rename_all = match s.value().as_str() {
                    "kebab-case" => RenameRule::KebabCase,
                    "snake_case" => RenameRule::SnakeCase,
                    other => {
                        return Err(meta.error(format!(
                            "unknown `rename_all` value {other:?}; expected \"kebab-case\" or \"snake_case\""
                        )));
                    }
                };
            } else {
                return Err(meta.error("unknown container-level `dump` attribute"));
            }
            Ok(())
        })?;
    }
    Ok(c)
}

#[derive(Default)]
struct FieldConfig {
    skip: bool,
    secret: bool,
    rename: Option<String>,
}

fn parse_field_attrs(attrs: &[syn::Attribute]) -> syn::Result<FieldConfig> {
    let mut c = FieldConfig::default();
    for attr in attrs {
        if !attr.path().is_ident("dump") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                c.skip = true;
            } else if meta.path.is_ident("secret") {
                c.secret = true;
            } else if meta.path.is_ident("rename") {
                let s: LitStr = meta.value()?.parse()?;
                c.rename = Some(s.value());
            } else {
                return Err(meta.error("unknown `dump` attribute"));
            }
            Ok(())
        })?;
    }
    Ok(c)
}

fn wrap_secret(expr: TokenStream2, secret: bool) -> TokenStream2 {
    if secret {
        quote! {
            ::dump::DumpValue::tagged(::dump::tag::SECRET, #expr)
        }
    } else {
        expr
    }
}

fn gen_struct(s: &DataStruct, container: &ContainerConfig) -> syn::Result<TokenStream2> {
    match &s.fields {
        Fields::Named(named) => {
            let mut entries = Vec::new();
            for f in &named.named {
                let cfg = parse_field_attrs(&f.attrs)?;
                if cfg.skip {
                    continue;
                }
                let ident = f.ident.as_ref().unwrap();
                let key = cfg
                    .rename
                    .unwrap_or_else(|| container.rename_all.apply(ident.to_string()));
                let value = wrap_secret(quote! { ::dump::Dump::dump(&self.#ident) }, cfg.secret);
                entries.push(quote! {
                    (::dump::DumpValue::String(#key.into()), #value)
                });
            }
            Ok(quote! {
                ::dump::DumpValue::Map(vec![#(#entries),*])
            })
        }
        Fields::Unnamed(unnamed) => {
            let mut items = Vec::new();
            for (i, f) in unnamed.unnamed.iter().enumerate() {
                let cfg = parse_field_attrs(&f.attrs)?;
                if cfg.skip {
                    continue;
                }
                let idx = syn::Index::from(i);
                let value = wrap_secret(quote! { ::dump::Dump::dump(&self.#idx) }, cfg.secret);
                items.push(value);
            }
            Ok(quote! {
                ::dump::DumpValue::Seq(vec![#(#items),*])
            })
        }
        Fields::Unit => Ok(quote! { ::dump::DumpValue::Null }),
    }
}

fn gen_enum(e: &DataEnum, name: &Ident, container: &ContainerConfig) -> syn::Result<TokenStream2> {
    let mut arms = Vec::new();
    for v in &e.variants {
        let vname = &v.ident;
        let vname_str = vname.to_string();
        let arm = match &v.fields {
            Fields::Unit => quote! {
                #name::#vname => ::dump::DumpValue::String(#vname_str.into())
            },
            Fields::Unnamed(unnamed) => {
                let n = unnamed.unnamed.len();
                let fields: Vec<_> = (0..n)
                    .map(|i| Ident::new(&format!("__f{}", i), proc_macro2::Span::call_site()))
                    .collect();

                if n == 1 {
                    let f = &fields[0];
                    let cfg = parse_field_attrs(&unnamed.unnamed[0].attrs)?;
                    let value = wrap_secret(quote! { ::dump::Dump::dump(#f) }, cfg.secret);
                    quote! {
                        #name::#vname(#f) => ::dump::DumpValue::Map(vec![(
                            ::dump::DumpValue::String(#vname_str.into()),
                            #value,
                        )])
                    }
                } else {
                    let mut dumps = Vec::new();
                    for (i, raw) in unnamed.unnamed.iter().enumerate() {
                        let cfg = parse_field_attrs(&raw.attrs)?;
                        if cfg.skip {
                            continue;
                        }
                        let fi = &fields[i];
                        dumps.push(wrap_secret(quote! { ::dump::Dump::dump(#fi) }, cfg.secret));
                    }
                    quote! {
                        #name::#vname(#(#fields),*) => ::dump::DumpValue::Map(vec![(
                            ::dump::DumpValue::String(#vname_str.into()),
                            ::dump::DumpValue::Seq(vec![#(#dumps),*]),
                        )])
                    }
                }
            }
            Fields::Named(named) => {
                let field_idents: Vec<&Ident> = named.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
                let mut entries = Vec::new();
                for f in &named.named {
                    let cfg = parse_field_attrs(&f.attrs)?;
                    if cfg.skip {
                        continue;
                    }
                    let fi = f.ident.as_ref().unwrap();
                    let key = cfg.rename.unwrap_or_else(|| container.rename_all.apply(fi.to_string()));
                    let value = wrap_secret(quote! { ::dump::Dump::dump(#fi) }, cfg.secret);
                    entries.push(quote! {
                        (::dump::DumpValue::String(#key.into()), #value)
                    });
                }
                quote! {
                    #name::#vname { #(#field_idents),* } => ::dump::DumpValue::Map(vec![(
                        ::dump::DumpValue::String(#vname_str.into()),
                        ::dump::DumpValue::Map(vec![#(#entries),*]),
                    )])
                }
            }
        };
        arms.push(arm);
    }
    Ok(quote! {
        match self {
            #(#arms,)*
        }
    })
}
