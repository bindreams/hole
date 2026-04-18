//! Proc-macro support crate for `tun-engine`.
//!
//! Provides `#[freeze]`: given a struct with `pub` fields, generates an
//! immutable companion (field-syntax reads, mutation blocked at compile time)
//! and a `MutXxx` builder companion with `.freeze()`.
//!
//! ```ignore
//! #[freeze]
//! pub struct EngineConfig {
//!     pub max_connections: usize,
//!     pub mtu: u16,
//! }
//!
//! // Usage:
//! let mut c = MutEngineConfig { max_connections: 0, mtu: 0 };
//! c.max_connections = 4096;
//! let config = c.freeze();
//! assert_eq!(config.max_connections, 4096);  // field-syntax read
//! // config.max_connections = 0;  // compile error
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{parse_macro_input, spanned::Spanned, Attribute, Error, Fields, ItemStruct, Meta, Visibility};

// Entry point =========================================================================================================

#[proc_macro_attribute]
pub fn freeze(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return Error::new(Span::call_site(), "#[freeze] does not accept arguments")
            .to_compile_error()
            .into();
    }

    let input = parse_macro_input!(input as ItemStruct);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// Expansion ===========================================================================================================

fn expand(input: ItemStruct) -> syn::Result<proc_macro2::TokenStream> {
    validate(&input)?;

    let derive_default = has_derive_default(&input.attrs)?;
    let doc_attrs: Vec<&Attribute> = input.attrs.iter().filter(|a| is_doc_attr(a)).collect();

    let vis = &input.vis;
    let name = &input.ident;
    let mut_name = format_ident!("Mut{}", name);
    let sealed_mod = format_ident!("__freeze_sealed_{}", name);
    let inner_ident = format_ident!("Inner");

    let fields = named_fields(&input)?;
    let field_names: Vec<_> = fields.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let field_types: Vec<_> = fields.named.iter().map(|f| &f.ty).collect();
    let field_vis: Vec<_> = fields.named.iter().map(|f| &f.vis).collect();
    let field_docs: Vec<Vec<&Attribute>> = fields
        .named
        .iter()
        .map(|f| f.attrs.iter().filter(|a| is_doc_attr(a)).collect())
        .collect();

    // Optional Default impls ------------------------------------------------------------------------------------------
    let default_impls = if derive_default {
        quote! {
            impl ::core::default::Default for #mut_name {
                #[inline]
                fn default() -> Self {
                    Self {
                        #( #field_names: ::core::default::Default::default(), )*
                    }
                }
            }

            impl ::core::default::Default for #name {
                #[inline]
                fn default() -> Self {
                    #mut_name::default().freeze()
                }
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #[doc(hidden)]
        #[allow(non_snake_case)]
        #vis mod #sealed_mod {
            use super::*;

            // Pub-fielded shadow — reached via Deref from the frozen struct.
            // Exposed (pub) so that field visibility carries through to readers
            // outside the sealed module; construction requires going through
            // `Mut...::freeze`, which is the only path that can set the
            // private `inner` field below.
            pub struct #inner_ident {
                #(
                    #( #field_docs )*
                    #field_vis #field_names: #field_types,
                )*
            }

            // The frozen struct. `inner` is private to this submodule — no
            // code outside the submodule (not even the parent module) can
            // mutate it, since field privacy is scoped to the defining
            // module.
            #( #doc_attrs )*
            pub struct #name {
                inner: #inner_ident,
            }

            impl ::core::ops::Deref for #name {
                type Target = #inner_ident;
                #[inline]
                fn deref(&self) -> &Self::Target { &self.inner }
            }

            // The mutable companion — plain pub fields, user mutates freely
            // during construction, then calls `.freeze()` to seal.
            pub struct #mut_name {
                #(
                    #( #field_docs )*
                    #field_vis #field_names: #field_types,
                )*
            }

            impl #mut_name {
                /// Freeze this mutable config into its immutable counterpart.
                #[inline]
                pub fn freeze(self) -> #name {
                    #name {
                        inner: #inner_ident {
                            #( #field_names: self.#field_names, )*
                        },
                    }
                }
            }
        }

        #vis use #sealed_mod::{#name, #mut_name};

        #default_impls
    };

    Ok(expanded)
}

// Validation ==========================================================================================================

fn validate(input: &ItemStruct) -> syn::Result<()> {
    if !input.generics.params.is_empty() {
        return Err(Error::new(
            input.generics.span(),
            "#[freeze] does not support generic parameters yet (v1 restriction)",
        ));
    }
    if let Some(where_clause) = &input.generics.where_clause {
        return Err(Error::new(
            where_clause.span(),
            "#[freeze] does not support where-clauses yet (v1 restriction)",
        ));
    }

    let fields = named_fields(input)?;
    if fields.named.is_empty() {
        return Err(Error::new(fields.span(), "#[freeze] requires at least one field"));
    }

    for field in &fields.named {
        if !matches!(field.vis, Visibility::Public(_)) {
            return Err(Error::new(field.span(), "#[freeze] requires all fields to be `pub`"));
        }
        for attr in &field.attrs {
            if !is_doc_attr(attr) {
                return Err(Error::new(
                    attr.span(),
                    "#[freeze] only supports doc-comment attributes on fields",
                ));
            }
        }
    }

    for attr in &input.attrs {
        if is_doc_attr(attr) {
            continue;
        }
        if is_derive_default(attr)? {
            continue;
        }
        if is_derive_attr(attr) {
            return Err(Error::new(
                attr.span(),
                "#[freeze] only supports `#[derive(Default)]` on the source struct; other derives are not yet supported",
            ));
        }
        return Err(Error::new(
            attr.span(),
            "#[freeze] only supports doc-comment and `#[derive(Default)]` attributes on the source struct",
        ));
    }

    Ok(())
}

fn named_fields(input: &ItemStruct) -> syn::Result<&syn::FieldsNamed> {
    match &input.fields {
        Fields::Named(named) => Ok(named),
        Fields::Unnamed(_) => Err(Error::new(
            input.fields.span(),
            "#[freeze] requires a struct with named fields; tuple structs are not supported",
        )),
        Fields::Unit => Err(Error::new(
            input.fields.span(),
            "#[freeze] requires a struct with named fields; unit structs are not supported",
        )),
    }
}

fn is_doc_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("doc")
}

fn is_derive_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("derive")
}

fn has_derive_default(attrs: &[Attribute]) -> syn::Result<bool> {
    for attr in attrs {
        if is_derive_default(attr)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_derive_default(attr: &Attribute) -> syn::Result<bool> {
    if !is_derive_attr(attr) {
        return Ok(false);
    }
    let Meta::List(list) = &attr.meta else {
        return Ok(false);
    };
    let parsed = list.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)?;
    let only_default = parsed.len() == 1 && parsed.first().map(|p| p.is_ident("Default")).unwrap_or(false);
    if only_default {
        Ok(true)
    } else if parsed.iter().any(|p| p.is_ident("Default")) {
        Err(Error::new(
            attr.span(),
            "#[freeze] only supports a sole `#[derive(Default)]`; combining Default with other derives is not yet supported",
        ))
    } else {
        Ok(false)
    }
}
