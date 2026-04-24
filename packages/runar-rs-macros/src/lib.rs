//! Proc-macro crate for Rúnar smart contract attributes.
//!
//! - `#[runar::contract]` — strips `#[readonly]` field annotations (since Rust
//!   doesn't allow attribute macros on fields) and passes the struct through.
//! - `#[runar::methods(Name)]` — identity macro for impl blocks.
//! - `#[public]` — identity macro marking a spending entry point.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Fields, Item, ItemStruct};

/// Marks a struct as a Rúnar smart contract.
///
/// Strips `#[readonly]` annotations from fields so the struct compiles.
/// The Rúnar compiler parses these annotations with its own parser.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(item as Item);

    // Only structs are supported — bail out with a compile error otherwise.
    let mut s: ItemStruct = match parsed {
        Item::Struct(s) => s,
        other => {
            let err = syn::Error::new_spanned(
                &other,
                "#[contract] can only be applied to a struct",
            );
            return err.into_compile_error().into();
        }
    };

    strip_readonly_from_fields(&mut s.fields);

    quote! { #s }.into()
}

/// Marks a struct as a stateful Rúnar smart contract.
#[proc_macro_attribute]
pub fn stateful_contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    contract(TokenStream::new(), item)
}

/// Marks an impl block as containing Rúnar contract methods.
///
/// Accepts a single identifier argument: `#[methods(StructName)]`.
#[proc_macro_attribute]
pub fn methods(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Validate the attribute argument shape: expect an `Ident` (the struct name)
    // or empty. Reject malformed argument forms (e.g. literals, punctuation)
    // with a diagnostic so downstream errors are less confusing.
    if !attr.is_empty() {
        let attr2: proc_macro2::TokenStream = attr.into();
        if syn::parse2::<syn::Ident>(attr2).is_err() {
            let err = syn::Error::new(
                proc_macro2::Span::call_site(),
                "#[methods(...)] expects a single identifier naming the contract struct",
            );
            return err.into_compile_error().into();
        }
    }

    // Validate that it wraps an impl block.
    let parsed = parse_macro_input!(item as Item);
    match parsed {
        Item::Impl(_) => quote! { #parsed }.into(),
        other => {
            let err = syn::Error::new_spanned(
                &other,
                "#[methods] can only be applied to an impl block",
            );
            err.into_compile_error().into()
        }
    }
}

/// Marks a method as a public spending entry point.
#[proc_macro_attribute]
pub fn public(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Remove `#[readonly]` attributes from each field in the given `Fields`.
/// Works for named, unnamed, and unit structs.
fn strip_readonly_from_fields(fields: &mut Fields) {
    match fields {
        Fields::Named(named) => {
            for field in named.named.iter_mut() {
                field.attrs.retain(|a| !is_readonly_attr(a));
            }
        }
        Fields::Unnamed(unnamed) => {
            for field in unnamed.unnamed.iter_mut() {
                field.attrs.retain(|a| !is_readonly_attr(a));
            }
        }
        Fields::Unit => {}
    }
}

/// Return true if the attribute is a bare `#[readonly]` marker.
fn is_readonly_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("readonly")
}
