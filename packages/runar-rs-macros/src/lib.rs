//! Proc-macro crate for Rúnar smart contract attributes.
//!
//! - `#[runar::contract]` / `#[runar::stateful_contract]` — strips `#[readonly]`
//!   field annotations (since Rust doesn't allow attribute macros on fields) and
//!   passes the struct through.
//!
//! Methods live in a plain `impl ContractName { ... }` block — no attribute is
//! required. `pub fn` marks a public spending entry point; bare `fn` is a
//! private helper. The former `#[runar::methods]` and `#[public]` attributes
//! have been removed; the Rúnar `.runar.rs` parsers reject them with a
//! migration diagnostic.

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

/// Marks a struct as an `UnsafeSmartContract` — the asm-escape-hatch base
/// class. Like `#[runar::contract]`, all fields must be readonly; the unsafe
/// designation only relaxes the type-checked subset for the bytes inside
/// `asm(...)` calls, not for mutable state. The Rúnar Rust-DSL frontend keys
/// off the `#[runar::unsafe_contract]` attribute to set `parentClass`.
#[proc_macro_attribute]
pub fn unsafe_contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    contract(TokenStream::new(), item)
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
