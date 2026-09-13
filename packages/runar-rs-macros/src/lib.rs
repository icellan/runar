//! Proc-macro crate for Rúnar smart contract attributes.
//!
//! - `#[runar::contract]` / `#[runar::stateful_contract]` /
//!   `#[runar::unsafe_contract]` — strip `#[readonly]` field annotations (since
//!   Rust doesn't allow attribute macros on fields) and pass the struct
//!   through.
//!
//! All three expand identically, and deliberately so (R-150): the macro exists
//! only to make the struct compile in Rust. Which base class a contract extends
//! is carried by the attribute NAME and read by the Rúnar `.runar.rs` frontend,
//! which sets `parentClass` from it. That distinction is not expressible as a
//! Rust-level transform, so applying the wrong attribute compiles here and is
//! caught there.
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
    expand_contract_like(item, "contract")
}

/// The shared body of all three contract attributes.
///
/// R-150: they expand IDENTICALLY, and that is correct rather than an
/// oversight — the macro's only job is to make the struct compile in Rust by
/// stripping `#[readonly]`, which Rust does not allow on fields. The
/// stateless / stateful / unsafe distinction is carried by the ATTRIBUTE NAME
/// in the source text and read by the Rúnar `.runar.rs` frontend, which sets
/// `parentClass` from it; nothing about that distinction is expressible as a
/// Rust-level transform. Applying the wrong one therefore compiles and passes
/// `cargo test` — and is caught by the Rúnar frontend, which is the only layer
/// that knows what the three mean.
///
/// `name` exists so the diagnostic names the attribute the author actually
/// wrote. Before, `#[stateful_contract]` on an enum reported
/// "#[contract] can only be applied to a struct", because the delegation
/// carried the callee's name into the message.
fn expand_contract_like(item: TokenStream, name: &str) -> TokenStream {
    let parsed = parse_macro_input!(item as Item);

    // Only structs are supported — bail out with a compile error otherwise.
    let mut s: ItemStruct = match parsed {
        Item::Struct(s) => s,
        other => {
            let err = syn::Error::new_spanned(
                &other,
                format!("#[{name}] can only be applied to a struct"),
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
    expand_contract_like(item, "stateful_contract")
}

/// Marks a struct as an `UnsafeSmartContract` — the asm-escape-hatch base
/// class. The unsafe designation relaxes the type-checked subset for the bytes
/// inside `asm(...)` calls, not for mutable state. The Rúnar Rust-DSL frontend
/// keys off the `#[runar::unsafe_contract]` attribute to set `parentClass`.
///
/// R-150: this doc comment used to assert "all fields must be readonly". That
/// is a rule of the RÚNAR FRONTEND, not of this macro — nothing here enforces
/// it, and a reader taking the sentence at face value would expect a Rust-level
/// compile error that has never existed. The claim is stated where it is true
/// instead of where it is merely believed.
#[proc_macro_attribute]
pub fn unsafe_contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_contract_like(item, "unsafe_contract")
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
