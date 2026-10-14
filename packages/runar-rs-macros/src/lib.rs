//! Proc-macro crate for Rúnar smart contract attributes.
//!
//! - `#[runar::contract]` / `#[runar::stateful_contract]` /
//!   `#[runar::unsafe_contract]` — strip the `#[readonly]` and `#[embed_always]`
//!   field annotations (since Rust doesn't allow attribute macros on fields)
//!   and pass the struct through. `#[embed_always]` (N-093) is the native
//!   spelling of the `@embedAlways` directive; it does not make a field
//!   readonly — only `#[readonly]` does.
//! - `#[runar::sighash(<FLAGS>)]` / `#[sighash(<FLAGS>)]` (N-093) — the native
//!   spelling of the `@sighash` directive on a public method. A pass-through:
//!   it returns the method unchanged so it compiles as ordinary Rust; the Rúnar
//!   `.runar.rs` frontend reads and validates the flags.
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
/// Strips `#[readonly]` and `#[embed_always]` annotations from fields so the
/// struct compiles. The Rúnar compiler parses these annotations with its own
/// parser.
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

    let ident = s.ident.clone();
    let mut_fields = mutable_named_fields(&s.fields);
    strip_field_markers(&mut s.fields);

    let field_args = mut_fields.iter().map(|(n, ty)| quote! { #n: #ty });
    let field_names: Vec<_> = mut_fields.iter().map(|(n, _)| n.clone()).collect();
    let output_fields = mut_fields.iter().map(|(n, ty)| quote! { pub #n: #ty });
    let vis = s.vis.clone();
    let output_ident = quote::format_ident!("{}Output", ident);
    let log_ident = quote::format_ident!("__RUNAR_{}_OUTPUTS", ident);
    let raw_output_ident = quote::format_ident!("{}RawOutput", ident);
    let raw_log_ident = quote::format_ident!("__RUNAR_{}_RAW_OUTPUTS", ident);
    let data_output_ident = quote::format_ident!("{}DataOutput", ident);
    let data_log_ident = quote::format_ident!("__RUNAR_{}_DATA_OUTPUTS", ident);

    // A second impl block is visible to the contract's own `impl` in the
    // same module (`#[path]` tests). Extra args match mutable properties
    // in declaration order — the same positional convention the compiler
    // uses for `this.addOutput(satoshis, ...)`.
    //
    // F-057: `add_output` RECORDS what it is given, on a thread-local log
    // that `take_outputs()` drains, typed as `<Contract>Output` with one field
    // per mutable property. It used to discard its arguments, so a native test
    // of a contract that creates outputs could only assert on fields — which is
    // why token-ft / token-nft tested a hand-copied struct instead of the real
    // contract. The log is per thread, and libtest runs each `#[test]` on its
    // own thread, so every test starts with an empty log.
    //
    // N-122: `add_raw_output` and `add_data_output` RECORD the same way, each
    // on its own thread-local log drained by its own `take_*_outputs()`. They
    // used to discard their arguments silently — the generated methods existed
    // (so `#[path]` tests compiled) but nothing could be asserted about what a
    // contract calling them actually emitted.
    quote! {
        #s

        /// One output recorded by the native `add_output` mock: the satoshis
        /// and the mutable properties, positionally, under their field names.
        #[allow(dead_code)]
        #[derive(Debug, Clone, PartialEq)]
        #vis struct #output_ident {
            pub satoshis: i64,
            #(#output_fields),*
        }

        /// One output recorded by the native `add_raw_output` mock: the
        /// satoshis and the raw script bytes, verbatim.
        #[allow(dead_code)]
        #[derive(Debug, Clone, PartialEq)]
        #vis struct #raw_output_ident {
            pub satoshis: i64,
            pub script: ::std::vec::Vec<u8>,
        }

        /// One output recorded by the native `add_data_output` mock: the
        /// satoshis and the data bytes, verbatim.
        #[allow(dead_code)]
        #[derive(Debug, Clone, PartialEq)]
        #vis struct #data_output_ident {
            pub satoshis: i64,
            pub data: ::std::vec::Vec<u8>,
        }

        ::std::thread_local! {
            #[allow(non_upper_case_globals)]
            static #log_ident: ::std::cell::RefCell<::std::vec::Vec<#output_ident>> =
                ::std::cell::RefCell::new(::std::vec::Vec::new());
            #[allow(non_upper_case_globals)]
            static #raw_log_ident: ::std::cell::RefCell<::std::vec::Vec<#raw_output_ident>> =
                ::std::cell::RefCell::new(::std::vec::Vec::new());
            #[allow(non_upper_case_globals)]
            static #data_log_ident: ::std::cell::RefCell<::std::vec::Vec<#data_output_ident>> =
                ::std::cell::RefCell::new(::std::vec::Vec::new());
        }

        impl #ident {
            #[allow(dead_code)]
            fn add_output(&mut self, satoshis: i64, #(#field_args),*) {
                #log_ident.with(|log| {
                    log.borrow_mut().push(#output_ident { satoshis, #(#field_names),* })
                });
            }
            /// Drain the outputs this thread's `add_output` calls recorded, in
            /// call order.
            #[allow(dead_code)]
            pub fn take_outputs() -> ::std::vec::Vec<#output_ident> {
                #log_ident.with(|log| ::std::mem::take(&mut *log.borrow_mut()))
            }
            #[allow(dead_code)]
            fn add_raw_output(&mut self, satoshis: i64, script: impl ::core::convert::AsRef<[u8]>) {
                #raw_log_ident.with(|log| {
                    log.borrow_mut().push(#raw_output_ident { satoshis, script: script.as_ref().to_vec() })
                });
            }
            /// Drain the outputs this thread's `add_raw_output` calls recorded,
            /// in call order.
            #[allow(dead_code)]
            pub fn take_raw_outputs() -> ::std::vec::Vec<#raw_output_ident> {
                #raw_log_ident.with(|log| ::std::mem::take(&mut *log.borrow_mut()))
            }
            #[allow(dead_code)]
            fn add_data_output(&mut self, satoshis: i64, data: impl ::core::convert::AsRef<[u8]>) {
                #data_log_ident.with(|log| {
                    log.borrow_mut().push(#data_output_ident { satoshis, data: data.as_ref().to_vec() })
                });
            }
            /// Drain the outputs this thread's `add_data_output` calls
            /// recorded, in call order.
            #[allow(dead_code)]
            pub fn take_data_outputs() -> ::std::vec::Vec<#data_output_ident> {
                #data_log_ident.with(|log| ::std::mem::take(&mut *log.borrow_mut()))
            }
        }
    }
    .into()
}

fn mutable_named_fields(fields: &Fields) -> Vec<(syn::Ident, syn::Type)> {
    match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .filter_map(|f| {
                if f.attrs.iter().any(is_readonly_attr) {
                    return None;
                }
                let ident = f.ident.clone()?;
                // Compiler-injected sighash preimage is not contract state.
                // Both Rust parsers omit it; including it here makes
                // `add_output` require an extra positional argument that
                // native `this.add_output(sats, ...mutable)` calls do not pass.
                if ident == "tx_preimage" || ident == "txPreimage" {
                    return None;
                }
                Some((ident, f.ty.clone()))
            })
            .collect(),
        _ => Vec::new(),
    }
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


/// Marks a public method's BIP-143 sighash type (N-093), e.g.
/// `#[sighash(SINGLE | FORKID)]` — the native spelling of the `@sighash`
/// directive. A pass-through: the item is returned unchanged so the method
/// compiles as ordinary Rust. The Rúnar `.runar.rs` frontend reads the flags
/// from the source text and refuses a malformed or misplaced one.
#[proc_macro_attribute]
pub fn sighash(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Remove the `#[readonly]` and `#[embed_always]` field markers from each
/// field in the given `Fields`. Works for named, unnamed, and unit structs.
fn strip_field_markers(fields: &mut Fields) {
    match fields {
        Fields::Named(named) => {
            for field in named.named.iter_mut() {
                field.attrs.retain(|a| !is_field_marker_attr(a));
            }
        }
        Fields::Unnamed(unnamed) => {
            for field in unnamed.unnamed.iter_mut() {
                field.attrs.retain(|a| !is_field_marker_attr(a));
            }
        }
        Fields::Unit => {}
    }
}

/// Return true if the attribute is a bare `#[readonly]` marker.
fn is_readonly_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("readonly")
}

/// Return true if the attribute is a field marker the Rúnar frontend reads:
/// `#[readonly]`, or `#[embed_always]` (N-093).
fn is_field_marker_attr(attr: &syn::Attribute) -> bool {
    is_readonly_attr(attr) || attr.path().is_ident("embed_always")
}
