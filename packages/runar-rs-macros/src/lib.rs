//! Proc-macro crate for Rúnar smart contract attributes.
//!
//! - `#[runar::contract]` — strips `#[readonly]` field annotations (since Rust
//!   doesn't allow attribute macros on fields) and passes the struct through.
//! - `#[runar::methods(Name)]` — identity macro for impl blocks.
//! - `#[public]` — identity macro marking a spending entry point.

use proc_macro::TokenStream;

/// Marks a struct as a Rúnar smart contract.
///
/// Strips `#[readonly]` annotations from fields so the struct compiles.
/// The Rúnar compiler parses these annotations with its own parser.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Strip #[readonly] from the token stream since Rust doesn't allow
    // proc_macro_attribute on struct fields.
    let src = item.to_string();
    let cleaned = src.replace("#[readonly]", "").replace("# [readonly]", "");
    cleaned.parse().expect("failed to parse struct after stripping #[readonly]")
}

/// Marks a struct as a stateful Rúnar smart contract.
#[proc_macro_attribute]
pub fn stateful_contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    contract(TokenStream::new(), item)
}

/// Marks an impl block as containing Rúnar contract methods.
#[proc_macro_attribute]
pub fn methods(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Marks a method as a public spending entry point.
#[proc_macro_attribute]
pub fn public(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
