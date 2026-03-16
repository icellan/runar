//! Rúnar smart contract development crate.
//!
//! Provides types, mock crypto functions, and real hash functions for
//! developing and testing Rúnar contracts in Rust. Import the prelude
//! to get everything:
//!
//! ```ignore
//! use runar::prelude::*;
//! ```

pub mod ec;
pub mod ecdsa;
pub mod prelude;
pub mod rabin;
pub mod sdk;
pub mod slh_dsa;
pub mod test_keys;
pub mod wots;

// Re-export proc-macro attributes so `#[runar::contract]` works.
pub use runar_lang_macros::{contract, methods, public, stateful_contract};

/// Runs the Rúnar frontend (parse → validate → typecheck) on a `.runar.rs`
/// source string. Returns `Ok(())` if the contract is valid Rúnar, or an
/// error describing what failed.
///
/// ```ignore
/// #[test]
/// fn test_compile() {
///     let source = include_str!("MyContract.runar.rs");
///     runar::compile_check(source, "MyContract.runar.rs").unwrap();
/// }
/// ```
pub fn compile_check(source: &str, file_name: &str) -> Result<(), String> {
    let parse_result = runar_compiler_rust::frontend::parser::parse_source(source, Some(file_name));
    if !parse_result.errors.is_empty() {
        let msgs: Vec<String> = parse_result.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("parse errors: {}", msgs.join("; ")));
    }

    let contract = parse_result
        .contract
        .ok_or_else(|| format!("no contract found in {}", file_name))?;

    let validation = runar_compiler_rust::frontend::validator::validate(&contract);
    if !validation.errors.is_empty() {
        return Err(format!("validation errors: {}", validation.errors.join("; ")));
    }

    let tc = runar_compiler_rust::frontend::typecheck::typecheck(&contract);
    if !tc.errors.is_empty() {
        return Err(format!("type check errors: {}", tc.errors.join("; ")));
    }

    Ok(())
}
