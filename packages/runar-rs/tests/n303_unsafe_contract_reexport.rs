//! N-303: `#[runar::unsafe_contract]` must resolve through the crate root,
//! like `#[runar::contract]`, `#[runar::stateful_contract]` and
//! `#[runar::sighash]`. The macro crate defines it and `prelude` already
//! re-exports it, but `lib.rs` did not, so the documented spelling
//! `#[runar::unsafe_contract]` did not compile for a crate that renames
//! `runar-lang` to `runar`.
//!
//! What this proves: the attribute resolves via `runar_lang::unsafe_contract`
//! and strips `#[readonly]` so the struct compiles.
//! What it does NOT prove: the macro's parentClass handling (the compiler's
//! `.runar.rs` parser tests cover that).

#[runar_lang::unsafe_contract]
pub struct Reexported {
    #[readonly]
    pub a: i64,
}

#[test]
fn unsafe_contract_resolves_from_the_crate_root() {
    let c = Reexported { a: 3 };
    assert_eq!(c.a, 3);
}
