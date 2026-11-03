// N-122: HashRegistry.runar.rs used a private (non-`pub`) struct, so it could
// not be instantiated from this test file via `mod contract` — Rust module
// privacy only opens private items to DESCENDANT modules, and this test file
// is the including (ancestor) side. Making the struct and its field `pub` is
// inert to the Rúnar frontend: `parser_rustmacro.rs` skips an optional `pub`
// before `struct` and before each field unconditionally (same as every other
// `pub struct` contract in this directory), so it does not change the parsed
// AST or move the compiled IR/hex goldens. This test now runs the real
// contract instead of only the Rúnar frontend.

#[path = "HashRegistry.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_compile() {
    runar::compile_check(include_str!("HashRegistry.runar.rs"), "HashRegistry.runar.rs").unwrap();
}

#[test]
fn update_overwrites_the_stored_hash() {
    let first = vec![0x01u8; 20];
    let second = vec![0x02u8; 20];
    // A test whose two fixtures were equal would pass on an `update` that did
    // nothing at all.
    assert_ne!(first, second, "the two fixtures are equal -- this test would be vacuous");

    let mut c = HashRegistry { current_hash: first };
    c.update(second.clone());
    assert_eq!(c.current_hash, second);
}
