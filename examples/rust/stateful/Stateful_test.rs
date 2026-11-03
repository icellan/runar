// N-122: Stateful.runar.rs used a private (non-`pub`) struct, so it could not
// be instantiated from this test file via `mod contract` — Rust module
// privacy only opens private items to DESCENDANT modules, and this test file
// is the including (ancestor) side. Making the struct and its fields `pub`
// is inert to the Rúnar frontend: `parser_rustmacro.rs` skips an optional
// `pub` before `struct` and before each field unconditionally, so it does
// not change the parsed AST or move the compiled IR/hex goldens. This test
// now runs the real contract instead of only the Rúnar frontend.

#[path = "Stateful.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Stateful.runar.rs"), "Stateful.runar.rs").unwrap();
}

#[test]
fn increment_accumulates() {
    let mut c = Stateful { count: 0, max_count: 10 };
    c.increment(3);
    c.increment(4);
    assert_eq!(c.count, 7);
}

// The bound is `<=`, so max_count itself is reachable and one past it is
// not. Both rows are needed: an off-by-one in either direction moves exactly
// one of them.
#[test]
fn bound_is_inclusive_at_max_count() {
    let mut c = Stateful { count: 0, max_count: 10 };
    c.increment(10);
    assert_eq!(c.count, 10);
}

#[test]
#[should_panic(expected = "self.count <= self.max_count")]
fn bound_rejects_one_past_max_count() {
    let mut c = Stateful { count: 0, max_count: 10 };
    c.increment(11);
}

#[test]
fn reset_zeroes_the_counter() {
    let mut c = Stateful { count: 9, max_count: 10 };
    c.reset();
    assert_eq!(c.count, 0);
}
