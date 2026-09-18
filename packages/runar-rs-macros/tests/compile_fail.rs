//! Compile-fail coverage for the Rúnar proc-macros.
//!
//! These tests use `trybuild` to assert that misuses of the attribute
//! macros produce a diagnostic rather than silently accepting bad input
//! or panicking inside the macro.

//! R-150: the coverage used to be ONE case against ONE of the three
//! attributes. `stateful_contract` and `unsafe_contract` both delegate to
//! `contract`, so they inherit its enum rejection — but "inherits it today" is
//! a fact about the current implementation, not a pinned behaviour, and the
//! delegation is exactly the kind of thing a later refactor separates.

#[test]
fn compile_fail_cases() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/contract_on_enum.rs");
    t.compile_fail("tests/compile_fail/stateful_contract_on_enum.rs");
    t.compile_fail("tests/compile_fail/unsafe_contract_on_enum.rs");
}
