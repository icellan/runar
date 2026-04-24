//! Compile-fail coverage for the Rúnar proc-macros.
//!
//! These tests use `trybuild` to assert that misuses of the attribute
//! macros produce a diagnostic rather than silently accepting bad input
//! or panicking inside the macro.

#[test]
fn compile_fail_cases() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/contract_on_enum.rs");
    t.compile_fail("tests/compile_fail/methods_bad_arg.rs");
}
