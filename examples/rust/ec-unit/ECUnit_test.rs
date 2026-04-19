// ECUnit.runar.rs uses Rúnar EC builtins that, in the Rust prelude, take
// &[u8] rather than owned Point (Vec<u8>). That mismatch is acceptable to
// the Rúnar Rust parser (it strips `&` and translates to the identifier
// call) but breaks Rust-native compilation. As a result we cannot include
// the contract via `#[path]` the way other tests do — attempting to do so
// triggers compile errors on ec_on_curve/ec_negate/ec_mul/ec_add etc.
//
// Instead we exercise the Rúnar frontend directly (parse → validate →
// typecheck → ANF → codegen) via compile_check, which is the real
// cross-compiler conformance boundary for this file.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ECUnit.runar.rs"),
        "ECUnit.runar.rs",
    )
    .unwrap();
}
