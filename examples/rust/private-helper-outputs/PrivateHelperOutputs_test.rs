// PrivateHelperOutputs.runar.rs uses self.add_output / self.add_data_output —
// Rúnar intrinsics the compiler materialises into emitted Bitcoin Script but
// that do not exist as methods on the macro-generated struct. We exercise
// the Rúnar frontend directly via compile_check.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PrivateHelperOutputs.runar.rs"),
        "PrivateHelperOutputs.runar.rs",
    )
    .unwrap();
}
