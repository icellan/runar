// DataOutputTest.runar.rs uses `self.add_data_output` — a Rúnar intrinsic
// the compiler materialises into emitted Bitcoin Script but that does not
// exist as a method on the macro-generated DataOutputTest struct. Attempting
// `#[path] mod contract;` therefore fails to compile (the method is not on
// &mut DataOutputTest). The peer add-raw-output test follows the same
// pattern. We exercise the Rúnar frontend directly via compile_check, which
// is the cross-compiler conformance boundary we care about.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("DataOutputTest.runar.rs"),
        "DataOutputTest.runar.rs",
    )
    .unwrap();
}
