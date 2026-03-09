// Native module import is omitted because the contract uses hex string
// literals (e.g., "1976a914") that represent ByteString values in the
// Rúnar DSL but are &str in native Rust. The contract logic is verified
// by the TS test suite and conformance golden files.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("CovenantVault.runar.rs"),
        "CovenantVault.runar.rs",
    ).unwrap();
}
