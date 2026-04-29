// HashRegistry.runar.rs uses a private (non-pub) struct, so it cannot be
// instantiated from this test file via `mod contract`. We cover the Rúnar
// frontend (parse → validate → typecheck) only.

#[test]
fn test_compile() {
    runar::compile_check(include_str!("HashRegistry.runar.rs"), "HashRegistry.runar.rs").unwrap();
}
