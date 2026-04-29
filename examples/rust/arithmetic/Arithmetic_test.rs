// Arithmetic.runar.rs declares `struct Arithmetic` (no `pub`) — the
// `#[runar::contract]` macro re-emits the struct as written, so the type
// is module-private and can't be constructed from a sibling test module
// imported via `#[path]`. We exercise the Rúnar frontend directly via
// compile_check, which is the cross-compiler conformance boundary we care
// about.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("Arithmetic.runar.rs"),
        "Arithmetic.runar.rs",
    )
    .unwrap();
}
