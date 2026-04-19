// BitwiseOps.runar.rs uses `~` as a unary bitwise-not operator, which is
// valid Rúnar (via its own parser) but NOT valid Rust syntax — Rust spells
// it `!`. Attempting `#[path] mod contract;` therefore fails to compile.
// We exercise the Rúnar frontend directly via compile_check, which is the
// cross-compiler conformance boundary we care about.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("BitwiseOps.runar.rs"),
        "BitwiseOps.runar.rs",
    )
    .unwrap();
}
