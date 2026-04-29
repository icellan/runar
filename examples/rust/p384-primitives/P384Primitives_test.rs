// P384Primitives.runar.rs references the `P384Point` type, which exists
// only inside the Rúnar IR's type universe — the runar Rust prelude does
// not expose it as a Rust type, so `#[path] mod contract;` won't compile.
// The NIST P-384 primitives themselves are exercised end-to-end by the
// p384-wallet example tests; this suite covers the cross-compiler
// frontend boundary (parse → validate → typecheck) for the
// p384-primitives surface.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("P384Primitives.runar.rs"),
        "P384Primitives.runar.rs",
    )
    .unwrap();
}
