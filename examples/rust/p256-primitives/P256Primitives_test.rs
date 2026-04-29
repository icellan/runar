// P256Primitives.runar.rs references the `P256Point` type, which exists
// only inside the Rúnar IR's type universe — the runar Rust prelude does
// not expose it as a Rust type, so `#[path] mod contract;` won't compile.
// The NIST P-256 primitives themselves are exercised end-to-end by the
// p256-wallet example tests; this suite covers the cross-compiler
// frontend boundary (parse → validate → typecheck) for the
// p256-primitives surface.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("P256Primitives.runar.rs"),
        "P256Primitives.runar.rs",
    )
    .unwrap();
}
