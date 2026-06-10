// SchnorrZKP.runar.rs cannot be included as a native Rust module here.
//
// 1. The Fiat-Shamir challenge `bin2num(hash256(R || P))` produces a 256-bit
//    value that overflows `runar::prelude::Bigint = i64` — so native
//    execution against the mock crypto types was already off-limits before
//    BUG-001 landed.
//
// 2. BUG-001 added the malleability gate `assert!(within(s, 1, <secp256k1-n>))`
//    where the upper bound is the secp256k1 group order (256 bits). That
//    literal does not fit in an `i64`, so a `#[path = "..."] mod contract;`
//    pull-in would now fail to compile under `cargo build`.
//
// The cross-tier conformance suite consumes this file as text via the Rúnar
// frontend, not as a Rust-buildable module, so this test only exercises the
// frontend's parse → validate → typecheck pipeline. The EC primitives'
// native semantics are exercised by `ec-demo` (which keeps its scalars
// within `i64`).

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("SchnorrZKP.runar.rs"),
        "SchnorrZKP.runar.rs",
    )
    .unwrap();
}
