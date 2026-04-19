// RawOutputTest.runar.rs uses `self.add_raw_output` and `self.add_output`
// — Rúnar intrinsics that the compiler materialises into the emitted
// Bitcoin Script but that do not exist as methods on the generated Rust
// struct. Attempting `#[path] mod contract;` therefore fails to compile
// (the methods are not on &mut RawOutputTest).
//
// NFT_test.rs solves the same problem by defining a shadow struct inline;
// for this much smaller contract we simply exercise the Rúnar frontend
// directly via compile_check, which is the cross-compiler conformance
// boundary we care about.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("RawOutputTest.runar.rs"),
        "RawOutputTest.runar.rs",
    )
    .unwrap();
}
