// ECPrimitives.runar.rs round-trips secp256k1 points through ec_point_x /
// ec_point_y / ec_make_point. Inside emitted Bitcoin Script the coordinates
// are arbitrary-precision bigints, but the Rust SDK's ec_point_x / ec_point_y
// return Bigint (i64) and truncate the high bits of any real curve point —
// so the rebuilt point is never on the curve when invoked natively. The
// cross-compiler conformance boundary we care about is the Rúnar frontend,
// so this suite covers parse → validate → typecheck. The EC primitives
// themselves are exercised end-to-end by the ec-demo native tests.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ECPrimitives.runar.rs"),
        "ECPrimitives.runar.rs",
    )
    .unwrap();
}
