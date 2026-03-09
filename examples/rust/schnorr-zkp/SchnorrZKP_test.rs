#[path = "SchnorrZKP.runar.rs"]
mod contract;

// Native execution tests are omitted because the Fiat-Shamir challenge
// e = bin2num(hash256(R || P)) produces a 256-bit value that overflows
// Rust's i64 Bigint type. The contract logic is verified by the TS test
// suite and conformance golden files (which use arbitrary-precision
// arithmetic via BigInt / Bitcoin Script numbers).

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("SchnorrZKP.runar.rs"),
        "SchnorrZKP.runar.rs",
    )
    .unwrap();
}
