#[path = "Sha256CompressTest.runar.rs"]
mod contract;

use contract::*;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_verify() {
    // SHA-256 IV
    let state =
        hex_to_bytes("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
    // "abc" padded to a full 64-byte block per FIPS 180-4 Section 5.1.1
    let block = hex_to_bytes(
        "6162638000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000018",
    );
    let expected = runar::prelude::sha256_compress(&state, &block);
    let c = Sha256CompressTest { expected };
    c.verify(&state, &block);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("Sha256CompressTest.runar.rs"),
        "Sha256CompressTest.runar.rs",
    )
    .unwrap();
}
