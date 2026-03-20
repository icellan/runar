#[path = "Sha256FinalizeTest.runar.rs"]
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
    // "abc" = 3 bytes = 24 bits
    let remaining = b"abc".to_vec();
    let msg_bit_len: i64 = 24;
    let expected = runar::prelude::sha256_finalize(&state, &remaining, msg_bit_len);
    let c = Sha256FinalizeTest { expected };
    c.verify(&state, &remaining, msg_bit_len);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("Sha256FinalizeTest.runar.rs"),
        "Sha256FinalizeTest.runar.rs",
    )
    .unwrap();
}
