#[path = "Blake3Test.runar.rs"]
mod contract;

use contract::*;

// Cross-language reference vectors for the Rúnar BLAKE3 single-block
// compression with hardcoded blockLen=64, counter=0, flags=11. Same values
// pinned in the seven runtime crates.
const EXPECTED_COMPRESS_ZERO_CV_ZERO_BLOCK: &str =
    "3c523e448860d92eefcfadcebd1873a4c2b22bd0acb7276b78e5ff58fcbd43f2";
const EXPECTED_HASH_ZERO_32: &str =
    "2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda";

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_verify_compress() {
    let chaining_value = vec![0u8; 32];
    let block = vec![0u8; 64];
    let c = Blake3Test { expected: hex_decode(EXPECTED_COMPRESS_ZERO_CV_ZERO_BLOCK) };
    c.verify_compress(&chaining_value, &block);
}

#[test]
fn test_verify_hash() {
    let message = vec![0u8; 32];
    let c = Blake3Test { expected: hex_decode(EXPECTED_HASH_ZERO_32) };
    c.verify_hash(&message);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Blake3Test.runar.rs"), "Blake3Test.runar.rs").unwrap();
}
