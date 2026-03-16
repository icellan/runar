#[path = "Blake3Test.runar.rs"]
mod contract;

use contract::*;

fn new_blake3_test() -> Blake3Test {
    // Mock BLAKE3 functions return 32 zero bytes, so set expected to match.
    Blake3Test {
        expected: vec![0u8; 32],
    }
}

#[test]
fn test_verify_compress() {
    let chaining_value = vec![0u8; 32];
    let block = vec![0u8; 64];
    new_blake3_test().verify_compress(&chaining_value, &block);
}

#[test]
fn test_verify_hash() {
    let message = vec![0u8; 32];
    new_blake3_test().verify_hash(&message);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Blake3Test.runar.rs"), "Blake3Test.runar.rs").unwrap();
}
