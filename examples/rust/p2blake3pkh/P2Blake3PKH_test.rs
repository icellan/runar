#[path = "P2Blake3PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = mock_pub_key();
    let c = P2Blake3PKH { pub_key_hash: blake3_hash(&pk) };
    c.unlock(&mock_sig(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_hash() {
    let pk = mock_pub_key();
    // blake3_hash is mocked (always returns 32 zero bytes), so use a non-matching hash
    let wrong_hash = vec![0xff; 32];
    let c = P2Blake3PKH { pub_key_hash: wrong_hash };
    c.unlock(&mock_sig(), &pk);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("P2Blake3PKH.runar.rs"), "P2Blake3PKH.runar.rs").unwrap();
}
