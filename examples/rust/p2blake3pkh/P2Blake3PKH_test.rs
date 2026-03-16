#[path = "P2Blake3PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = ALICE.pub_key.to_vec();
    let c = P2Blake3PKH { pub_key_hash: blake3_hash(&pk) };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_hash() {
    let pk = ALICE.pub_key.to_vec();
    // blake3_hash is mocked (always returns 32 zero bytes), so use a non-matching hash
    let wrong_hash = vec![0xff; 32];
    let c = P2Blake3PKH { pub_key_hash: wrong_hash };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("P2Blake3PKH.runar.rs"), "P2Blake3PKH.runar.rs").unwrap();
}
