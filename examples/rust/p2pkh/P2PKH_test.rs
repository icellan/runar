#[path = "P2PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = mock_pub_key();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_key() {
    let pk = mock_pub_key();
    let wrong_pk = vec![0x03; 33];
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &wrong_pk);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("P2PKH.runar.rs"), "P2PKH.runar.rs").unwrap();
}
