#[path = "P2PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = ALICE.pub_key.to_vec();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_key() {
    let pk = ALICE.pub_key.to_vec();
    let wrong_pk = BOB.pub_key.to_vec();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&BOB.sign_test_message(), &wrong_pk);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("P2PKH.runar.rs"), "P2PKH.runar.rs").unwrap();
}
