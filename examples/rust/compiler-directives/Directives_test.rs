#[path = "Directives.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn directives() -> Directives {
    let pk = ALICE.pub_key.to_vec();
    Directives { pub_key_hash: hash160(&pk), deploy_tag: b"deploy-v1".to_vec() }
}

#[test]
fn test_spend_all() {
    let pk = ALICE.pub_key.to_vec();
    directives().spend_all(&ALICE.sign_test_message(), &pk);
}

#[test]
fn test_spend_single() {
    let pk = ALICE.pub_key.to_vec();
    directives().spend_single(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_spend_single_wrong_key() {
    let wrong_pk = BOB.pub_key.to_vec();
    directives().spend_single(&BOB.sign_test_message(), &wrong_pk);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Directives.runar.rs"), "Directives.runar.rs").unwrap();
}
