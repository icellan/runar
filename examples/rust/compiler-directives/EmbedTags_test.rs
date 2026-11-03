#[path = "EmbedTags.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn embed_tags() -> EmbedTags {
    let pk = ALICE.pub_key.to_vec();
    let mut c = EmbedTags { pub_key_hash: hash160(&pk), tags: [0; 3] };
    c.init();
    c
}

#[test]
fn test_init_sets_tags() {
    assert_eq!(embed_tags().tags, [7, 9, 11]);
}

#[test]
fn test_unlock() {
    let pk = ALICE.pub_key.to_vec();
    embed_tags().unlock(&ALICE.sign_test_message(), &pk, 9);
}

#[test]
#[should_panic]
fn test_unlock_amount_below_tag() {
    let pk = ALICE.pub_key.to_vec();
    embed_tags().unlock(&ALICE.sign_test_message(), &pk, 8);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("EmbedTags.runar.rs"), "EmbedTags.runar.rs").unwrap();
}
