//! StateCovenantMechanics as native Rust.
//!
//! The contract calls `len`, which `packages/runar-rs` did not ship, so none of
//! its guards had ever been executed off-chain in this tier.

#[path = "StateCovenantMechanics.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn genesis() -> ByteString {
    vec![0u8; 32]
}

fn subject() -> StateCovenantMechanics {
    StateCovenantMechanics {
        state_root: genesis(),
        block_number: 0,
        verifying_key_hash: sha256(b"verifying key"),
    }
}

/// The batch-data hash the contract recomputes: hash256(pre || new).
fn batch_hash(pre: &ByteString, new: &ByteString) -> ByteString {
    hash256(&cat(pre, new))
}

#[test]
fn advances_on_a_well_formed_transition() {
    let mut c = subject();
    let new_root = sha256(b"block 1");
    let h = batch_hash(&genesis(), &new_root);
    c.advance_state(new_root.clone(), 1, h, genesis());
    assert_eq!(c.state_root, new_root);
    assert_eq!(c.block_number, 1);
}

#[test]
fn chains_across_several_transitions() {
    let mut c = subject();
    let mut pre = genesis();
    for block in 1i64..=3 {
        let new_root = sha256(&[block as u8]);
        let h = batch_hash(&pre, &new_root);
        c.advance_state(new_root.clone(), block, h, pre.clone());
        assert_eq!(c.block_number, block);
        pre = new_root;
    }
}

#[test]
#[should_panic]
fn rejects_a_non_increasing_block_number() {
    let mut c = subject();
    c.block_number = 5;
    let new_root = sha256(b"block 5");
    let h = batch_hash(&genesis(), &new_root);
    c.advance_state(new_root, 5, h, genesis());
}

#[test]
#[should_panic]
fn rejects_a_pre_state_root_that_is_not_the_current_one() {
    let mut c = subject();
    let new_root = sha256(b"block 1");
    let wrong = vec![0xffu8; 32];
    let h = batch_hash(&wrong, &new_root);
    c.advance_state(new_root, 1, h, wrong);
}

#[test]
#[should_panic]
fn rejects_a_batch_data_hash_that_does_not_bind_the_transition() {
    let mut c = subject();
    let new_root = sha256(b"block 1");
    c.advance_state(new_root, 1, vec![0xbbu8; 32], genesis());
}

/// R-192: the readonly commitment is kept live by `len(&self.verifying_key_hash)
/// == 32`. That assert is the only reader of the field, so it is the only thing
/// stopping the compiler from eliminating it and turning this fixture into a
/// different contract. It had never been executed.
#[test]
#[should_panic]
fn rejects_a_verifying_key_hash_that_is_not_32_bytes() {
    let mut c = subject();
    c.verifying_key_hash = vec![0u8; 31];
    let new_root = sha256(b"block 1");
    let h = batch_hash(&genesis(), &new_root);
    c.advance_state(new_root, 1, h, genesis());
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("StateCovenantMechanics.runar.rs"),
        "StateCovenantMechanics.runar.rs",
    )
    .unwrap();
}
