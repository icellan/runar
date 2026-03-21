#[path = "MessageBoard.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_post() {
    let mut b = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    b.post(b"hello".to_vec());
    assert_eq!(b.message, b"hello");
}

#[test]
fn test_post_multiple() {
    let mut b = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    b.post(b"first".to_vec());
    b.post(b"second".to_vec());
    assert_eq!(b.message, b"second");
}

#[test]
fn test_burn() {
    let b = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    b.burn(&ALICE.sign_test_message());
}

#[test]
#[should_panic]
fn test_burn_wrong_key_fails() {
    let b = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    b.burn(&BOB.sign_test_message());
}

#[test]
fn test_owner_unchanged_after_post() {
    let mut b = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    let original_owner = b.owner.clone();
    b.post(b"test".to_vec());
    assert_eq!(b.owner, original_owner);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("MessageBoard.runar.rs"), "MessageBoard.runar.rs").unwrap();
}

#[test]
fn test_empty_initial_message() {
    let c = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    assert_eq!(c.message, b"");
}

#[test]
fn test_post_to_empty() {
    let mut c = MessageBoard {
        message: b"".to_vec(),
        owner: ALICE.pub_key.to_vec(),
    };
    c.post(b"48656c6c6f".to_vec());
    assert_eq!(c.message, b"48656c6c6f");
}
