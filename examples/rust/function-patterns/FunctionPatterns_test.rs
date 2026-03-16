#[path = "FunctionPatterns.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn alice_sig() -> Sig {
    ALICE.sign_test_message()
}

fn make(balance: Bigint) -> FunctionPatterns {
    FunctionPatterns {
        owner: ALICE.pub_key.to_vec(),
        balance,
    }
}

// ---------------------------------------------------------------------------
// Public method: deposit
// ---------------------------------------------------------------------------

#[test]
fn test_deposit() {
    let mut c = make(10000);
    c.deposit(&alice_sig(), 500);
    assert_eq!(c.balance, 10500);
}

#[test]
fn test_deposit_multiple() {
    let mut c = make(10000);
    c.deposit(&alice_sig(), 100);
    c.deposit(&alice_sig(), 200);
    c.deposit(&alice_sig(), 300);
    assert_eq!(c.balance, 10600);
}

#[test]
#[should_panic]
fn test_deposit_rejects_zero() {
    make(10000).deposit(&alice_sig(), 0);
}

#[test]
#[should_panic]
fn test_deposit_rejects_negative() {
    make(10000).deposit(&alice_sig(), -100);
}

// ---------------------------------------------------------------------------
// Public method: withdraw (private method + built-in)
// ---------------------------------------------------------------------------

#[test]
fn test_withdraw_no_fee() {
    let mut c = make(10000);
    c.withdraw(&alice_sig(), 3000, 0);
    assert_eq!(c.balance, 7000);
}

#[test]
fn test_withdraw_with_fee() {
    let mut c = make(10000);
    // 1000 + 5% fee (50) = 1050
    c.withdraw(&alice_sig(), 1000, 500);
    assert_eq!(c.balance, 8950);
}

#[test]
fn test_withdraw_full_balance() {
    let mut c = make(10000);
    c.withdraw(&alice_sig(), 10000, 0);
    assert_eq!(c.balance, 0);
}

#[test]
#[should_panic]
fn test_withdraw_insufficient() {
    make(10000).withdraw(&alice_sig(), 20000, 0);
}

#[test]
#[should_panic]
fn test_withdraw_fee_exceeds_balance() {
    // 10000 - (10000 + 1% fee of 100 = 10100) -> fail
    make(10000).withdraw(&alice_sig(), 10000, 100);
}

// ---------------------------------------------------------------------------
// Public method: scale (private helper wrapping built-in)
// ---------------------------------------------------------------------------

#[test]
fn test_scale_double() {
    let mut c = make(10000);
    c.scale(&alice_sig(), 2, 1);
    assert_eq!(c.balance, 20000);
}

#[test]
fn test_scale_half() {
    let mut c = make(10000);
    c.scale(&alice_sig(), 1, 2);
    assert_eq!(c.balance, 5000);
}

#[test]
fn test_scale_three_quarters() {
    let mut c = make(10000);
    c.scale(&alice_sig(), 3, 4);
    assert_eq!(c.balance, 7500);
}

// ---------------------------------------------------------------------------
// Public method: normalize (composed private helpers)
// ---------------------------------------------------------------------------

#[test]
fn test_normalize_clamps_and_rounds() {
    let mut c = make(10000);
    c.normalize(&alice_sig(), 0, 8000, 1000);
    assert_eq!(c.balance, 8000);
}

#[test]
fn test_normalize_rounds_down() {
    let mut c = make(7777);
    c.normalize(&alice_sig(), 0, 10000, 1000);
    assert_eq!(c.balance, 7000);
}

#[test]
fn test_normalize_clamps_up() {
    let mut c = make(50);
    c.normalize(&alice_sig(), 1000, 10000, 500);
    assert_eq!(c.balance, 1000);
}

// ---------------------------------------------------------------------------
// Composition: multi-step workflows
// ---------------------------------------------------------------------------

#[test]
fn test_deposit_then_withdraw_with_fee() {
    let mut c = make(10000);
    c.deposit(&alice_sig(), 5000); // 15000
    // 15000 - (5000 + 2% fee of 100) = 9900
    c.withdraw(&alice_sig(), 5000, 200);
    assert_eq!(c.balance, 9900);
}

#[test]
fn test_scale_then_normalize() {
    let mut c = make(10000);
    c.scale(&alice_sig(), 3, 4); // 7500
    c.normalize(&alice_sig(), 0, 10000, 1000); // 7000
    assert_eq!(c.balance, 7000);
}

// ---------------------------------------------------------------------------
// Runar compile check
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(include_str!("FunctionPatterns.runar.rs"), "FunctionPatterns.runar.rs").unwrap();
}
