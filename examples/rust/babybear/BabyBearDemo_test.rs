#[path = "BabyBearDemo.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

/// Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
const BB_P: i64 = 2013265921;

// ---------------------------------------------------------------------------
// check_add (bb_field_add)
// ---------------------------------------------------------------------------

#[test]
fn test_check_add_small() {
    let c = BabyBearDemo {};
    c.check_add(5, 7, 12);
}

#[test]
fn test_check_add_wrap() {
    let c = BabyBearDemo {};
    // (p-1) + 1 wraps to 0
    c.check_add(BB_P - 1, 1, 0);
}

#[test]
fn test_check_add_zero() {
    let c = BabyBearDemo {};
    c.check_add(42, 0, 42);
}

#[test]
#[should_panic]
fn test_check_add_wrong() {
    let c = BabyBearDemo {};
    c.check_add(5, 7, 13);
}

// ---------------------------------------------------------------------------
// check_sub (bb_field_sub)
// ---------------------------------------------------------------------------

#[test]
fn test_check_sub() {
    let c = BabyBearDemo {};
    c.check_sub(10, 3, 7);
}

#[test]
fn test_check_sub_wrap() {
    let c = BabyBearDemo {};
    // 0 - 1 = p - 1
    c.check_sub(0, 1, BB_P - 1);
}

#[test]
#[should_panic]
fn test_check_sub_wrong() {
    let c = BabyBearDemo {};
    c.check_sub(10, 3, 8);
}

// ---------------------------------------------------------------------------
// check_mul (bb_field_mul)
// ---------------------------------------------------------------------------

#[test]
fn test_check_mul() {
    let c = BabyBearDemo {};
    c.check_mul(6, 7, 42);
}

#[test]
fn test_check_mul_large_wrap() {
    let c = BabyBearDemo {};
    // (p-1) * 2 mod p = p - 2
    c.check_mul(BB_P - 1, 2, BB_P - 2);
}

#[test]
fn test_check_mul_zero() {
    let c = BabyBearDemo {};
    c.check_mul(12345, 0, 0);
}

#[test]
#[should_panic]
fn test_check_mul_wrong() {
    let c = BabyBearDemo {};
    c.check_mul(6, 7, 43);
}

// ---------------------------------------------------------------------------
// check_inv (bb_field_inv)
// ---------------------------------------------------------------------------

#[test]
fn test_check_inv_one() {
    let c = BabyBearDemo {};
    c.check_inv(1);
}

#[test]
fn test_check_inv_two() {
    let c = BabyBearDemo {};
    c.check_inv(2);
}

#[test]
fn test_check_inv_large() {
    let c = BabyBearDemo {};
    c.check_inv(1000000007);
}

// ---------------------------------------------------------------------------
// check_add_sub_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_check_add_sub_roundtrip() {
    let c = BabyBearDemo {};
    c.check_add_sub_roundtrip(42, 99);
}

// ---------------------------------------------------------------------------
// check_distributive
// ---------------------------------------------------------------------------

#[test]
fn test_check_distributive() {
    let c = BabyBearDemo {};
    c.check_distributive(5, 7, 11);
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("BabyBearDemo.runar.rs"),
        "BabyBearDemo.runar.rs",
    )
    .unwrap();
}
