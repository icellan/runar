#[path = "ShiftOps.runar.rs"]
mod contract;

use contract::*;

// The caller supplies the expected shift results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). With
// a = 12 native Rust agrees with the on-chain OP_LSHIFT / OP_RSHIFT; the
// on-chain verdict is pinned by conformance/witnesses/real-crypto/shift-ops.json.

#[test]
fn test_shift() {
    let c = ShiftOps { a: 12 };
    c.test_shift(96, 3);
}

#[test]
#[should_panic(expected = "left == expected_left")]
fn test_shift_rejects_wrong_left_result() {
    let c = ShiftOps { a: 12 };
    c.test_shift(97, 3);
}

#[test]
#[should_panic(expected = "right == expected_right")]
fn test_shift_rejects_wrong_right_result() {
    let c = ShiftOps { a: 12 };
    c.test_shift(96, 2);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ShiftOps.runar.rs"),
        "ShiftOps.runar.rs",
    )
    .unwrap();
}
