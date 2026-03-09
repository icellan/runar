#[path = "ECDemo.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

// Helper: generate a point from a known scalar for deterministic tests
fn make_test_point(k: Bigint) -> Point {
    ec_mul_gen(k)
}

// -------------------------------------------------------------------
// Coordinate extraction and construction
// -------------------------------------------------------------------

#[test]
fn test_check_x() {
    let pt = make_test_point(7);
    let x = ec_point_x(&pt);
    let c = ECDemo { pt };
    c.check_x(x);
}

#[test]
#[should_panic]
fn test_check_x_wrong() {
    let pt = make_test_point(7);
    let x = ec_point_x(&pt);
    let c = ECDemo { pt };
    c.check_x(x + 1);
}

#[test]
fn test_check_y() {
    let pt = make_test_point(7);
    let y = ec_point_y(&pt);
    let c = ECDemo { pt };
    c.check_y(y);
}

#[test]
#[should_panic]
fn test_check_y_wrong() {
    let pt = make_test_point(7);
    let y = ec_point_y(&pt);
    let c = ECDemo { pt };
    c.check_y(y + 1);
}

#[test]
fn test_check_make_point() {
    let pt = make_test_point(7);
    let x = ec_point_x(&pt);
    let y = ec_point_y(&pt);
    let c = ECDemo { pt };
    c.check_make_point(x, y, x, y);
}

// -------------------------------------------------------------------
// Curve membership
// -------------------------------------------------------------------

#[test]
fn test_check_on_curve() {
    let pt = make_test_point(42);
    let c = ECDemo { pt };
    c.check_on_curve();
}

// -------------------------------------------------------------------
// Point arithmetic
// -------------------------------------------------------------------

#[test]
fn test_check_add() {
    let pt = make_test_point(10);
    let other = make_test_point(20);
    let sum = ec_add(&pt, &other);
    let expected_x = ec_point_x(&sum);
    let expected_y = ec_point_y(&sum);
    let c = ECDemo { pt };
    c.check_add(&other, expected_x, expected_y);
}

#[test]
#[should_panic]
fn test_check_add_wrong() {
    let pt = make_test_point(10);
    let other = make_test_point(20);
    let sum = ec_add(&pt, &other);
    let expected_x = ec_point_x(&sum);
    let c = ECDemo { pt };
    c.check_add(&other, expected_x, 999);
}

#[test]
fn test_check_mul() {
    let pt = make_test_point(5);
    let scalar: Bigint = 3;
    let result = ec_mul(&pt, scalar);
    let expected_x = ec_point_x(&result);
    let expected_y = ec_point_y(&result);
    let c = ECDemo { pt };
    c.check_mul(scalar, expected_x, expected_y);
}

#[test]
#[should_panic]
fn test_check_mul_wrong_scalar() {
    let pt = make_test_point(5);
    let result = ec_mul(&pt, 3);
    let expected_x = ec_point_x(&result);
    let expected_y = ec_point_y(&result);
    let c = ECDemo { pt };
    // Pass scalar 4 but expect results from scalar 3
    c.check_mul(4, expected_x, expected_y);
}

#[test]
fn test_check_mul_gen() {
    let pt = make_test_point(1);
    let scalar: Bigint = 99;
    let result = ec_mul_gen(scalar);
    let expected_x = ec_point_x(&result);
    let expected_y = ec_point_y(&result);
    let c = ECDemo { pt };
    c.check_mul_gen(scalar, expected_x, expected_y);
}

#[test]
#[should_panic]
fn test_check_mul_gen_wrong() {
    let pt = make_test_point(1);
    let result = ec_mul_gen(99);
    let expected_x = ec_point_x(&result);
    let c = ECDemo { pt };
    c.check_mul_gen(99, expected_x, 0);
}

// -------------------------------------------------------------------
// Point negation
// -------------------------------------------------------------------

#[test]
fn test_check_negate() {
    let pt = make_test_point(7);
    let neg = ec_negate(&pt);
    let expected_neg_y = ec_point_y(&neg);
    let c = ECDemo { pt };
    c.check_negate(expected_neg_y);
}

#[test]
fn test_check_negate_roundtrip() {
    let pt = make_test_point(13);
    let c = ECDemo { pt };
    c.check_negate_roundtrip();
}

// -------------------------------------------------------------------
// Modular arithmetic
// -------------------------------------------------------------------

#[test]
fn test_check_mod_reduce_positive() {
    let pt = make_test_point(1);
    let c = ECDemo { pt };
    c.check_mod_reduce(17, 5, 2);
}

#[test]
fn test_check_mod_reduce_negative() {
    let pt = make_test_point(1);
    let c = ECDemo { pt };
    c.check_mod_reduce(-3, 5, 2);
}

#[test]
#[should_panic]
fn test_check_mod_reduce_wrong() {
    let pt = make_test_point(1);
    let c = ECDemo { pt };
    c.check_mod_reduce(17, 5, 3);
}

// -------------------------------------------------------------------
// Compressed encoding
// -------------------------------------------------------------------

#[test]
fn test_check_encode_compressed() {
    let pt = make_test_point(7);
    let compressed = ec_encode_compressed(&pt);
    let c = ECDemo { pt };
    c.check_encode_compressed(compressed);
}

// -------------------------------------------------------------------
// Algebraic properties
// -------------------------------------------------------------------

#[test]
fn test_check_mul_identity() {
    let pt = make_test_point(42);
    let c = ECDemo { pt };
    c.check_mul_identity();
}

#[test]
fn test_check_add_on_curve() {
    let pt = make_test_point(11);
    let other = make_test_point(22);
    let c = ECDemo { pt };
    c.check_add_on_curve(&other);
}

#[test]
fn test_check_mul_gen_on_curve() {
    let pt = make_test_point(1);
    let c = ECDemo { pt };
    c.check_mul_gen_on_curve(12345);
}

// -------------------------------------------------------------------
// Compile check
// -------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ECDemo.runar.rs"),
        "ECDemo.runar.rs",
    )
    .unwrap();
}
