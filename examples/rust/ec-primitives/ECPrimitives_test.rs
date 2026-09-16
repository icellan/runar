// ECPrimitives.runar.rs round-trips secp256k1 points through ec_point_x /
// ec_point_y / ec_make_point.
//
// This file used to say, as its reason for running only a compile check:
//
//   "the Rust SDK's ec_point_x / ec_point_y return Bigint (i64) and truncate
//    the high bits of any real curve point — so the rebuilt point is never on
//    the curve when invoked natively"
//
// That was true and it was the bug. The accessors return BigintBig now and
// carry the whole 32-byte coordinate, so the round trip the contract asserts
// runs here rather than being explained away. Keeping the compile check as the
// only coverage would leave the contract's central claim unexecuted — which is
// how the truncation survived in the first place.
#[path = "ECPrimitives.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn point(k: Bigint) -> Point {
    ec_mul_gen(k)
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ECPrimitives.runar.rs"),
        "ECPrimitives.runar.rs",
    )
    .unwrap();
}

/// The coordinates of a real curve point do not fit i64. Without this the two
/// round-trip tests below would pass just as happily on the truncating
/// accessors, because both sides of their comparison would be truncated the
/// same way.
#[test]
fn test_coordinates_are_wider_than_i64() {
    let pt = point(7);
    assert!(ec_point_x(&pt).bits() > 64);
    assert!(ec_point_y(&pt).bits() > 64);
}

#[test]
fn test_check_x_and_y() {
    let pt = point(7);
    let x = ec_point_x(&pt);
    let y = ec_point_y(&pt);
    let c = ECPrimitives { pt };
    c.check_x(x);
    c.check_y(y);
}

#[test]
#[should_panic]
fn test_check_x_wrong() {
    let pt = point(7);
    let x = ec_point_x(&pt);
    let c = ECPrimitives { pt };
    c.check_x(x + 1);
}

/// The identity the contract exists to assert: a point rebuilt from its own
/// coordinates is the point it came from. This could not run at all while the
/// accessors truncated.
#[test]
fn test_make_point_round_trip() {
    let pt = point(7);
    let x = ec_point_x(&pt);
    let y = ec_point_y(&pt);
    let c = ECPrimitives { pt: pt.clone() };
    c.check_make_point(x.clone(), y.clone(), x.clone(), y.clone());
    assert_eq!(ec_make_point(x, y), pt);
}

#[test]
fn test_on_curve() {
    let pt = point(7);
    let c = ECPrimitives { pt };
    c.check_on_curve();
}
