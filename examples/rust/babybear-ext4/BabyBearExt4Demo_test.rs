#[path = "BabyBearExt4Demo.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

/// Ext4 identity: (a0,a1,a2,a3) * (1,0,0,0) = (a0,a1,a2,a3).
#[test]
fn test_check_mul_identity() {
    let c = BabyBearExt4Demo {};
    let a = (7i64, 11i64, 13i64, 17i64);
    let b = (1i64, 0i64, 0i64, 0i64);
    let expected = (
        bb_ext4_mul0(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
        bb_ext4_mul1(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
        bb_ext4_mul2(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
        bb_ext4_mul3(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
    );
    assert_eq!(expected, a);
    c.check_mul(
        a.0, a.1, a.2, a.3,
        b.0, b.1, b.2, b.3,
        expected.0, expected.1, expected.2, expected.3,
    );
}

#[test]
fn test_check_inv_roundtrip() {
    let c = BabyBearExt4Demo {};
    let a = (100i64, 200i64, 300i64, 400i64);
    let inv = (
        bb_ext4_inv0(a.0, a.1, a.2, a.3),
        bb_ext4_inv1(a.0, a.1, a.2, a.3),
        bb_ext4_inv2(a.0, a.1, a.2, a.3),
        bb_ext4_inv3(a.0, a.1, a.2, a.3),
    );
    // Feed the computed inverse back through check_inv.
    c.check_inv(a.0, a.1, a.2, a.3, inv.0, inv.1, inv.2, inv.3);

    // Sanity: a * inv(a) = (1, 0, 0, 0) in Ext4.
    let prod = (
        bb_ext4_mul0(a.0, a.1, a.2, a.3, inv.0, inv.1, inv.2, inv.3),
        bb_ext4_mul1(a.0, a.1, a.2, a.3, inv.0, inv.1, inv.2, inv.3),
        bb_ext4_mul2(a.0, a.1, a.2, a.3, inv.0, inv.1, inv.2, inv.3),
        bb_ext4_mul3(a.0, a.1, a.2, a.3, inv.0, inv.1, inv.2, inv.3),
    );
    assert_eq!(prod, (1, 0, 0, 0));
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("BabyBearExt4Demo.runar.rs"),
        "BabyBearExt4Demo.runar.rs",
    )
    .unwrap();
}
