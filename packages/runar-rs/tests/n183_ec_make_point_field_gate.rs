//! N-183: `ec_make_point` must apply the compiled script's R-156 gate: each
//! coordinate must satisfy 0 <= v < p, or the script aborts. Before the fix
//! Rust refused only a negative or wider-than-256-bit coordinate, so x = p,
//! x = p + 1 and y = p (all < 2^256) built a Point.
//!
//! Proves: boundary operands (p, p+1, 2^256-1 on either half, plus -1 and
//! 2^256) panic, and p - 1 / 0 / a real curve point still build.
//! Does not prove: the script itself (the runar-testing r156 test pins it).

use std::panic;

use num_bigint::BigInt;
use runar_lang::prelude::{ec_make_point, ec_point_y};

fn big(hex: &str) -> BigInt {
    BigInt::parse_bytes(hex.as_bytes(), 16).expect("hex")
}

fn p() -> BigInt {
    big("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
}

fn gy() -> BigInt {
    big("4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee")
}

#[test]
fn ec_make_point_refuses_non_field_elements() {
    let one = BigInt::from(1);
    let two256: BigInt = BigInt::from(1) << 256;
    let cases: Vec<(&str, BigInt, BigInt)> = vec![
        ("x = p", p(), gy()),
        ("x = p + 1", p() + 1, gy()),
        ("y = p", one.clone(), p()),
        ("y = p + 1", one.clone(), p() + 1),
        ("x = 2^256 - 1", two256.clone() - 1, gy()),
        ("y = 2^256 - 1", one.clone(), two256.clone() - 1),
        ("x = -1", BigInt::from(-1), gy()),
        ("y = -1", one.clone(), BigInt::from(-1)),
        ("x = 2^256", two256.clone(), gy()),
        ("y = 2^256 + 1", one.clone(), two256 + 1),
    ];
    for (why, x, y) in cases {
        let r = panic::catch_unwind(|| ec_make_point(x, y));
        assert!(r.is_err(), "ec_make_point({why}) built a Point; the script aborts");
    }
}

#[test]
fn ec_make_point_still_builds_field_elements() {
    let pm1: BigInt = p() - 1;
    assert_eq!(ec_make_point(pm1.clone(), pm1).len(), 64);
    assert_eq!(ec_make_point(BigInt::from(0), BigInt::from(0)), vec![0u8; 64]);
    let pt = ec_make_point(BigInt::from(1), gy());
    assert_eq!(ec_point_y(&pt), gy());
}
