#[path = "MathDemo.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_safediv() {
    let mut m = MathDemo { value: 100 };
    m.divide_by(5);
    assert_eq!(m.value, 20);
}

#[test]
fn test_safediv_truncates() {
    let mut m = MathDemo { value: 7 };
    m.divide_by(2);
    assert_eq!(m.value, 3);
}

#[test]
#[should_panic(expected = "division by zero")]
fn test_safediv_rejects_zero() {
    let mut m = MathDemo { value: 10 };
    m.divide_by(0);
}

#[test]
fn test_percent_of() {
    let mut m = MathDemo { value: 10000 };
    m.withdraw_with_fee(1000, 500); // 5% fee = 50, total = 1050
    assert_eq!(m.value, 8950);
}

#[test]
fn test_clamp_below() {
    let mut m = MathDemo { value: 3 };
    m.clamp_value(10, 100);
    assert_eq!(m.value, 10);
}

#[test]
fn test_clamp_above() {
    let mut m = MathDemo { value: 200 };
    m.clamp_value(10, 100);
    assert_eq!(m.value, 100);
}

#[test]
fn test_clamp_in_range() {
    let mut m = MathDemo { value: 50 };
    m.clamp_value(10, 100);
    assert_eq!(m.value, 50);
}

#[test]
fn test_sign_positive() {
    let mut m = MathDemo { value: 42 };
    m.normalize();
    assert_eq!(m.value, 1);
}

#[test]
fn test_sign_negative() {
    let mut m = MathDemo { value: -7 };
    m.normalize();
    assert_eq!(m.value, -1);
}

#[test]
fn test_sign_zero() {
    let mut m = MathDemo { value: 0 };
    m.normalize();
    assert_eq!(m.value, 0);
}

#[test]
fn test_pow() {
    let mut m = MathDemo { value: 2 };
    m.exponentiate(10);
    assert_eq!(m.value, 1024);
}

#[test]
fn test_pow_zero() {
    let mut m = MathDemo { value: 99 };
    m.exponentiate(0);
    assert_eq!(m.value, 1);
}

#[test]
fn test_sqrt() {
    let mut m = MathDemo { value: 100 };
    m.square_root();
    assert_eq!(m.value, 10);
}

#[test]
fn test_sqrt_non_perfect() {
    let mut m = MathDemo { value: 10 };
    m.square_root();
    assert_eq!(m.value, 3);
}

#[test]
fn test_gcd() {
    let mut m = MathDemo { value: 12 };
    m.reduce_gcd(8);
    assert_eq!(m.value, 4);
}

#[test]
fn test_gcd_coprime() {
    let mut m = MathDemo { value: 7 };
    m.reduce_gcd(13);
    assert_eq!(m.value, 1);
}

#[test]
fn test_mul_div() {
    let mut m = MathDemo { value: 1000 };
    m.scale_by_ratio(3, 4);
    assert_eq!(m.value, 750);
}

#[test]
fn test_log2() {
    let mut m = MathDemo { value: 1024 };
    m.compute_log2();
    assert_eq!(m.value, 10);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("MathDemo.runar.rs"), "MathDemo.runar.rs").unwrap();
}
