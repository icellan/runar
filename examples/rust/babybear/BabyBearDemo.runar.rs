use runar::prelude::*;

/// BabyBearDemo -- Demonstrates Baby Bear prime field arithmetic.
///
/// Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
/// Field prime: p = 2^31 - 2^27 + 1 = 2013265921
///
/// Four operations:
/// - `bb_field_add(a, b)` -- (a + b) mod p
/// - `bb_field_sub(a, b)` -- (a - b + p) mod p
/// - `bb_field_mul(a, b)` -- (a * b) mod p
/// - `bb_field_inv(a)` -- a^(p-2) mod p (multiplicative inverse via Fermat)
#[runar::contract]
pub struct BabyBearDemo {}

#[runar::methods(BabyBearDemo)]
impl BabyBearDemo {
    /// Verify field addition.
    #[public]
    pub fn check_add(&self, a: Bigint, b: Bigint, expected: Bigint) {
        assert!(bb_field_add(a, b) == expected);
    }

    /// Verify field subtraction.
    #[public]
    pub fn check_sub(&self, a: Bigint, b: Bigint, expected: Bigint) {
        assert!(bb_field_sub(a, b) == expected);
    }

    /// Verify field multiplication.
    #[public]
    pub fn check_mul(&self, a: Bigint, b: Bigint, expected: Bigint) {
        assert!(bb_field_mul(a, b) == expected);
    }

    /// Verify field inversion: a * inv(a) === 1.
    #[public]
    pub fn check_inv(&self, a: Bigint) {
        let inv = bb_field_inv(a);
        assert!(bb_field_mul(a, inv) == 1);
    }

    /// Verify subtraction is the inverse of addition: (a + b) - b === a.
    #[public]
    pub fn check_add_sub_roundtrip(&self, a: Bigint, b: Bigint) {
        let sum = bb_field_add(a, b);
        let result = bb_field_sub(sum, b);
        assert!(result == a);
    }

    /// Verify distributive law: a * (b + c) === a*b + a*c.
    #[public]
    pub fn check_distributive(&self, a: Bigint, b: Bigint, c: Bigint) {
        let lhs = bb_field_mul(a, bb_field_add(b, c));
        let rhs = bb_field_add(bb_field_mul(a, b), bb_field_mul(a, c));
        assert!(lhs == rhs);
    }
}
