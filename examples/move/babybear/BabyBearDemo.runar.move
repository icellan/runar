// BabyBearDemo — Demonstrates Baby Bear prime field arithmetic.
//
// Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
// Field prime: p = 2^31 - 2^27 + 1 = 2013265921
//
// Four operations:
// - bbFieldAdd(a, b) — (a + b) mod p
// - bbFieldSub(a, b) — (a - b + p) mod p
// - bbFieldMul(a, b) — (a * b) mod p
// - bbFieldInv(a) — a^(p-2) mod p (multiplicative inverse via Fermat)
module BabyBearDemo {
    use runar::math::{bbFieldAdd, bbFieldSub, bbFieldMul, bbFieldInv};

    struct BabyBearDemo {
    }

    // Verify field addition.
    public fun check_add(contract: &BabyBearDemo, a: bigint, b: bigint, expected: bigint) {
        assert!(bbFieldAdd(a, b) == expected, 0);
    }

    // Verify field subtraction.
    public fun check_sub(contract: &BabyBearDemo, a: bigint, b: bigint, expected: bigint) {
        assert!(bbFieldSub(a, b) == expected, 0);
    }

    // Verify field multiplication.
    public fun check_mul(contract: &BabyBearDemo, a: bigint, b: bigint, expected: bigint) {
        assert!(bbFieldMul(a, b) == expected, 0);
    }

    // Verify field inversion: a * inv(a) === 1.
    public fun check_inv(contract: &BabyBearDemo, a: bigint) {
        let inv: bigint = bbFieldInv(a);
        assert!(bbFieldMul(a, inv) == 1, 0);
    }

    // Verify subtraction is the inverse of addition: (a + b) - b === a.
    public fun check_add_sub_roundtrip(contract: &BabyBearDemo, a: bigint, b: bigint) {
        let sum: bigint = bbFieldAdd(a, b);
        let result: bigint = bbFieldSub(sum, b);
        assert!(result == a, 0);
    }

    // Verify distributive law: a * (b + c) === a*b + a*c.
    public fun check_distributive(contract: &BabyBearDemo, a: bigint, b: bigint, c: bigint) {
        let lhs: bigint = bbFieldMul(a, bbFieldAdd(b, c));
        let rhs: bigint = bbFieldAdd(bbFieldMul(a, b), bbFieldMul(a, c));
        assert!(lhs == rhs, 0);
    }
}
