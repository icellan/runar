module P384Primitives {
    use runar::types::{P384Point};
    use runar::crypto::{p384_mul, p384_add, p384_mul_gen, p384_on_curve};

    struct P384Primitives {
        expected_point: P384Point,
    }

    public fun verify(contract: &P384Primitives, k: bigint, base_point: P384Point) {
        let result: P384Point = p384_mul(base_point, k);
        assert!(p384_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }

    public fun verify_add(contract: &P384Primitives, a: P384Point, b: P384Point) {
        let result: P384Point = p384_add(a, b);
        assert!(p384_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }

    public fun verify_mul_gen(contract: &P384Primitives, k: bigint) {
        let result: P384Point = p384_mul_gen(k);
        assert!(p384_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }
}
