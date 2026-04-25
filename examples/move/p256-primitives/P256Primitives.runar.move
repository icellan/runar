module P256Primitives {
    use runar::types::{P256Point};
    use runar::crypto::{p256_mul, p256_add, p256_mul_gen, p256_on_curve};

    struct P256Primitives {
        expected_point: P256Point,
    }

    public fun verify(contract: &P256Primitives, k: bigint, base_point: P256Point) {
        let result: P256Point = p256_mul(base_point, k);
        assert!(p256_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }

    public fun verify_add(contract: &P256Primitives, a: P256Point, b: P256Point) {
        let result: P256Point = p256_add(a, b);
        assert!(p256_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }

    public fun verify_mul_gen(contract: &P256Primitives, k: bigint) {
        let result: P256Point = p256_mul_gen(k);
        assert!(p256_on_curve(result), 0);
        assert!(result == contract.expected_point, 0);
    }
}
