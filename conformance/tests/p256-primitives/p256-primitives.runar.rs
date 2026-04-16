use runar::prelude::*;

#[runar::contract]
struct P256Primitives {
    #[readonly]
    expected_point: ByteString,
}

#[runar::methods(P256Primitives)]
impl P256Primitives {
    #[public]
    fn verify(&self, k: Bigint, base_point: &ByteString) {
        let result = p256_mul(base_point, k);
        assert!(p256_on_curve(&result));
        assert!(result == self.expected_point);
    }

    #[public]
    fn verify_add(&self, a: &ByteString, b: &ByteString) {
        let result = p256_add(a, b);
        assert!(p256_on_curve(&result));
        assert!(result == self.expected_point);
    }

    #[public]
    fn verify_mul_gen(&self, k: Bigint) {
        let result = p256_mul_gen(k);
        assert!(p256_on_curve(&result));
        assert!(result == self.expected_point);
    }
}
