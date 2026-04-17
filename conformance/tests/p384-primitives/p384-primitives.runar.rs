use runar::prelude::*;

#[runar::contract]
struct P384Primitives {
    #[readonly]
    expected_point: P384Point,
}

#[runar::methods(P384Primitives)]
impl P384Primitives {
    #[public]
    fn verify(&self, k: Bigint, base_point: &P384Point) {
        let result = p384_mul(base_point, k);
        assert!(p384_on_curve(&result));
        assert!(result == self.expected_point);
    }

    #[public]
    fn verify_add(&self, a: &P384Point, b: &P384Point) {
        let result = p384_add(a, b);
        assert!(p384_on_curve(&result));
        assert!(result == self.expected_point);
    }

    #[public]
    fn verify_mul_gen(&self, k: Bigint) {
        let result = p384_mul_gen(k);
        assert!(p384_on_curve(&result));
        assert!(result == self.expected_point);
    }
}
