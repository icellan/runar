use runar::prelude::*;

#[runar::contract]
struct ECDemo {
    #[readonly]
    pt: Point,
}

#[runar::methods(ECDemo)]
impl ECDemo {
    #[public]
    fn check_x(&self, expected_x: Bigint) {
        assert!(ec_point_x(&self.pt) == expected_x);
    }

    #[public]
    fn check_y(&self, expected_y: Bigint) {
        assert!(ec_point_y(&self.pt) == expected_y);
    }

    #[public]
    fn check_make_point(&self, x: Bigint, y: Bigint, expected_x: Bigint, expected_y: Bigint) {
        let p = ec_make_point(x, y);
        assert!(ec_point_x(&p) == expected_x);
        assert!(ec_point_y(&p) == expected_y);
    }

    #[public]
    fn check_on_curve(&self) {
        assert!(ec_on_curve(&self.pt));
    }

    #[public]
    fn check_add(&self, other: &Point, expected_x: Bigint, expected_y: Bigint) {
        let result = ec_add(&self.pt, other);
        assert!(ec_point_x(&result) == expected_x);
        assert!(ec_point_y(&result) == expected_y);
    }

    #[public]
    fn check_mul(&self, scalar: Bigint, expected_x: Bigint, expected_y: Bigint) {
        let result = ec_mul(&self.pt, scalar);
        assert!(ec_point_x(&result) == expected_x);
        assert!(ec_point_y(&result) == expected_y);
    }

    #[public]
    fn check_mul_gen(&self, scalar: Bigint, expected_x: Bigint, expected_y: Bigint) {
        let result = ec_mul_gen(scalar);
        assert!(ec_point_x(&result) == expected_x);
        assert!(ec_point_y(&result) == expected_y);
    }

    #[public]
    fn check_negate(&self, expected_neg_y: Bigint) {
        let neg = ec_negate(&self.pt);
        assert!(ec_point_y(&neg) == expected_neg_y);
    }

    #[public]
    fn check_negate_roundtrip(&self) {
        let neg1 = ec_negate(&self.pt);
        let neg2 = ec_negate(&neg1);
        assert!(ec_point_x(&neg2) == ec_point_x(&self.pt));
        assert!(ec_point_y(&neg2) == ec_point_y(&self.pt));
    }

    #[public]
    fn check_mod_reduce(&self, value: Bigint, modulus: Bigint, expected: Bigint) {
        assert!(ec_mod_reduce(value, modulus) == expected);
    }

    #[public]
    fn check_encode_compressed(&self, expected: ByteString) {
        let compressed = ec_encode_compressed(&self.pt);
        assert!(compressed == expected);
    }

    #[public]
    fn check_mul_identity(&self) {
        let result = ec_mul(&self.pt, 1);
        assert!(ec_point_x(&result) == ec_point_x(&self.pt));
        assert!(ec_point_y(&result) == ec_point_y(&self.pt));
    }

    #[public]
    fn check_add_on_curve(&self, other: &Point) {
        let result = ec_add(&self.pt, other);
        assert!(ec_on_curve(&result));
    }

    #[public]
    fn check_mul_gen_on_curve(&self, scalar: Bigint) {
        let result = ec_mul_gen(scalar);
        assert!(ec_on_curve(&result));
    }
}
