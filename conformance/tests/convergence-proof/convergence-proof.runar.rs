use runar::prelude::*;

#[runar::contract]
struct ConvergenceProof {
    #[readonly]
    r_a: Point,
    #[readonly]
    r_b: Point,
}

#[runar::methods(ConvergenceProof)]
impl ConvergenceProof {
    #[public]
    fn prove_convergence(&self, delta_o: Bigint) {
        // Verify both committed points are on the curve
        assert!(ec_on_curve(&self.r_a));
        assert!(ec_on_curve(&self.r_b));

        // R_A - R_B (point subtraction = add + negate)
        let diff = ec_add(&self.r_a, &ec_negate(&self.r_b));

        // delta_o * G (scalar multiplication of generator)
        let expected = ec_mul_gen(delta_o);

        // Assert point equality via coordinate comparison
        assert!(ec_point_x(&diff) == ec_point_x(&expected));
        assert!(ec_point_y(&diff) == ec_point_y(&expected));
    }
}
