use runar::prelude::*;

/// OPRF-based fraud signal convergence proof.
///
/// Two parties submit randomized tokens R_A = (T + o_A)*G and R_B = (T + o_B)*G
/// where T is the shared underlying token and o_A, o_B are ECDH-derived offsets.
///
/// An authority who knows both offsets can prove the two submissions share the
/// same token T by providing Δo = o_A - o_B and verifying:
///
/// ```text
/// R_A - R_B = Δo · G
/// ```
///
/// The token T cancels out in the subtraction, proving convergence without
/// revealing T. Spending this UTXO serves as a formal on-chain subpoena trigger.
#[runar::contract]
pub struct ConvergenceProof {
    #[readonly]
    pub r_a: Point,
    #[readonly]
    pub r_b: Point,
}

#[runar::methods(ConvergenceProof)]
impl ConvergenceProof {
    /// Prove convergence via offset difference.
    ///
    /// `delta_o` is the offset difference o_A - o_B (mod n), provided by the authority.
    #[public]
    pub fn prove_convergence(&self, delta_o: Bigint) {
        // Verify both committed points are on the curve
        assert!(ec_on_curve(&self.r_a));
        assert!(ec_on_curve(&self.r_b));

        // R_A - R_B (point subtraction = add + negate)
        let diff = ec_add(&self.r_a, &ec_negate(&self.r_b));

        // Δo · G (scalar multiplication of generator)
        let expected = ec_mul_gen(delta_o);

        // Assert point equality via coordinate comparison
        assert!(ec_point_x(&diff) == ec_point_x(&expected));
        assert!(ec_point_y(&diff) == ec_point_y(&expected));
    }
}
