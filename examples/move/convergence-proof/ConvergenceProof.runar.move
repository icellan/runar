module ConvergenceProof {
    use runar::types::{Point};
    use runar::crypto::{ecOnCurve, ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY};

    resource struct ConvergenceProof {
        r_a: Point,
        r_b: Point,
    }

    public fun prove_convergence(contract: &ConvergenceProof, delta_o: bigint) {
        // Verify both committed points are on the curve
        assert!(ecOnCurve(contract.r_a), 0);
        assert!(ecOnCurve(contract.r_b), 0);

        // R_A - R_B (point subtraction = addition with negated second operand)
        let diff: Point = ecAdd(contract.r_a, ecNegate(contract.r_b));

        // delta_o * G (scalar multiplication of generator)
        let expected: Point = ecMulGen(delta_o);

        // Assert point equality via coordinate comparison
        assert!(ecPointX(diff) == ecPointX(expected), 0);
        assert!(ecPointY(diff) == ecPointY(expected), 0);
    }
}
