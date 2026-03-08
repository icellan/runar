"""OPRF-based fraud signal convergence proof.

Two parties submit randomized tokens R_A = (T + o_A)*G and R_B = (T + o_B)*G
where T is the shared underlying token and o_A, o_B are ECDH-derived offsets.

An authority who knows both offsets can prove the two submissions share the
same token T by providing delta_o = o_A - o_B and verifying:

    R_A - R_B = delta_o * G

The token T cancels out in the subtraction, proving convergence without
revealing T. Spending this UTXO serves as a formal on-chain subpoena trigger.
"""
from runar import (
    SmartContract, Point, Bigint, public, assert_,
    ec_add, ec_negate, ec_mul_gen, ec_point_x, ec_point_y, ec_on_curve,
)

class ConvergenceProof(SmartContract):
    """Verifies that two OPRF-randomized tokens share the same underlying value."""

    r_a: Point
    r_b: Point

    def __init__(self, r_a: Point, r_b: Point):
        super().__init__(r_a, r_b)
        self.r_a = r_a
        self.r_b = r_b

    @public
    def prove_convergence(self, delta_o: Bigint):
        """Prove convergence via offset difference.

        Args:
            delta_o: The offset difference o_A - o_B (mod n), provided by the authority.
        """
        # Verify both committed points are on the curve
        assert_(ec_on_curve(self.r_a))
        assert_(ec_on_curve(self.r_b))

        # R_A - R_B (point subtraction = addition with negated second operand)
        diff = ec_add(self.r_a, ec_negate(self.r_b))

        # delta_o * G (scalar multiplication of generator)
        expected = ec_mul_gen(delta_o)

        # Assert point equality via coordinate comparison
        assert_(ec_point_x(diff) == ec_point_x(expected))
        assert_(ec_point_y(diff) == ec_point_y(expected))
