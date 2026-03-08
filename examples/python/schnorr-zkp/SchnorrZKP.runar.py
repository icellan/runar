"""Schnorr Zero-Knowledge Proof verifier.

Proves knowledge of a private key k such that P = k*G without
revealing k. Uses the Schnorr identification protocol:

    Prover: picks random r, sends R = r*G
    Verifier: sends challenge e
    Prover: sends s = r + e*k (mod n)
    Verifier: checks s*G === R + e*P

In a Bitcoin contract context, the prover provides (R, s, e) in the
unlocking script, and the contract verifies the proof on-chain.
"""
from runar import (
    SmartContract, Point, Bigint, public, assert_,
    ec_add, ec_mul, ec_mul_gen, ec_point_x, ec_point_y, ec_on_curve,
)

class SchnorrZKP(SmartContract):
    """Verifies Schnorr ZKP proofs on-chain."""

    pub_key: Point

    def __init__(self, pub_key: Point):
        super().__init__(pub_key)
        self.pub_key = pub_key

    @public
    def verify(self, r_point: Point, s: Bigint, e: Bigint):
        """Verify a Schnorr ZKP proof.

        Args:
            r_point: The commitment R = r*G (prover's nonce point).
            s: The response s = r + e*k (mod n).
            e: The challenge value.
        """
        # Verify R is on the curve
        assert_(ec_on_curve(r_point))

        # Left side: s*G
        s_g = ec_mul_gen(s)

        # Right side: R + e*P
        e_p = ec_mul(self.pub_key, e)
        rhs = ec_add(r_point, e_p)

        # Verify equality
        assert_(ec_point_x(s_g) == ec_point_x(rhs))
        assert_(ec_point_y(s_g) == ec_point_y(rhs))
