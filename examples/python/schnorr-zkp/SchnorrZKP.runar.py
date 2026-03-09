"""Schnorr Zero-Knowledge Proof verifier (non-interactive, Fiat-Shamir).

Proves knowledge of a private key k such that P = k*G without
revealing k. Uses the Schnorr identification protocol with the
Fiat-Shamir heuristic to derive the challenge on-chain:

    Prover: picks random r, computes R = r*G
    Challenge: e = bin2num(hash256(R || P))  (derived on-chain)
    Prover: sends s = r + e*k (mod n)
    Verifier: checks s*G === R + e*P

The challenge is derived deterministically from the commitment and
public key, preventing the prover from choosing a convenient e.
"""
from runar import (
    SmartContract, Point, Bigint, public, assert_,
    ec_add, ec_mul, ec_mul_gen, ec_point_x, ec_point_y, ec_on_curve,
    hash256, cat, bin2num,
)

class SchnorrZKP(SmartContract):
    """Verifies Schnorr ZKP proofs on-chain."""

    pub_key: Point

    def __init__(self, pub_key: Point):
        super().__init__(pub_key)
        self.pub_key = pub_key

    @public
    def verify(self, r_point: Point, s: Bigint):
        """Verify a Schnorr ZKP proof.

        Args:
            r_point: The commitment R = r*G (prover's nonce point).
            s: The response s = r + e*k (mod n).
        """
        # Verify R is on the curve
        assert_(ec_on_curve(r_point))

        # Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P))
        e = bin2num(hash256(cat(r_point, self.pub_key)))

        # Left side: s*G
        s_g = ec_mul_gen(s)

        # Right side: R + e*P
        e_p = ec_mul(self.pub_key, e)
        rhs = ec_add(r_point, e_p)

        # Verify equality
        assert_(ec_point_x(s_g) == ec_point_x(rhs))
        assert_(ec_point_y(s_g) == ec_point_y(rhs))
