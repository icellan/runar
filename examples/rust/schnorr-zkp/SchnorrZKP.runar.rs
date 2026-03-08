use runar::prelude::*;

/// Schnorr zero-knowledge proof verifier.
///
/// Proves knowledge of a private key `k` such that `P = k*G` without
/// revealing `k`. Uses the Schnorr identification protocol:
///
/// ```text
/// Prover: picks random r, sends R = r*G
/// Verifier: sends challenge e
/// Prover: sends s = r + e*k (mod n)
/// Verifier: checks s*G === R + e*P
/// ```
///
/// In a Bitcoin contract context, the prover provides (R, s, e) in the
/// unlocking script, and the contract verifies the proof on-chain.
#[runar::contract]
pub struct SchnorrZKP {
    #[readonly]
    pub pub_key: Point,
}

#[runar::methods(SchnorrZKP)]
impl SchnorrZKP {
    /// Verify a Schnorr ZKP proof.
    ///
    /// - `r_point` - The commitment R = r*G (prover's nonce point)
    /// - `s` - The response s = r + e*k (mod n)
    /// - `e` - The challenge value
    #[public]
    pub fn verify(&self, r_point: &Point, s: Bigint, e: Bigint) {
        // Verify R is on the curve
        assert!(ec_on_curve(r_point));

        // Left side: s*G
        let s_g = ec_mul_gen(s);

        // Right side: R + e*P
        let e_p = ec_mul(&self.pub_key, e);
        let rhs = ec_add(r_point, &e_p);

        // Verify equality
        assert!(ec_point_x(&s_g) == ec_point_x(&rhs));
        assert!(ec_point_y(&s_g) == ec_point_y(&rhs));
    }
}
