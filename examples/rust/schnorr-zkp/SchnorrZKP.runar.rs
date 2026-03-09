use runar::prelude::*;

/// Schnorr zero-knowledge proof verifier (non-interactive, Fiat-Shamir).
///
/// Proves knowledge of a private key `k` such that `P = k*G` without
/// revealing `k`. Uses the Schnorr identification protocol with the
/// Fiat-Shamir heuristic to derive the challenge on-chain:
///
/// ```text
/// Prover: picks random r, computes R = r*G
/// Challenge: e = bin2num(hash256(R || P))  (derived on-chain)
/// Prover: sends s = r + e*k (mod n)
/// Verifier: checks s*G === R + e*P
/// ```
///
/// The challenge is derived deterministically from the commitment and
/// public key, preventing the prover from choosing a convenient e.
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
    #[public]
    pub fn verify(&self, r_point: &Point, s: Bigint) {
        // Verify R is on the curve
        assert!(ec_on_curve(r_point));

        // Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P))
        let e = bin2num(&hash256(&cat(r_point, &self.pub_key)));

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
