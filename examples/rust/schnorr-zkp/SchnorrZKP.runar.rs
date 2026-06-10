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
///
/// WARNING — nonce reuse is fatal. Two proofs (s1, s2) over different
/// challenges (e1, e2) that share the same nonce r leak the secret key:
///     k = (e1 - e2)^{-1} * (s1 - s2) mod n
/// The contract cannot detect cross-proof nonce reuse; the prover MUST
/// sample a fresh, uniformly random r for every proof.
#[runar::contract]
pub struct SchnorrZKP {
    #[readonly]
    pub pub_key: Point,
}

impl SchnorrZKP {
    /// Verify a Schnorr ZKP proof.
    ///
    /// - `r_point` - The commitment R = r*G (prover's nonce point)
    /// - `s` - The response s = r + e*k (mod n)
    pub fn verify(&self, r_point: &Point, s: Bigint) {
        // Bound s to the canonical range [1, n) where n is the secp256k1
        // group order (malleability gate). Inlined as a decimal literal so
        // every frontend lowers it to the same bigint_literal ANF node
        // (sol/move/go/rust/zig all lex 0x... as a ByteString literal).
        // Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert!(within(s, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494337));

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
