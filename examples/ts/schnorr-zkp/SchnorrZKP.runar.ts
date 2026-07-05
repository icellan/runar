import {
  SmartContract, assert, within,
  ecAdd, ecMul, ecMulGen, ecPointX, ecPointY, ecOnCurve, ecModReduce,
  hash256, cat, bin2num,
} from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * Schnorr Zero-Knowledge Proof verifier (non-interactive, Fiat-Shamir).
 *
 * Proves knowledge of a private key `k` such that `P = k*G` without
 * revealing `k`. Uses the Schnorr identification protocol with the
 * Fiat-Shamir heuristic to derive the challenge on-chain:
 *
 *   Prover: picks random r, computes R = r*G
 *   Challenge: e = bin2num(hash256(R || P))  (derived on-chain)
 *   Prover: sends s = r + e*k (mod n)
 *   Verifier: checks s*G === R + e*P
 *
 * The challenge is derived deterministically from the commitment and
 * public key, preventing the prover from choosing a convenient e.
 *
 * WARNING — this is a proof of KNOWLEDGE, not a spend authorization, and it
 * is REPLAYABLE. The challenge e = hash256(R || P) binds the witness to the
 * commitment and public key but NOT to the spending transaction. A valid
 * (rPoint, s) pair is therefore a bearer credential: once it appears on-chain,
 * any observer can replay the same (rPoint, s) to satisfy any other UTXO that
 * carries an identical `SchnorrZKP` locking script (same `pubKey`). Do NOT use
 * this contract as a standalone spend gate. To bind a proof to a particular
 * spend, fold the sighash/preimage into the challenge
 * (e = hash256(R || P || sighash)) so a witness is valid for exactly one tx.
 *
 * WARNING — nonce reuse is fatal. The contract verifies a single
 * non-interactive proof; it cannot detect that two proofs (sig1, sig2)
 * over different challenges (e1, e2) reuse the same nonce r. When a
 * prover reuses r across two proofs the secret key is recoverable by
 * any observer as k = (e1 - e2)^{-1} * (s1 - s2) mod n. The prover MUST
 * sample a fresh, uniformly random r for every proof. This is a
 * use-the-API-correctly responsibility of the proof generator; see
 * SchnorrZKP.test.ts ("nonce reuse off-chain key recovery") for the
 * canonical demonstration.
 */
class SchnorrZKP extends SmartContract {
  readonly pubKey: Point;

  constructor(pubKey: Point) {
    super(pubKey);
    this.pubKey = pubKey;
  }

  /**
   * Verify a Schnorr ZKP proof.
   *
   * @param rPoint - The commitment R = r*G (prover's nonce point)
   * @param s      - The response s = r + e*k (mod n)
   */
  public verify(rPoint: Point, s: bigint) {
    // Bound s to the canonical range [1, n) where n is the secp256k1 group
    // order. EC scalars are intentionally not reduced mod n inside the
    // primitives (k*G == (k + n)*G), so without this bound `s` and `s + n`
    // would both verify, opening a malleability surface where any forwarded
    // valid proof can be silently rewritten. The group order is inlined
    // here as a decimal literal so every frontend (sol/move/go/rust/zig all
    // lex `0x...` as a ByteString literal, not a bigint) lowers it to the
    // same `bigint_literal` ANF node and produces byte-identical hex.
    // Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert(within(
      s,
      1n,
      115792089237316195423570985008687907852837564279074904382605163141518161494337n,
    ));

    // Verify R is on the curve
    assert(ecOnCurve(rPoint));

    // Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P))
    const e = bin2num(hash256(cat(rPoint, this.pubKey)));

    // Left side: s*G
    const sG = ecMulGen(s);

    // Right side: R + e*P
    const eP = ecMul(this.pubKey, e);
    const rhs = ecAdd(rPoint, eP);

    // Verify equality
    assert(ecPointX(sG) === ecPointX(rhs));
    assert(ecPointY(sG) === ecPointY(rhs));
  }
}
