import {
  SmartContract, assert,
  ecAdd, ecMul, ecMulGen, ecPointX, ecPointY, ecOnCurve, ecModReduce,
  EC_N, hash256, cat, bin2num,
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
