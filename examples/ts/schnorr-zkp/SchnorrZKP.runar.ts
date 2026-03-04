import {
  SmartContract, assert,
  ecAdd, ecMul, ecMulGen, ecPointX, ecPointY, ecOnCurve, ecModReduce,
  EC_N,
} from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * Schnorr Zero-Knowledge Proof verifier.
 *
 * Proves knowledge of a private key `k` such that `P = k*G` without
 * revealing `k`. Uses the Schnorr identification protocol:
 *
 *   Prover: picks random r, sends R = r*G
 *   Verifier: sends challenge e
 *   Prover: sends s = r + e*k (mod n)
 *   Verifier: checks s*G === R + e*P
 *
 * In a Bitcoin contract context, the prover provides (R, s, e) in the
 * unlocking script, and the contract verifies the proof on-chain.
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
   * @param e      - The challenge value
   */
  public verify(rPoint: Point, s: bigint, e: bigint) {
    // Verify R is on the curve
    assert(ecOnCurve(rPoint));

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
