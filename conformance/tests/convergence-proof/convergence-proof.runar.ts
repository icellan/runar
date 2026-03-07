import {
  SmartContract, assert,
  ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY, ecOnCurve,
} from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * OPRF-based fraud signal convergence proof.
 *
 * Two parties submit randomized tokens R_A = (T + o_A)·G and R_B = (T + o_B)·G
 * where T is the shared underlying token and o_A, o_B are ECDH-derived offsets.
 *
 * An authority who knows both offsets can prove the two submissions share the
 * same token T by providing Δo = o_A - o_B and verifying:
 *
 *   R_A - R_B = Δo · G
 *
 * The token T cancels out in the subtraction, proving convergence without
 * revealing T. Spending this UTXO serves as a formal on-chain subpoena trigger.
 */
class ConvergenceProof extends SmartContract {
  readonly rA: Point;
  readonly rB: Point;

  constructor(rA: Point, rB: Point) {
    super(rA, rB);
    this.rA = rA;
    this.rB = rB;
  }

  /**
   * Prove convergence via offset difference.
   *
   * @param deltaO - The offset difference o_A - o_B (mod n), provided by authority
   */
  public proveConvergence(deltaO: bigint) {
    // Verify both committed points are on the curve
    assert(ecOnCurve(this.rA));
    assert(ecOnCurve(this.rB));

    // R_A - R_B (point subtraction = addition with negated second operand)
    const diff = ecAdd(this.rA, ecNegate(this.rB));

    // Δo · G (scalar multiplication of generator)
    const expected = ecMulGen(deltaO);

    // Assert point equality via coordinate comparison
    assert(ecPointX(diff) === ecPointX(expected));
    assert(ecPointY(diff) === ecPointY(expected));
  }
}
