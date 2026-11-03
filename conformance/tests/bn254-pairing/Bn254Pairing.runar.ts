import { SmartContract, assert, bn254MultiPairing4 } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * Bn254Pairing -- N-314: the first conformance fixture that runs the BN254
 * pairing codegen. It asserts that a product of four optimal-ate pairings is
 * the identity in GT:
 *
 *   e(p1, q1) * e(p2, q2) * e(p3, q3) * e(p4, q4) == 1
 *
 * which is the Groth16 verification equation in the SP1 rearrangement
 * (A, B), (L, -gamma), (C, -delta), (alpha, -beta). Every pair is a spend
 * argument and there is no constructor, so the compiled golden IS the
 * locking script. BN254 codegen is Go-only by project policy.
 */
class Bn254Pairing extends SmartContract {
  constructor() {
    super();
  }

  public verify(
    p1: Point, q1x0: bigint, q1x1: bigint, q1y0: bigint, q1y1: bigint,
    p2: Point, q2x0: bigint, q2x1: bigint, q2y0: bigint, q2y1: bigint,
    p3: Point, q3x0: bigint, q3x1: bigint, q3y0: bigint, q3y1: bigint,
    p4: Point, q4x0: bigint, q4x1: bigint, q4y0: bigint, q4y1: bigint,
  ) {
    assert(bn254MultiPairing4(
      p1, q1x0, q1x1, q1y0, q1y1,
      p2, q2x0, q2x1, q2y0, q2y1,
      p3, q3x0, q3x1, q3y0, q3y1,
      p4, q4x0, q4x1, q4y0, q4y1,
    ));
  }
}
