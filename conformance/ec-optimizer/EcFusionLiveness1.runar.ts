import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-460 — a fusing rule (R9, R10, R11) fires only when the fusion removes a
 * scalar multiplication.
 *
 * A fusion replaces the outer call with ONE new multiplication. It shrinks the
 * script only if the N-113 post-pass can then drop an inner call it read: an
 * inner call still read elsewhere stays, and so does an `ecMul` bound outside
 * the fusion's scope (its only witness, the fused call, is nested) and an
 * `ecMulGen` bound outside an enclosing loop (the fusion would multiply once
 * per iteration; the guard refuses at any trip count, though at two it would
 * still have shrunk). Across the three fixtures, the first eight methods are
 * those shapes: none fuses. The last three are positive controls that must
 * still fuse: one inner call stays live but the other goes, or the inner
 * calls are ecMulGen bound outside an if arm.
 *
 * Alias form (`const q: Point = p`) as in EcFusionDce: the rules match on
 * binding identity. The eleven methods are split over EcFusionLiveness1-3 so
 * each script stays under ScriptVM's 4 MB limit; this file holds the R9 shapes
 * and R10 with both inner calls read again.
 */
export class EcFusionLiveness1 extends SmartContract {
  constructor() {
    super();
  }

  /** R9, inner read again: r = 6q, t = 2q. */
  public r9InnerLive(p: Point, ex: bigint, ey: bigint) {
    const q: Point = p;
    const t: Point = ecMul(q, 2n);
    const r: Point = ecMul(t, 3n);
    assert(ecPointX(r) === ex && ecPointY(t) === ey);
  }

  /** R9, inner bound outside the if arm: flag = 1 -> 6q, else q. */
  public r9OuterNested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    const t: Point = ecMul(q, 2n);
    let r: Point = q;
    if (flag === 1n) {
      r = ecMul(t, 3n);
    }
    assert(ecPointX(r) === ex);
  }

  /** R10, both inner calls read again: r = 5G. */
  public r10BothLive(ex: bigint, ey2: bigint, ey3: bigint) {
    const a: Point = ecMulGen(2n);
    const b: Point = ecMulGen(3n);
    const r: Point = ecAdd(a, b);
    assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);
  }
}
