import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-460 — part 2 of the EcFusionLiveness fixtures; the rationale is in
 * EcFusionLiveness1.runar.ts. More shapes no fusion may grow.
 */
export class EcFusionLiveness2 extends SmartContract {
  constructor() {
    super();
  }

  /** R10 through an alias, both inner calls read again: r = 5G. */
  public r10BothLiveAlias(ex: bigint, ey2: bigint, ey3: bigint) {
    const a: Point = ecMulGen(2n);
    const b: Point = ecMulGen(3n);
    const a2: Point = a;
    const r: Point = ecAdd(a2, b);
    assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);
  }

  /** R10 inside a loop, inner calls bound outside it: r = q + 15G. */
  public r10OuterLoop(p: Point, ex: bigint) {
    const q: Point = p;
    const a: Point = ecMulGen(2n);
    const b: Point = ecMulGen(3n);
    let r: Point = q;
    for (let i = 0n; i < 3n; i++) {
      r = ecAdd(r, ecAdd(a, b));
    }
    assert(ecPointX(r) === ex);
  }

  /** R11, both inner calls read again: r = 5q. */
  public r11BothLive(p: Point, ex: bigint, ey2: bigint, ey3: bigint) {
    const q: Point = p;
    const a: Point = ecMul(q, 2n);
    const b: Point = ecMul(q, 3n);
    const r: Point = ecAdd(a, b);
    assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);
  }
}
