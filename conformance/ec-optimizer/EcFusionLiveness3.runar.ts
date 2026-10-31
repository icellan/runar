import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-460 — part 3 of the EcFusionLiveness fixtures; the rationale is in
 * EcFusionLiveness1.runar.ts. The last two shapes no fusion may grow, then
 * the three positive controls that must still fuse.
 */
export class EcFusionLiveness3 extends SmartContract {
  constructor() {
    super();
  }

  /** R11, both inner calls bound outside the if arm: flag = 1 -> 5q, else q. */
  public r11OuterBothNested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    const a: Point = ecMul(q, 2n);
    const b: Point = ecMul(q, 3n);
    let r: Point = q;
    if (flag === 1n) {
      r = ecAdd(a, b);
    }
    assert(ecPointX(r) === ex);
  }

  /** R11, a outside the arm, b inside and read again: flag = 1 -> 5q, else q. */
  public r11OuterANestedBLive(p: Point, flag: bigint, ex: bigint, ey: bigint) {
    const q: Point = p;
    const a: Point = ecMul(q, 2n);
    let r: Point = q;
    if (flag === 1n) {
      const b: Point = ecMul(q, 3n);
      r = ecAdd(a, b);
      assert(ecPointY(b) === ey);
    }
    assert(ecPointX(r) === ex);
  }

  /** Positive control, R10 with a read again: r = 5G, b goes. */
  public r10LeftLive(ex: bigint, ey: bigint) {
    const a: Point = ecMulGen(2n);
    const b: Point = ecMulGen(3n);
    const r: Point = ecAdd(a, b);
    assert(ecPointX(r) === ex && ecPointY(a) === ey);
  }

  /** Positive control, R11 with a read again: r = 5q, b goes. */
  public r11LeftLive(p: Point, ex: bigint, ey: bigint) {
    const q: Point = p;
    const a: Point = ecMul(q, 2n);
    const b: Point = ecMul(q, 3n);
    const r: Point = ecAdd(a, b);
    assert(ecPointX(r) === ex && ecPointY(a) === ey);
  }

  /** Positive control, R10 in an if arm with ecMulGen bound outside it: flag = 1 -> 5G, else q. */
  public r10OuterNested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    const a: Point = ecMulGen(2n);
    const b: Point = ecMulGen(3n);
    let r: Point = q;
    if (flag === 1n) {
      r = ecAdd(a, b);
    }
    assert(ecPointX(r) === ex);
  }
}
