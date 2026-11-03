import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-113 — the EC optimizer's fusing rules shrink the script.
 *
 * R9 `ecMul(ecMul(q, k1), k2) -> ecMul(q, k1*k2)`, R10
 * `ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2)` and R11
 * `ecAdd(ecMul(q, k1), ecMul(q, k2)) -> ecMul(q, k1+k2)` used to leave the
 * inner calls they orphan in the script (an EC call was never dead-code
 * eliminated), so R10/R11 grew a method by ~400 KB. Each method below uses the
 * alias form `const q: Point = p` because the rules match on binding identity:
 * two reads of a parameter are two different bindings, and nothing fires.
 *
 * `crossScope` is the negative: its outer `ecMul(q, 2n)` runs on every path,
 * and the fusion happens inside the `if` arm only, so the outer call (and its
 * on-curve gate on q) must survive even though nothing references it.
 */
export class EcFusionDce extends SmartContract {
  constructor() {
    super();
  }

  /** R9 at top level: r = 6q. */
  public r9Top(p: Point, ex: bigint) {
    const q: Point = p;
    const r: Point = ecMul(ecMul(q, 2n), 3n);
    assert(ecPointX(r) === ex);
  }

  /** R9 chained twice: r = 30q. */
  public r9Chain(p: Point, ex: bigint) {
    const q: Point = p;
    const r: Point = ecMul(ecMul(ecMul(q, 2n), 3n), 5n);
    assert(ecPointX(r) === ex);
  }

  /** R10 at top level: r = 5G. */
  public r10Top(ex: bigint) {
    const r: Point = ecAdd(ecMulGen(2n), ecMulGen(3n));
    assert(ecPointX(r) === ex);
  }

  /** R11 at top level: r = 5q. */
  public r11Top(p: Point, ex: bigint) {
    const q: Point = p;
    const r: Point = ecAdd(ecMul(q, 2n), ecMul(q, 3n));
    assert(ecPointX(r) === ex);
  }

  /** R9 inside an if arm: flag = 1 -> 6q, else q. */
  public r9Nested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    let r: Point = q;
    if (flag === 1n) {
      r = ecMul(ecMul(q, 2n), 3n);
    }
    assert(ecPointX(r) === ex);
  }

  /** R10 inside an if arm: flag = 1 -> 5G, else q. */
  public r10Nested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    let r: Point = q;
    if (flag === 1n) {
      r = ecAdd(ecMulGen(2n), ecMulGen(3n));
    }
    assert(ecPointX(r) === ex);
  }

  /** R11 inside an if arm: flag = 1 -> 5q, else q. */
  public r11Nested(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    let r: Point = q;
    if (flag === 1n) {
      r = ecAdd(ecMul(q, 2n), ecMul(q, 3n));
    }
    assert(ecPointX(r) === ex);
  }

  /** Outer ecMul(q, 2n) gates q on both paths; flag = 1 -> 5q, else q. */
  public crossScope(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    const a: Point = ecMul(q, 2n);
    let r: Point = q;
    if (flag === 1n) {
      r = ecAdd(a, ecMul(q, 3n));
    }
    assert(ecPointX(r) === ex);
  }
}
