import { SmartContract, assert, ecAdd, ecMul, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-465 — R9 readers that share one inner `ecMul` all fuse.
 *
 * N-460 let a fusing rule fire only when an inner call can then be removed,
 * counting every reader of that inner call. Two R9 readers `ecMul(g, 2n)` and
 * `ecMul(g, 3n)` of one `g = ecMul(q, 7n)` each saw the other as a reader, so
 * neither fused and g stayed. They fire together in one sweep, and each fused
 * `ecMul(q, _)` is then g's witness, so g goes. These two methods are the
 * shared-inner shapes N-460 gave up; see ec-fusion-liveness.test.ts.
 */
export class EcFusionLiveness4 extends SmartContract {
  constructor() {
    super();
  }

  /** R9 twice, then R11 on the results: one multiplication, 35q. */
  public r9SharedThenR11(p: Point, ex: bigint) {
    const q: Point = p;
    const g: Point = ecMul(q, 7n);
    const r: Point = ecAdd(ecMul(g, 2n), ecMul(g, 3n));
    assert(ecPointX(r) === ex);
  }

  /** Two R9 readers, both read: r = 14q, s = 21q, and g goes. */
  public r9SharedTwoReaders(p: Point, ex: bigint, ey: bigint) {
    const q: Point = p;
    const g: Point = ecMul(q, 7n);
    const r: Point = ecMul(g, 2n);
    const s: Point = ecMul(g, 3n);
    assert(ecPointX(r) === ex && ecPointX(s) === ey);
  }
}
