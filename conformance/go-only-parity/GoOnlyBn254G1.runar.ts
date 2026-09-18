// R-141 — the BN254 G1 POINT surface, as opposed to GoOnlyBn254's field
// surface. `bn254G1OnCurve` had no coordinate-canonicity guard and
// `bn254DecomposePoint` had no OP_SIZE-64 gate, so the predicate answered TRUE
// for `(x+p) || y`, for `x || (y+p)` and for a 65-byte blob; `bn254G1Negate`
// re-emitted the non-canonical x verbatim. Both gates landed in six tiers at
// once, and nothing else in this repository compares those six on a G1 POINT
// builtin — the existing probe only exercises `bn254FieldMul`.
import { SmartContract, assert, bn254G1OnCurve, bn254G1Negate } from 'runar-lang';
import type { ByteString, Point } from 'runar-lang';

export class GoOnlyBn254G1 extends SmartContract {
  readonly expected: ByteString;
  constructor(expected: ByteString) { super(expected); this.expected = expected; }
  public verify(p: Point) {
    assert(bn254G1OnCurve(p));
    assert(bn254G1Negate(p) === this.expected);
  }
}
