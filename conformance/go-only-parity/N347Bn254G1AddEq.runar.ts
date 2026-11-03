// N-347 — `===` on two builtin results, neither a parameter nor a property, so pass 4
// can only learn they are byte strings from the builtin's return type:
//   bn254G1Add(p, q) === bn254G1Add(q, p)
// See the N-347 describe block in go-only-parity.test.ts.
import { SmartContract, assert, bn254G1Add } from 'runar-lang';
import type { Point } from 'runar-lang';

export class N347Bn254G1AddEq extends SmartContract {
  constructor() { super(); }
  public verify(p: Point, q: Point) {
    assert(bn254G1Add(p, q) === bn254G1Add(q, p));
  }
}
