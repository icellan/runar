// N-347 — `===` on two builtin results, neither a parameter nor a property, so pass 4
// can only learn they are byte strings from the builtin's return type:
//   bn254G1ScalarMul(p, k) === bn254G1ScalarMul(q, k)
// See the N-347 describe block in go-only-parity.test.ts.
import { SmartContract, assert, bn254G1ScalarMul } from 'runar-lang';
import type { Point } from 'runar-lang';

export class N347Bn254G1ScalarMulEq extends SmartContract {
  constructor() { super(); }
  public verify(p: Point, q: Point, k: bigint) {
    assert(bn254G1ScalarMul(p, k) === bn254G1ScalarMul(q, k));
  }
}
