// F-091 — bn254G1Add on the omega-partner pair. BN254 has j-invariant 0 and
// p = 1 mod 3, so (w*px, -py) is an ordinary curve point that zeroes the
// unified slope's denominator py + qy while px != qx. Every tier used to
// answer that 0/0 slope with a WRONG but ON-CURVE point; the builtin now
// aborts there. The parity leg pins the bytes to Go; the execution leg in
// go-only-parity.test.ts runs each tier's script on @bsv/sdk's Spend.
import { SmartContract, assert, bn254G1Add } from 'runar-lang';
import type { ByteString, Point } from 'runar-lang';

export class GoOnlyBn254G1Add extends SmartContract {
  constructor() { super(); }
  public verify(p: Point, q: Point, expected: ByteString) {
    assert(bn254G1Add(p, q) === expected);
  }
}
