// R-037 — BN254 field arithmetic. Go-only by project policy.
import { SmartContract, assert, bn254FieldMul } from 'runar-lang';

export class GoOnlyBn254 extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bn254FieldMul(a, b) === this.expected);
  }
}
