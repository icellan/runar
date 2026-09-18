// R-037 — BabyBear field arithmetic. Go-only by project policy.
import { SmartContract, assert, bbFieldMul } from 'runar-lang';

export class GoOnlyBabyBear extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
