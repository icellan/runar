// R-037 — KoalaBear field arithmetic. Go-only by project policy.
import { SmartContract, assert, kbFieldMul } from 'runar-lang';

export class GoOnlyKoalaBear extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(kbFieldMul(a, b) === this.expected);
  }
}
