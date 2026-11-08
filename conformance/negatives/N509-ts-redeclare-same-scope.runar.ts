// N-509 — a local re-declared in the same scope. spec/grammar.md: a variable
// cannot be re-declared in the same scope. Every tier refuses:
//   'a' is already declared in this scope and cannot be re-declared
import { SmartContract, assert } from 'runar-lang';

class N509 extends SmartContract {
  readonly k: bigint;

  constructor(k: bigint) {
    super(k);
    this.k = k;
  }

  public unlock(p: bigint) {
    const a = p + 1n;
    const a = p + 2n;
    assert(a == this.k);
  }
}
