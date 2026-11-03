import { SmartContract, assert } from 'runar-lang';

// F-208: Rúnar has no first-class functions. A bound local variable used as
// a callee fell into the typechecker's "local variable" branch and returned
// "<unknown>" with NO diagnostic in all seven tiers, silently accepting
// `const f: bigint = a; const r = f(a, a, a);`. Every tier must refuse it.
export class N194 extends SmartContract {
  readonly a: bigint;
  constructor(a: bigint) { super(a); this.a = a; }
  public check(a: bigint) {
    const f: bigint = a;
    const r = f(a, a, a);
    assert(this.a >= 0n);
  }
}
