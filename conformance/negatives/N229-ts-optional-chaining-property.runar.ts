// N-121 (user decision R85): optional chaining is disallowed (spec/grammar.md).
// TS and Go compiled `this?.t` as `this.t`; the other five tiers refused it,
// each in its own words. Every tier must refuse it with the shared diagnostic
//   optional chaining '?.' is not supported
// located at the `?` of `?.`.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public unlock(x: bigint) {
    assert(x === this?.t);
  }
}
