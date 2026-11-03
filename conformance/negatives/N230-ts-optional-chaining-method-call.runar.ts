// N-121 (user decision R85): `this?.check(x)` is optional chaining on a private
// method call. TS and Go compiled it as `this.check(x)`; every tier must refuse
// it with the shared diagnostic, located at the `?` of `?.`.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public unlock(x: bigint) {
    assert(this?.check(x));
  }

  private check(x: bigint): boolean {
    return x === this.t;
  }
}
