// N-325: a constructor parameter whose type annotation names a type that does
// not exist. Before the fix every tier accepted it.
import { SmartContract, assert } from 'runar-lang';

class CtorParamUnknownType extends SmartContract {
  readonly t: bigint;

  constructor(t: TTT) {
    super(t);
    this.t = t;
  }

  public verify(a: bigint) {
    assert(a === this.t);
  }
}
