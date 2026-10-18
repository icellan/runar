// N-325: a public method parameter whose type annotation names a type that
// does not exist. Before the fix every tier accepted it (the parameter is
// unused here, so no call-site mismatch can refuse it incidentally).
import { SmartContract, assert } from 'runar-lang';

class PublicParamUnknownType extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public verify(a: bigint, c: TTT) {
    assert(a === this.t);
  }
}
