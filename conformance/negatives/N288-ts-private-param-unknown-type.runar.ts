// N-325: a private method parameter whose type annotation names a type that
// does not exist. The helper is never called, so no call-site mismatch can
// refuse it incidentally. Before the fix every tier accepted it.
import { SmartContract, assert } from 'runar-lang';

class PrivateParamUnknownType extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  private helper(x: TTT): bigint {
    return 1n;
  }

  public verify(a: bigint) {
    assert(a === this.t);
  }
}
