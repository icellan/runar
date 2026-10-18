// N-331: a private method whose RETURN type annotation names a type that does
// not exist. The helper is never called and its parameters are valid, so only
// the return type can refuse it. Before the fix every tier accepted it.
import { SmartContract, assert } from 'runar-lang';

class PrivateReturnUnknownType extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  private helper(x: bigint): TTT {
    return 1n;
  }

  public verify(a: bigint) {
    assert(a === this.t);
  }
}
