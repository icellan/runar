// N-323: a local `let` whose type annotation names a type that does not exist.
// Go, TS, Rust, Python, Ruby and Java refuse it ("type 'bigint' is not
// assignable to type 'TTT'"); the Zig tier accepted it because its parsers
// collapse every unrecognised type name to `unknown`, which is a subtype of
// everything.
import { SmartContract, assert } from 'runar-lang';

class LocalUnknownType extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public verify(a: bigint) {
    let q: TTT = a;
    assert(q === this.t);
  }
}
