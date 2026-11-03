// N-002: an index assignment is only a write when its root is a FixedArray
// contract property. Pre-fix TS, Go, Rust and Zig lowered this target as a
// READ, dropping the write, and emitted a deployable script whose state never
// changes (Python refused it since F-013; Ruby and Java failed late on an
// internal __array_access). Every tier must refuse in the validator with:
//   index assignment is only supported on FixedArray contract properties;
//   the target here is not a FixedArray property
// Shape: a write to a local ByteString and to a ByteString parameter.
import { SmartContract, ByteString, assert } from 'runar-lang';

class Loc extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    let c: ByteString = b;
    c[0n] = 7n;
    b[1n] = 7n;
    assert(c == this.h);
  }
}
