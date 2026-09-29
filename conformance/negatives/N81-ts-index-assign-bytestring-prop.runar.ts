// N-002: an index assignment is only a write when its root is a FixedArray
// contract property. Pre-fix TS, Go, Rust and Zig lowered this target as a
// READ, dropping the write, and emitted a deployable script whose state never
// changes (Python refused it since F-013; Ruby and Java failed late on an
// internal __array_access). Every tier must refuse in the validator with:
//   index assignment is only supported on FixedArray contract properties;
//   the target here is not a FixedArray property
// Shape: a literal-index write to a ByteString property.
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class Blob extends StatefulSmartContract {
  blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public poke(i: bigint) {
    this.blob[0n] = 7n;
    assert(true);
  }
}
