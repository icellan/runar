// R-050 — three different designs for whether a nested block inherits the
// side-effect summary. A stateful method calling a private OUTPUT-EMITTING
// helper from inside an `if` is the shape that separated them.
import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class NestedHelper extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  private emit(payload: ByteString) {
    this.addDataOutput(0n, payload);
  }

  public go(flag: bigint, payload: ByteString) {
    this.count = this.count + 1n;
    if (flag > 0n) {
      this.emit(payload);
    }
    assert(true);
  }
}
