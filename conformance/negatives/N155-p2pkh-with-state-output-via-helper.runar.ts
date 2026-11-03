// F-075: the R-300 guard (`requireOutputP2PKH` mixed with a state output) must
// see an `addOutput` call that sits inside a private helper.
//
// The direct form (N34) is refused. Before F-075 this form compiled, because
// the guard only walked the public method's own body while ANF lowering
// inlines the helper's `addOutput`, putting the continuation at output 0 where
// `requireOutputP2PKH(0, ...)` demands a 34-byte P2PKH.

import { StatefulSmartContract, assert, requireOutputP2PKH } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P2PKHWithStateOutputViaHelper extends StatefulSmartContract {
  count: bigint;
  readonly bondPKH: ByteString;
  readonly bond: bigint;

  constructor(count: bigint, bondPKH: ByteString, bond: bigint) {
    super(count, bondPKH, bond);
    this.count = count;
    this.bondPKH = bondPKH;
    this.bond = bond;
  }

  private emitNext(): void {
    this.addOutput(1000n, this.count + 1n);
  }

  public go() {
    this.emitNext();
    requireOutputP2PKH(0n, this.bondPKH, this.bond);
    assert(true);
  }
}
