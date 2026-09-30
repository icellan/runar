// F-075: Crit-3 (`requireOutputP2PKH` mixed with `addDataOutput`) must see a
// `requireOutputP2PKH` call that sits inside a private helper.
//
// The direct form is refused as Crit-3. Before F-075 this form compiled,
// because the guard only walked the public method's own body while ANF
// lowering inlines the helper and the side-effect summary injects the
// continuation as if the call were in the public body.

import { StatefulSmartContract, assert, requireOutputP2PKH } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P2PKHViaHelperWithDataOutput extends StatefulSmartContract {
  count: bigint;
  readonly bondPKH: ByteString;
  readonly bond: bigint;

  constructor(count: bigint, bondPKH: ByteString, bond: bigint) {
    super(count, bondPKH, bond);
    this.count = count;
    this.bondPKH = bondPKH;
    this.bond = bond;
  }

  private assertBond(): void {
    requireOutputP2PKH(0n, this.bondPKH, this.bond);
  }

  public go(payload: ByteString) {
    this.addDataOutput(0n, payload);
    this.assertBond();
    assert(true);
  }
}
