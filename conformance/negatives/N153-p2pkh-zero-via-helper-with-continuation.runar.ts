// F-075: `requireOutputP2PKH(0, ...)` moved into a private helper must be
// refused exactly like the direct call.
//
// The public method mutates state and emits no explicit output, so the
// auto-injected single-output continuation puts the contract's own codePart at
// output 0. `requireOutputP2PKH(0, ...)` then demands that same output be a
// 34-byte P2PKH, which no transaction satisfies: the UTXO is permanently
// unspendable. The direct form was already refused; this form compiled cleanly
// because the guard only walked the public method's own body, while the
// continuation auto-injection follows private helpers.

import { StatefulSmartContract, assert, requireOutputP2PKH } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P2PKHZeroViaHelper extends StatefulSmartContract {
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

  public go() {
    this.count = this.count + 1n;
    this.assertBond();
    assert(true);
  }
}
