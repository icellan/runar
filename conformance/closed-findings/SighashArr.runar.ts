// R-076 — Zig's FixedArray expansion zeroed the @sighash mode, so a method
// declared SINGLE|FORKID (0x43) got the default flag instead. The emitted
// script must still push 0x43.
//
// This probe is only compilable at all since N-124 taught the Zig tier
// `this.arr[i]++`. Its continuation is an explicit addOutput carrying the
// whole table: a mutate-only SINGLE method (auto-continuation sized by the
// spender's _newAmount) is refused as a value skim, and since PR C that
// includes a write to a FixedArray element (conformance/negatives/N539).
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class SighashArr extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  /** @sighash SINGLE|FORKID */
  public bump(i: bigint, sats: bigint) {
    this.table[i]++;
    this.addOutput(sats, this.table[0], this.table[1], this.table[2], this.table[3]);
    assert(true);
  }
}
