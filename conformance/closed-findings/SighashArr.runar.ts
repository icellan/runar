// R-076 — Zig's FixedArray expansion zeroed the @sighash mode, so a method
// declared SINGLE|FORKID (0x43) got the default flag instead. The emitted
// script must still push 0x43.
//
// This probe is only compilable at all since N-124 taught the Zig tier
// `this.arr[i]++`.
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class SighashArr extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  /** @sighash SINGLE|FORKID */
  public bump(i: bigint) {
    this.table[i]++;
    assert(true);
  }
}
