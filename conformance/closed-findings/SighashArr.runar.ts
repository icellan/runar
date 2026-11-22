// R-076 — Zig's FixedArray expansion zeroed the @sighash mode, so a method
// declared SINGLE|FORKID (0x43) got the default flag instead. The emitted
// script must still push 0x43.
//
// This probe is only compilable at all since N-124 taught the Zig tier
// `this.arr[i]++`. Its continuation is an explicit addOutput carrying the
// whole table. (It was written when a mutate-only SINGLE method was refused
// as a value skim; D25 removed that refusal — a mutate-only continuation now
// commits under SINGLE by design — so the explicit addOutput is no longer
// required, only kept so this probe's bytes stay stable.)
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
