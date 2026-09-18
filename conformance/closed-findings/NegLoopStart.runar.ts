// N-138: a for-loop whose start is a NEGATIVE literal.
//
// Every surface parser in the Zig tier recognised a bare number token (or a
// folded `.literal_int`) as the loop start and let `-1` fall through to the
// discard path, leaving `init_value` at its `0` default. The loop then
// unrolled from 0 instead of -1 — a different program from the one written,
// in one tier only, and byte-divergent from the other six with no size tell.
//
// Measured before the fix on the `bounded-loop` example rewritten to start at
// -1, once per surface. All NINE surfaces of the Zig tier diverged:
//
//   go   004f52797b7c937c930052797b7c937c93…  100 hexchars  (0x4f = OP_1NEGATE)
//   zig  000052797b7c937c935152797b7c937c93…   84 hexchars  (0x00 = OP_0)
//
// The first push is the tell: the other six tiers push -1, the Zig tier pushed
// 0. The conformance corpus has a `bounded-loop` fixture in all nine formats
// and every one of them starts at 0, so nothing exercised the sign.
//
// This pin is the positive half — every tier must accept it and agree byte for
// byte. `conformance/negatives/N31-loop-runtime-start.runar.ts` is the other
// half: a start that is not a literal at all, which every tier must refuse.

import { SmartContract, assert } from 'runar-lang';

class NegLoopStart extends SmartContract {
  readonly expectedSum: bigint;

  constructor(expectedSum: bigint) {
    super(expectedSum);
    this.expectedSum = expectedSum;
  }

  public verify(start: bigint) {
    let sum: bigint = 0n;
    for (let i: bigint = -1n; i < 5n; i++) {
      sum = sum + start + i;
    }
    assert(sum === this.expectedSum);
  }
}
