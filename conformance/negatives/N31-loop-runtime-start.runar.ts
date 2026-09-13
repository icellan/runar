// N-137 (found while verifying R-148) — a for-loop whose START is a runtime
// value.
//
// The loop model carries `{count, iterVar, start, step, body}` and unrolls at
// compile time, so the start must be a literal. Six tiers say so:
//
//   ts / go / rust / python / ruby   exit 1, "Cannot determine loop start at
//                                    compile time. For-loop iterators must
//                                    start at an integer literal."
//   java                             exit 70, same message
//   zig                              exit 0 — COMPILED IT
//
// Zig's surface parsers guard the BOUND with a `bound_is_const` flag and have
// no equivalent for the START: `parse_ts.zig`'s initializer branch falls
// through to `_ = self.parseExpression();` and leaves `init_value` at its `0`
// default. Measured on the live-loop shape below (the first probe had a dead
// loop that DCE removed, which hid it):
//
//   for (let i = start; i < 3n; i++)   zig: 1368 hexchars
//   for (let i = 0n;    i < 3n; i++)   zig: 1368 hexchars, IDENTICAL
//
// So the contract compiles to a loop that starts at 0 whatever the caller
// passes, and the state continuation commits to a sum the source never
// computes. Six tiers refuse; one emits a different program than was written.
//
// The loop must be LIVE — `acc` feeds a state write, and `start` is asserted —
// or DCE removes it before ANF lowering ever looks at the shape.

import { StatefulSmartContract, assert } from 'runar-lang';

class LoopRuntimeStart extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(start: bigint) {
    let acc: bigint = this.count;
    for (let i = start; i < 3n; i++) {
      acc = acc + i;
    }
    this.count = acc;
    assert(start >= 0n);
  }
}
