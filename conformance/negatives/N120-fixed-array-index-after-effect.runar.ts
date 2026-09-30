// N-048 (external "PrematurePeek"): pass 3b binds a computed FixedArray index
// to `const __idx_K` in front of its whole statement. Here that moved
// `this.cursor % 2n` ahead of `++this.cursor`, so the gate read the
// pre-increment slot and an outsider could spend at cursor 0, which the
// source forbids (enabled[1] = 0). Accepted by all seven tiers pre-fix, under
// @bsv/sdk Spend.validate. Every tier must refuse with:
//   FixedArray index would be evaluated out of source order: ...
// Shape: index after a ++ in the left operand of &&.
import { StatefulSmartContract, FixedArray, ByteString, assert } from 'runar-lang';

class RotatingVault extends StatefulSmartContract {
  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
  cursor: bigint;

  constructor(cursor: bigint) {
    super(cursor);
    this.cursor = cursor;
  }

  public release(destination: ByteString) {
    assert((++this.cursor > 0n) && this.enabled[this.cursor % 2n] === 1n);
    this.addRawOutput(199000n, destination);
  }
}
