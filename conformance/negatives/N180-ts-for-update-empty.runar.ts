// N-132: an EMPTY for-update on `.runar.ts`. The source loop never advances
// `i`; the unrolled loop model would advance it anyway. The TS reference
// refuses it in its parser:
//   For loop must have an update expression
// Go, Python, Zig, Ruby and Java filled the slot with a `0n` placeholder and
// compiled it (byte-identical to `i++`). Every tier must refuse it.
import { StatefulSmartContract, assert } from 'runar-lang';

class N180 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; ) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
