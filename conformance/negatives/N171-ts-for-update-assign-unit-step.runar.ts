// N-133: a plain assignment in a `.runar.ts` for-update. The TS reference
// refuses it as an expression:
//   Unsupported binary operator: '='
// Go alone desugared it into an assignment statement and compiled it
// (byte-identical to `i++`). Every tier must refuse it.
import { StatefulSmartContract, assert } from 'runar-lang';

class N171 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; i = i + 1n) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
