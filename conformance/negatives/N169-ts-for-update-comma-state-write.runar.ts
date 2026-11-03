// N-133: a `.runar.ts` for-header whose update slot is a comma sequence that
// carries a state write. Go's tree-sitter walk once zeroed the sequence, so
// this compiled to the same 938 hexchars as a plain `i++` loop with the
// per-iteration `this.count++` silently DROPPED from the script. Every tier
// must refuse it; the TS reference says:
//   Unsupported binary operator: ','
import { StatefulSmartContract, assert } from 'runar-lang';

class N169 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; i++, this.count++) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
