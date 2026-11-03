// N-135: an EMPTY for-condition on `.runar.ts`. In the source the loop has no
// exit test at all; a tier that substitutes a placeholder (`false`) for the
// missing condition compiles a loop that runs zero times instead. The TS
// reference refuses it in its parser:
//   For loop must have a condition
// Every tier must refuse it.
import { StatefulSmartContract, assert } from 'runar-lang';

class N274 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; ; i++) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
