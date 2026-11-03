// N-135: a for-header whose condition slot is EMPTY and whose remaining two
// clauses shift one place left, `for (let i = 0n;; i < 3n; i++)`. It is not
// valid TypeScript. The TS reference refuses it in its parser:
//   For loop must have a condition
// (alongside TypeScript's own syntax errors). Python, Zig, Ruby and Java
// swallowed the empty condition slot's `;` after the initializer and compiled
// it as `for (let i = 0n; i < 3n; i++)`. Every tier must refuse it.
import { StatefulSmartContract, assert } from 'runar-lang';

class N275 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n;; i < 3n; i++) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
