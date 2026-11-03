// N-306: a for-initializer that is NOT a `let`/`const` declaration,
// `for (i = 0n; i < 3n; i++)`. The TS reference refuses it in its parser:
//   For loop must have a variable declaration initializer
// Python, Go, Zig, Ruby and Java silently substituted a synthetic `_i = 0`
// for the whole initializer instead, discarding `i = 0n` with no diagnostic.
// Every tier must refuse it.
//
// NOTE for anyone bisecting against this fixture: before the N-306 fix, this
// EXACT spelling was already refused on those five tiers too, but only by
// accident -- an unrelated validator rule ("condition must compare the loop
// variable") caught the mismatch between the substituted `_i` and the
// source's own `i` in the condition/update clauses. Reverting the N-306
// parser fix will NOT turn this fixture red; N278 is the one that defeats
// that accidental catch and actually regresses without the fix.
import { StatefulSmartContract, assert } from 'runar-lang';

class N277 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (i = 0n; i < 3n; i++) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
