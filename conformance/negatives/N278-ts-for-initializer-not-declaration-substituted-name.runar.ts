// N-306: the same non-declaration for-initializer as N277, but with the
// condition/update written against the SUBSTITUTED iterator name `_i` rather
// than the source's own `i`. On Python, Go, Zig, Ruby and Java this used to
// defeat an unrelated accidental catch (the unrolled loop's "condition must
// compare the loop variable" validator rule, which only fired because the
// substituted `_i` didn't match the source's `i`) and compiled clean -- the
// discarded `i = 0n` initializer never raised a diagnostic at all. The TS
// reference refuses it in its parser, the same as N277:
//   For loop must have a variable declaration initializer
// Every tier must refuse it.
import { StatefulSmartContract, assert } from 'runar-lang';

class N278 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (i = 0n; _i < 3n; _i++) {
      acc = acc + 1n;
    }
    assert(acc === expected);
  }
}
