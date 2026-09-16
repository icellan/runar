// W5 / LoopYoink, second site — extra declarators in a for-initializer.
//
// The statement-position site at least emitted a warning (see N43). This one
// emitted NOTHING. `01-parse.ts` took `decls[0]` and returned; every later
// declarator, and anything it called, disappeared between the source and the
// AST.
//
// That is a silent guard deletion, and it was measured rather than argued.
// `this.guard(x)` below asserts `x > 100n`. With the guard in the second
// declarator, and with the whole declarator removed, the reference tier emitted
// the SAME five bytes:
//
//   for (let i = 0n, k = this.guard(x); i < 2n; i++)   hex 008b519c77
//   for (let i = 0n;                    i < 2n; i++)   hex 008b519c77
//
// and `@bsv/sdk` `Spend.validate()` ACCEPTED `verify(5n)` -- a value the guard
// exists to reject. Written as its own statement the same guard compiles to 23
// bytes and `Spend.validate()` REJECTS `verify(5n)`. The developer wrote the
// check, the compiler said nothing, and the locking script does not contain it.
//
// Note what this shape defeats: `k` is never named again, so no tier can catch
// it as an undeclared variable. Only the effect is lost, which is exactly the
// case a diagnostic has to cover.
//
// Every tier must refuse this.

import { SmartContract, assert } from 'runar-lang';

class ForInitExtraDeclarator extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  private guard(x: bigint): bigint {
    assert(x > 100n);
    return x;
  }

  public verify(x: bigint) {
    let s: bigint = 0n;
    for (let i: bigint = 0n, k: bigint = this.guard(x); i < 2n; i++) {
      s = s + i;
    }
    assert(s === 1n + this.tag);
  }
}
