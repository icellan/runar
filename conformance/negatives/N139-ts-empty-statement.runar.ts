// F-064: a `EmptyStatement` inside a public method. Outside spec/grammar.md §9, so every
// tier must refuse it with "Unsupported statement kind: EmptyStatement". Pre-fix the
// Go tier's tree-sitter walk returned nil for it and the caller dropped it, so
// the method compiled with the statement missing.
// Go/Python/Zig/Ruby/Java silently skipped the `;` pre-fix; TS and Rust refuse it.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public unlock(x: bigint) {
    if (x > 0n) { ; }
    assert(x > this.a);
  }
}
