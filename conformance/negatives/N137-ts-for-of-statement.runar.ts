// F-064: a `ForOfStatement` inside a public method. Outside spec/grammar.md §9, so every
// tier must refuse it with "Unsupported statement kind: ForOfStatement". Pre-fix the
// Go tier's tree-sitter walk returned nil for it and the caller dropped it, so
// the method compiled with the statement missing.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public unlock(x: bigint) {
    for (const k of [x]) { assert(false); }
    assert(x > this.a);
  }
}
