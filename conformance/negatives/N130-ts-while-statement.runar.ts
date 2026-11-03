// F-064: a `WhileStatement` inside a public method. Outside spec/grammar.md §9, so every
// tier must refuse it with "Unsupported statement kind: WhileStatement". Pre-fix the
// Go tier's tree-sitter walk returned nil for it and the caller dropped it, so
// the method compiled with the statement missing.
// Measured pre-fix: Go compiled `while (x > 0n) { assert(false); } assert(x >= 0n);`
// to 00a2 (the loop gone) and @bsv/sdk Spend.validate accepted x = 5.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public unlock(x: bigint) {
    while (x > 0n) { assert(false); }
    assert(x > this.a);
  }
}
