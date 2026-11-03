// F-064: a `Block` inside a public method. Outside spec/grammar.md §9, so every
// tier must refuse it with "Unsupported statement kind: Block". Pre-fix the
// Go tier's tree-sitter walk returned nil for it and the caller dropped it, so
// the method compiled with the statement missing.
// The TS REFERENCE was fail-open here too: parseStatements took the FIRST nested
// Block's statements in place of the method body, so this parsed as
// `assert(true)` alone and anyone could spend. Measured pre-fix: TS compiled
// `assert(x == 42n); { assert(true); }` to 5177 and @bsv/sdk Spend.validate
// accepted x = 5. Go dropped the block instead.
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public unlock(x: bigint) {
    assert(x > this.a);
    { assert(true); }
  }
}
