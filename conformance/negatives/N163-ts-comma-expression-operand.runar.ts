// N-052: a comma expression nested in a comparison (Go compiled it as `0n === this.t`).
// The Go tier's tree-sitter parseExpression returned nil for an expression kind
// it did not recognise and the binary parser read that nil as 0n, so this
// compiled in Go only. Every tier must refuse it; the TS reference says:
//   Unsupported binary operator: ','
import { SmartContract, assert } from 'runar-lang';

class N163 extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public unlock(x: bigint) { assert((x, 0n) === this.t); }
}
