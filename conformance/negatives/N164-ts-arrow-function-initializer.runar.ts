// N-052: an arrow function as a local initializer (Go bound the local to 0n).
// The Go tier's tree-sitter parseExpression returned nil for an expression kind
// it did not recognise and the binary parser read that nil as 0n, so this
// compiled in Go only. Every tier must refuse it; the TS reference says:
//   Unsupported expression kind: ArrowFunction ('(y: bigint) => y')
import { SmartContract, assert } from 'runar-lang';

class N164 extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public unlock(x: bigint) {
    const f = (y: bigint) => y;
    assert(x === this.t);
  }
}
