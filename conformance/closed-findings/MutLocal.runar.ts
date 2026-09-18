// R-077 / R-078 — a method whose ONLY mutation is through a local
// (`const old = this.count++`) must still inject the continuation params and
// assert the continuation. Ruby's state-mutation analysis and Java's
// methodMutatesState both missed the VariableDecl form; a method classified
// terminal emits no covenant at all.
import { StatefulSmartContract, assert } from 'runar-lang';

export class MutLocal extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump() {
    const old = this.count++;
    assert(old >= 0n);
  }
}
