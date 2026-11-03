import { StatefulSmartContract } from 'runar-lang';
// F-039: a bare `// @sighash` line comment with no flag list.
// Every tier must refuse it; before F-039 the reference (and most tiers)
// silently compiled the method under the default ALL|FORKID instead.
export class N97 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  // @sighash
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
