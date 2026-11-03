import { StatefulSmartContract } from 'runar-lang';
// F-039: two @sighash directives on one method (a malformed one, then a well-formed one).
// Every tier must refuse it; before F-039 the reference (and most tiers)
// silently compiled the method under the default ALL|FORKID instead.
export class N98 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @sighash SINGLE|FORKID!
   * @sighash NONE|FORKID */
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
