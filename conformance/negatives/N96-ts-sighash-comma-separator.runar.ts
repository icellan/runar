import { StatefulSmartContract } from 'runar-lang';
// F-039: a @sighash flag list using `,` instead of `|` is malformed.
// Every tier must refuse it; before F-039 the reference (and most tiers)
// silently compiled the method under the default ALL|FORKID instead.
export class N96 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @sighash SINGLE,FORKID */
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
