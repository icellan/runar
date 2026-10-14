import { StatefulSmartContract } from 'runar-lang';
// N-199 (user decision R75): a sighash directive comment sharing a line with
// the preceding method's closing brace is that brace's trailing trivia, so it
// attaches to no member. Every tier must refuse it; before N-199 every tier
// silently compiled `grow` under the default ALL|FORKID.
export class N262 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(): void { this.addOutput(1000n, this.count); } // @sighash SINGLE|FORKID
  public grow(): void {
    this.addOutput(1000n, this.count + 1n);
  }
}
