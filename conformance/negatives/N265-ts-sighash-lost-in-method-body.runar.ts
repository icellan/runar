import { StatefulSmartContract } from 'runar-lang';
// N-199 (user decision R75): a sighash directive inside a method body attaches
// to no member. Every tier must refuse it.
export class N265 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(): void {
    // @sighash SINGLE|FORKID
    this.addOutput(1000n, this.count);
  }
}
