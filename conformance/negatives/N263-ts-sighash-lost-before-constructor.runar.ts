import { StatefulSmartContract } from 'runar-lang';
// N-199 (user decision R75): a sighash directive above the constructor is read
// by no member (only methods carry a sighash mode). Every tier must refuse it.
export class N263 extends StatefulSmartContract {
  count: bigint;
  /** @sighash SINGLE|FORKID */
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(): void {
    this.addOutput(1000n, this.count);
  }
}
