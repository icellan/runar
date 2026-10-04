import { StatefulSmartContract, assert } from 'runar-lang';

class SighashCounter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  /** @sighash ALL|ANYONECANPAY|FORKID */
  public increment(): void {
    this.count = this.count + 1n;
    assert(true);
  }
}
