import { StatefulSmartContract } from 'runar-lang';
class SatCounter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public inc(): void {
    this.count = this.count + 1n;
    this.addOutput(1000n, this.count);
  }
}