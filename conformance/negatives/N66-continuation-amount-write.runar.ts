import { StatefulSmartContract, assert, continuationAmount } from 'runar-lang';
// F-024 (R14): continuationAmount() is a read-only view of the injected
// _newAmount; assigning to it must be refused, never lowered as a read.
export class N66 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump() {
    continuationAmount() = 1n;
    this.count = this.count + 1n;
  }
}
