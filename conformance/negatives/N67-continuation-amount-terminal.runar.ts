import { StatefulSmartContract, assert, continuationAmount } from 'runar-lang';
// F-024 (R14): a terminal method has no state continuation, so there is no
// _newAmount for continuationAmount() to read. It must be refused.
export class N67 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public close() {
    assert(continuationAmount() > this.count);
  }
}
