// currentBlockHeight() asserts its own value is below 500000000 (a block
// height), so comparing it against a Unix-timestamp lower bound can never
// pass: an output gated on it could never be spent. Every tier refuses:
//   method 'spend' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts its value is below 500000000 (a block height), so this compare can never pass and an output gated on it could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate
import { StatefulSmartContract, assert, currentBlockHeight, extractSequence } from 'runar-lang';

class N539 extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public spend() {
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
    assert(currentBlockHeight() >= 1700000000n);
    this.count = this.count + 1n;
  }
}
