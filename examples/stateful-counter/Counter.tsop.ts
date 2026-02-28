import { SmartContract, assert, SigHashPreimage, checkPreimage, hash256, extractOutputHash } from 'tsop-lang';

class Counter extends SmartContract {
  count: bigint; // non-readonly = stateful

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));
    this.count++;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }

  public decrement(txPreimage: SigHashPreimage) {
    assert(this.count > 0n);
    assert(checkPreimage(txPreimage));
    this.count--;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }
}
