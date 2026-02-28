import { SmartContract, assert, SigHashPreimage, checkPreimage, hash256, extractOutputHash } from 'tsop-lang';

class Stateful extends SmartContract {
  count: bigint;
  readonly maxCount: bigint;

  constructor(count: bigint, maxCount: bigint) {
    super(count, maxCount);
    this.count = count;
    this.maxCount = maxCount;
  }

  public increment(amount: bigint, txPreimage: SigHashPreimage): void {
    assert(checkPreimage(txPreimage));
    this.count = this.count + amount;
    assert(this.count <= this.maxCount);
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }

  public reset(txPreimage: SigHashPreimage): void {
    assert(checkPreimage(txPreimage));
    this.count = 0n;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }
}
