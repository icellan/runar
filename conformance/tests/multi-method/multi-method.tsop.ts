import { SmartContract, assert, PubKey, Sig, checkSig } from 'tsop-lang';

class MultiMethod extends SmartContract {
  readonly owner: PubKey;
  readonly backup: PubKey;

  constructor(owner: PubKey, backup: PubKey) {
    super(owner, backup);
    this.owner = owner;
    this.backup = backup;
  }

  private computeThreshold(a: bigint, b: bigint): bigint {
    return a * b + 1n;
  }

  public spendWithOwner(sig: Sig, amount: bigint): void {
    const threshold: bigint = this.computeThreshold(amount, 2n);
    assert(threshold > 10n);
    assert(checkSig(sig, this.owner));
  }

  public spendWithBackup(sig: Sig): void {
    assert(checkSig(sig, this.backup));
  }
}
