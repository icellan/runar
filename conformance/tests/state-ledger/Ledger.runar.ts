import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * Ledger -- F-352 second witness for the mutable-state shape
 * {PubKey, bigint, bigint} (the first is `token-ft`). Both bigint fields are
 * rewritten in one call, from different expressions.
 */
class Ledger extends StatefulSmartContract {
  holder: PubKey;
  balance: bigint;
  nonce: bigint;

  constructor(holder: PubKey, balance: bigint, nonce: bigint) {
    super(holder, balance, nonce);
    this.holder = holder;
    this.balance = balance;
    this.nonce = nonce;
  }

  public spend(sig: Sig, amount: bigint) {
    assert(checkSig(sig, this.holder));
    assert(amount > 0n);
    assert(amount <= this.balance);
    this.balance = this.balance - amount;
    this.nonce = this.nonce + 1n;
  }
}
