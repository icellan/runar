import { InductiveSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class InductiveToken extends InductiveSmartContract {
  owner: PubKey;
  balance: bigint;
  readonly tokenId: ByteString;

  constructor(owner: PubKey, balance: bigint, tokenId: ByteString) {
    super(owner, balance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.tokenId = tokenId;
  }

  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(amount > 0n);
    assert(amount <= this.balance);

    this.addOutput(outputSatoshis, to, amount);
    this.addOutput(outputSatoshis, this.owner, this.balance - amount);
  }

  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));

    this.addOutput(outputSatoshis, to, this.balance);
  }
}
