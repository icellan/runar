import { StatefulSmartContract, assert, checkSig, hash256, substr, extractHashPrevouts, extractOutpoint } from 'runar-lang';

class FungibleToken extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;
  mergeBalance: bigint;
  readonly tokenId: ByteString;

  constructor(owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString) {
    super(owner, balance, mergeBalance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.mergeBalance = mergeBalance;
    this.tokenId = tokenId;
  }

  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    const totalBalance = this.balance + this.mergeBalance;
    assert(amount > 0n);
    assert(amount <= totalBalance);
    this.addOutput(outputSatoshis, to, amount, 0n);
    if (amount < totalBalance) {
      this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0n);
    }
  }

  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0n);
  }

  public merge(sig: Sig, otherBalance: bigint, allPrevouts: ByteString, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    assert(otherBalance >= 0n);
    assert(hash256(allPrevouts) === extractHashPrevouts(this.txPreimage));
    const myOutpoint = extractOutpoint(this.txPreimage);
    const firstOutpoint = substr(allPrevouts, 0n, 36n);
    const myBalance = this.balance + this.mergeBalance;
    if (myOutpoint === firstOutpoint) {
      this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
    } else {
      this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
    }
  }
}
