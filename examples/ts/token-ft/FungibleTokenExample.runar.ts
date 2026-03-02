import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class FungibleToken extends StatefulSmartContract {
  owner: PubKey;           // stateful: current token owner
  balance: bigint;         // stateful: token balance in this UTXO
  readonly tokenId: ByteString; // immutable: token identifier

  constructor(owner: PubKey, balance: bigint, tokenId: ByteString) {
    super(owner, balance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.tokenId = tokenId;
  }

  // Split: 1 input → 2 outputs (recipient + change)
  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(amount > 0n);
    assert(amount <= this.balance);

    // addOutput(satoshis, owner, balance) — args match mutable props in order
    this.addOutput(outputSatoshis, to, amount);
    this.addOutput(outputSatoshis, this.owner, this.balance - amount);
  }

  // Simple send: 1 input → 1 output, full balance
  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));

    this.addOutput(outputSatoshis, to, this.balance);
  }

  // Merge: N inputs → 1 output (each input calls this independently)
  public merge(sig: Sig, totalBalance: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(totalBalance >= this.balance);

    this.addOutput(outputSatoshis, this.owner, totalBalance);
  }
}
