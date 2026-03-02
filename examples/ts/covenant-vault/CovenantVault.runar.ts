import { SmartContract, assert, PubKey, Sig, Addr, ByteString, SigHashPreimage, checkSig, checkPreimage, hash160, extractOutputHash, hash256 } from 'runar-lang';

class CovenantVault extends SmartContract {
  readonly owner: PubKey;
  readonly recipient: Addr;
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  public spend(sig: Sig, amount: bigint, txPreimage: SigHashPreimage) {
    // Owner must authorize
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));

    // Enforce minimum output amount (covenant rule)
    assert(amount >= this.minAmount);
  }
}
