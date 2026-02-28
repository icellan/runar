import { SmartContract, assert, PubKey, Sig, SigHashPreimage, checkSig, checkPreimage, hash256, extractOutputHash, ByteString } from 'tsop-lang';

class SimpleFungibleToken extends SmartContract {
  owner: PubKey;          // stateful: current token owner
  readonly supply: bigint; // immutable: total supply

  constructor(owner: PubKey, supply: bigint) {
    super(owner, supply);
    this.owner = owner;
    this.supply = supply;
  }

  public transfer(sig: Sig, newOwner: PubKey, txPreimage: SigHashPreimage) {
    // Only current owner can transfer
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));

    // Update owner
    this.owner = newOwner;

    // Ensure output contains updated contract
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }
}
