import { SmartContract, assert, PubKey, Sig, SigHashPreimage, ByteString, checkSig, checkPreimage, hash256, extractOutputHash } from 'tsop-lang';

class SimpleNFT extends SmartContract {
  owner: PubKey;             // stateful
  readonly tokenId: ByteString;   // immutable: unique token identifier
  readonly metadata: ByteString;  // immutable: token metadata URI/hash

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  public transfer(sig: Sig, newOwner: PubKey, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));
    this.owner = newOwner;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }

  public burn(sig: Sig) {
    // Only owner can burn
    assert(checkSig(sig, this.owner));
    // No state continuation = token destroyed
  }
}
