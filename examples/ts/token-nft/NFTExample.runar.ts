import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class SimpleNFT extends StatefulSmartContract {
  owner: PubKey;             // stateful
  readonly tokenId: ByteString;   // immutable: unique token identifier
  readonly metadata: ByteString;  // immutable: token metadata URI/hash

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  public transfer(sig: Sig, newOwner: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    // addOutput(satoshis, owner) — single mutable prop
    this.addOutput(outputSatoshis, newOwner);
  }

  public burn(sig: Sig) {
    // Only owner can burn
    assert(checkSig(sig, this.owner));
    // No addOutput and no state mutation = token destroyed
  }
}
