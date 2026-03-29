import { StatefulSmartContract, assert, checkSig } from 'runar-lang';

class SimpleNFT extends StatefulSmartContract {
  owner: PubKey;
  readonly tokenId: ByteString;
  readonly metadata: ByteString;

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  public transfer(sig: Sig, newOwner: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, newOwner);
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
