import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public releaseBySeller(sig: Sig) {
    assert(checkSig(sig, this.seller));
  }

  public releaseByArbiter(sig: Sig) {
    assert(checkSig(sig, this.arbiter));
  }

  public refundToBuyer(sig: Sig) {
    assert(checkSig(sig, this.buyer));
  }

  public refundByArbiter(sig: Sig) {
    assert(checkSig(sig, this.arbiter));
  }
}
