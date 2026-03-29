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

  public release(sellerSig: Sig, arbiterSig: Sig) {
    assert(checkSig(sellerSig, this.seller));
    assert(checkSig(arbiterSig, this.arbiter));
  }

  public refund(buyerSig: Sig, arbiterSig: Sig) {
    assert(checkSig(buyerSig, this.buyer));
    assert(checkSig(arbiterSig, this.arbiter));
  }
}
