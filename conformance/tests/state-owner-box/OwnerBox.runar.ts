import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * OwnerBox -- F-352 second witness for the mutable-state shape {PubKey} (the
 * first is `token-nft`). Ownership moves by assigning the property, not by
 * `addOutput`.
 */
class OwnerBox extends StatefulSmartContract {
  owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public rotate(sig: Sig, newOwner: PubKey) {
    assert(checkSig(sig, this.owner));
    this.owner = newOwner;
  }
}
