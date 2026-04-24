import { StatefulSmartContract, assert } from 'runar-lang';

class HashRegistry extends StatefulSmartContract {
  currentHash: Ripemd160;

  constructor(currentHash: Ripemd160) {
    super(currentHash);
    this.currentHash = currentHash;
  }

  public update(newHash: Ripemd160): void {
    this.currentHash = newHash;
    assert(true);
  }
}
