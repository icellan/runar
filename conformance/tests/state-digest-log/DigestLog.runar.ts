import { StatefulSmartContract, assert } from 'runar-lang';
import type { Ripemd160 } from 'runar-lang';

/**
 * DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}
 * (the first is `state-ripemd160`). A replacement carries a positive version
 * tag, so this contract's method shape differs from HashRegistry's.
 */
class DigestLog extends StatefulSmartContract {
  digest: Ripemd160;

  constructor(digest: Ripemd160) {
    super(digest);
    this.digest = digest;
  }

  public replace(newDigest: Ripemd160, version: bigint) {
    assert(version > 0n);
    this.digest = newDigest;
  }
}
