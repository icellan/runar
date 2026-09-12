// R-037 — merkleRootSha256. Go-only by project policy.
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class GoOnlyMerkle extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) { super(expectedRoot); this.expectedRoot = expectedRoot; }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    assert(merkleRootSha256(leaf, proof, index, 4n) === this.expectedRoot);
  }
}
