// N-347 — `===` on two builtin results, neither a parameter nor a property, so pass 4
// can only learn they are byte strings from the builtin's return type:
//   merkleRootSha256(a, proof, 0n, 1n) === merkleRootSha256(b, proof, 0n, 1n)
// See the N-347 describe block in go-only-parity.test.ts.
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class N347MerkleSha256Eq extends SmartContract {
  constructor() { super(); }
  public verify(a: ByteString, b: ByteString, proof: ByteString) {
    assert(merkleRootSha256(a, proof, 0n, 1n) === merkleRootSha256(b, proof, 0n, 1n));
  }
}
