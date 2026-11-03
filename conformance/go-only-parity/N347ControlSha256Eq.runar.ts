// N-347 — positive control, a builtin every tier already listed: must compare with OP_EQUAL:
//   sha256(a) === sha256(b)
// See the N-347 describe block in go-only-parity.test.ts.
import { SmartContract, assert, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class N347ControlSha256Eq extends SmartContract {
  constructor() { super(); }
  public verify(a: ByteString, b: ByteString) {
    assert(sha256(a) === sha256(b));
  }
}
