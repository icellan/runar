// N-347 — negative control, a bigint-returning builtin: must compare with OP_NUMEQUAL:
//   len(a) === len(b)
// See the N-347 describe block in go-only-parity.test.ts.
import { SmartContract, assert, len } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class N347ControlLenEq extends SmartContract {
  constructor() { super(); }
  public verify(a: ByteString, b: ByteString) {
    assert(len(a) === len(b));
  }
}
