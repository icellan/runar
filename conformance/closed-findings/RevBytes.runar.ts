// R-070 — `reverseBytes` CRASHED the Ruby compiler: a bare Integer where every
// other push is a hex string. A crash is not a diagnostic, and the other six
// tiers compiled it.
import { SmartContract, assert, reverseBytes } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class RevBytes extends SmartContract {
  readonly expected: ByteString;
  constructor(expected: ByteString) { super(expected); this.expected = expected; }
  public verify(input: ByteString) {
    assert(reverseBytes(input) === this.expected);
  }
}
