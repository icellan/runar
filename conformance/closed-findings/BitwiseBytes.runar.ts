// R-197: bitwise operators with ByteString operands.
//
// CLAUDE.md states "Bitwise operators (&, |, ^, ~) work on both `bigint` and
// `ByteString` operands", and conformance/README.md described the
// `bitwise-ops` fixture as covering "bigint + ByteString". The fixture is
// bigint-only (examples/ts/bitwise-ops/BitwiseOps.runar.ts — two `bigint`
// properties, no ByteString anywhere), so the one artefact that would have
// proved the ByteString half proved nothing.
//
// Measured while writing this: all six native tiers DO compile it and agree on
// the leading bytes (0000840000850000860083…), so the claim is true — it was
// simply untested. This probe is the test: seven tiers, byte-identical hex.

import { SmartContract, assert, ByteString, len } from 'runar-lang';

class BitwiseBytes extends SmartContract {
  readonly a: ByteString;
  readonly b: ByteString;

  constructor(a: ByteString, b: ByteString) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public testBitwise(): void {
    const andResult: ByteString = this.a & this.b;
    const orResult: ByteString = this.a | this.b;
    const xorResult: ByteString = this.a ^ this.b;
    const notResult: ByteString = ~this.a;
    assert(len(andResult) > 0n);
    assert(len(orResult) > 0n);
    assert(len(xorResult) > 0n);
    assert(len(notResult) > 0n);
    assert(true);
  }
}
