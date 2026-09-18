// R-204 — a ByteString-literal property initializer.
//
// CLAUDE.md's Contract Model says property initializers take "literal values
// only: BigIntLiteral, BoolLiteral, ByteStringLiteral". The
// `property-initializers` conformance fixture covers the first two —
// `count: bigint = 0n` and `active: boolean = true` — and never the third, in
// any of its nine surface files. So one of the three documented initializer
// types had no cross-tier coverage at all.
//
// Measured while writing this: all seven tiers accept it and agree byte for
// byte (1392 hexchars, sha 8c06459e6c23), so the claim is true and was simply
// untested. This probe is the test.
//
// Two initializers, not one, and both used: a single unused readonly field
// would be eliminated by DCE and prove nothing about the initializer surviving
// into the deployed script.

import { StatefulSmartContract, assert, len, ByteString } from 'runar-lang';

class BytesInit extends StatefulSmartContract {
  count: bigint = 0n;
  readonly prefix: ByteString = '1976a914';
  readonly suffix: ByteString = '88ac';
  readonly owner: ByteString;

  constructor(owner: ByteString) {
    super(owner);
    this.owner = owner;
  }

  public bump(n: bigint): void {
    assert(len(this.prefix) + len(this.suffix) > 0n);
    this.count = this.count + n;
  }
}
